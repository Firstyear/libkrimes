/*
 * The string after "KEYRING:" is called the residual and has three parts:
 * <anchor>:<collection>:<subsidiary>
 *
 * The <anchor> is the keyring to use:
 *   - process
 *   - session
 *   - user
 *   - persistent
 *
 * There can be multiple collections of credentials in the anchor.
 *
 * One <collection> can contain multiple subsidiaries. A subsidiary stores the
 * tickets for a particular principal name (e.g., TGTs for different realms or multiple
 * service tickets). Each collection has a "primary" subsidiary identified by a key
 * named krb_ccache:primary. Usually the command line tools read this key when the subsidiary
 * name was not given in the residual.
 *
 * MIT uses the collection name as the subsidiary name when it is not given, or,
 * in case of storing a ticket for other principal, it creates a random one.
 *
 * Example of a kernel keyring credential cache:
 *
 * $ KRB5CCNAME="KEYRING:session:foo" klist
 * Ticket cache: KEYRING:session:foo:krb_ccache_Hsq3H8X
 * Default principal: u2@AFOREST.AD
 *
 * Valid starting     Expires            Service principal
 * 17/01/25 13:50:38  17/01/25 23:50:38  krbtgt/AFOREST.AD@AFOREST.AD
 *         renew until 18/01/25 13:50:36
 *
 * Ticket cache: KEYRING:session:foo:foo
 * Default principal: u1@AFOREST.AD
 *
 * Valid starting     Expires            Service principal
 * 17/01/25 13:41:20  17/01/25 23:41:02  cifs/win2k25-1.aforest.ad@AFOREST.AD
 *         renew until 18/01/25 13:41:00
 * 17/01/25 13:41:02  17/01/25 23:41:02  krbtgt/AFOREST.AD@AFOREST.AD
 *         renew until 18/01/25 13:41:00
 *
 * $ keyctl show
 * Session Keyring
 *  719031901 --alswrv   1000   100  keyring: _ses
 *  541342232 --alswrv   1000   100   \_ keyring: _krb_foo
 *  557625224 --alswrv   1000   100       \_ user: krb_ccache:primary
 *  967438278 --alswrv   1000   100       \_ keyring: krb_ccache_Hsq3H8X
 *  624398775 --alswrv   1000   100       |   \_ user: __krb5_princ__
 *  217070267 --alswrv   1000   100       |   \_ user: krbtgt/AFOREST.AD@AFOREST.AD
 *  354787744 --alswrv   1000   100       |   \_ user: krb5_ccache_conf_data/pa_type/krbtgt\/AFOREST.AD\@AFOREST.AD@X-CACHECONF:
 *  764584426 --alswrv   1000   100       |   \_ user: __krb5_time_offsets__
 *  463197567 --alswrv   1000   100       \_ keyring: foo
 *  106708269 --alswrv   1000   100           \_ user: __krb5_princ__
 *  150210269 --alswrv   1000   100           \_ user: cifs/win2k25-1.aforest.ad@AFOREST.AD
 *  676215280 --alswrv   1000   100           \_ user: krbtgt/AFOREST.AD@AFOREST.AD
 * 1072460542 --alswrv   1000   100           \_ user: krb5_ccache_conf_data/pa_type/krbtgt\/AFOREST.AD\@AFOREST.AD@X-CACHECONF:
 *  999302906 --alswrv   1000   100           \_ user: __krb5_time_offsets__
 *
 * $ keyctl read 557625224
 * 11 bytes of data in key:
 * 00000001 00000003 666f6f
 *                   f o o
 *
 * $ keyctl read 106708269
 * 28 bytes of data in key:
 * 00000001 00000001 0000000a 41464f52 4553542e 41440000 00027531
 *                            A F O R  E S T .  A D          u 1
 *
 * $ keyctl read 624398775
 * 28 bytes of data in key:
 * 00000001 00000001 0000000a 41464f52 4553542e 41440000 00027532
 *                            A F O R  E S T .  A D          u 2
 */

use super::CredentialCache;
use super::CredentialCacheCollection;
use crate::ccache::{CredentialV4, PrincipalV4};
use crate::error::KrbError;
use crate::proto::{EncTicket, KdcReplyPart, KerberosCredentials, Name};

use binrw::{binread, binwrite};
use binrw::{BinReaderExt, BinWrite};
use errno::Errno;
use keyutils::keytypes::user::User;
use keyutils::SpecialKeyring;
use keyutils::{Key, Keyring};
use keyutils_raw::{keyctl_get_keyring_id, keyctl_get_persistent};
use crypto_glue::rand::{self, distr::Alphanumeric, Rng};
use std::fmt::Display;
use std::ops::{Deref, DerefMut};
use std::time::Duration;
use tracing::{debug, error, trace};

impl From<errno::Errno> for KrbError {
    fn from(value: errno::Errno) -> Self {
        error!(errno = ?value, "kernel keyring error");
        KrbError::KeyutilsError
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
struct Residual {
    anchor: String,
    collection: String,
    subsidiary: Option<String>,
}

impl Display for Residual {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.anchor, self.collection)?;
        if let Some(subsidiary) = self.subsidiary.as_ref() {
            write!(f, ":{}", subsidiary)?;
        }
        Ok(())
    }
}

impl Residual {
    fn parse(residual: &str) -> Result<Self, KrbError> {
        trace!(?residual, "Parsing residual");

        if !residual.starts_with("KEYRING:") {
            return Err(KrbError::UnsupportedCredentialCacheType);
        }
        let residual = residual
            .strip_prefix("KEYRING:")
            .ok_or(KrbError::UnsupportedCredentialCacheType)?;

        let (anchor, suffix) = residual
            .split_once(":")
            .ok_or(KrbError::UnsupportedCredentialCacheType)?;
        if anchor.is_empty() {
            return Err(KrbError::UnsupportedCredentialCacheType);
        }

        let (collection, suffix) = suffix.split_once(":").unwrap_or((suffix, ""));
        if collection.is_empty() {
            return Err(KrbError::UnsupportedCredentialCacheType);
        }

        let subsidiary: Option<String> = match suffix.split_once(":") {
            Some((subsidiary, _)) => Some(subsidiary.to_string()),
            None => {
                if !suffix.is_empty() {
                    Some(suffix.to_string())
                } else {
                    None
                }
            }
        };

        Ok(Residual {
            anchor: anchor.to_string(),
            collection: collection.to_string(),
            subsidiary,
        })
    }
}

#[binwrite]
#[bw(big, magic = 1u32)]
#[binread]
#[br(magic = 1u32)]
struct PrimaryName {
    #[bw(calc=strval.len() as u32)]
    #[br(temp)]
    strlen: u32,
    #[br(count=strlen)]
    strval: Vec<u8>,
}

#[binwrite]
#[bw(big)]
#[binread]
#[derive(Debug)]
struct TimeOffsets {
    secs: i32,
    usecs: i32,
}

fn get_subsidiary_time_offsets(keyring: &Keyring) -> Result<Option<TimeOffsets>, KrbError> {
    let key_name = "__krb5_time_offsets__";
    match keyring.search_for_key::<User, &str, Option<&mut Keyring>>(key_name, None) {
        Ok(k) => {
            let payload = k.read()?;
            let mut reader = binrw::io::Cursor::new(payload);
            let offsets: TimeOffsets = reader.read_type(binrw::Endian::Big).map_err(|err| {
                error!(error=?err);
                KrbError::BinRWError
            })?;
            Ok(Some(offsets))
        }
        Err(errno::Errno(libc::ENOKEY)) => Ok(None),
        Err(e) => Err(KrbError::from(e)),
    }
}

/// Gets the subsidiary's principal name
///
/// This function reads the "__krb5_princ__" key in the subsidiary keyring and returns
/// the stored principal name.
fn get_subsidiary_principal(keyring: &Keyring) -> Result<Option<Name>, KrbError> {
    let key_name = "__krb5_princ__";
    match keyring.search_for_key::<User, &str, Option<&mut Keyring>>(key_name, None) {
        Ok(k) => {
            let payload = k.read()?;
            let mut reader = binrw::io::Cursor::new(payload);
            let name: PrincipalV4 = reader.read_type(binrw::Endian::Big).map_err(|err| {
                error!(error=?err);
                KrbError::BinRWError
            })?;
            let name: Name = (&name).try_into()?;
            Ok(Some(name))
        }
        Err(errno::Errno(libc::ENOKEY)) => Ok(None),
        Err(e) => Err(KrbError::from(e)),
    }
}

/// Checks if a subsidiary name exists within collection.
fn subsidiary_exists(collection: &Keyring, name: &str) -> Result<Option<Keyring>, KrbError> {
    match collection.search_for_keyring(name, None) {
        Ok(k) => Ok(Some(k)),
        Err(errno::Errno(libc::ENOKEY)) => Ok(None),
        Err(e) => Err(KrbError::from(e)),
    }
}

/// Generates a valid random subsidiary name.
fn get_random_subsidiary_name(collection: &mut Keyring) -> Result<String, KrbError> {
    for _ in 1..10 {
        let s: String = rand::rng()
            .sample_iter(&Alphanumeric)
            .take(7)
            .map(char::from)
            .collect();
        let s = format!("_krb_{s}");
        let k = subsidiary_exists(collection, s.as_str())?;
        if k.is_none() {
            return Ok(s);
        }
    }

    error!(collection=?collection, "Failed to generate random cache name");
    Err(KrbError::CredentialCacheError)
}

fn get_subsidiary_cache_name(residual: &Residual) -> String {
    residual
        .subsidiary
        .clone()
        .unwrap_or(residual.collection.clone())
}

/// Given a collection and a principal, get the subsidiary keyring
fn get_subsidiary_cache(
    name: &Name,
    collection: &mut Keyring,
    residual: &Residual,
) -> Result<Keyring, KrbError> {
    let subsidiary_name = get_subsidiary_cache_name(residual);
    match residual.subsidiary.as_deref() {
        Some(_) => {
            // The subsidiary name was given in the residual
            match subsidiary_exists(collection, &subsidiary_name)? {
                Some(subsidiary) => {
                    // The subsidiary name was given in the residual and it already
                    // exists, check the stored principal matches the given one.
                    let stored_name = get_subsidiary_principal(&subsidiary)?.ok_or_else(|| {
                        error!(
                            ?collection,
                            ?subsidiary,
                            ?subsidiary_name,
                            ?name,
                            "Subsidiary ccache has no principal"
                        );
                        KrbError::CredentialCacheError
                    })?;
                    if &stored_name == name {
                        Ok(subsidiary)
                    } else {
                        error!(
                            ?collection,
                            ?subsidiary_name,
                            ?stored_name,
                            ?name,
                            "Stored principal do not match"
                        );
                        Err(KrbError::CredentialCacheError)
                    }
                }
                None => {
                    // The subsidiary name was given in the residual and it does not exists so create it.
                    collection
                        .add_keyring(subsidiary_name.as_str())
                        .map_err(|e| {
                            error!(?collection, ?e, "Failed to add keyring");
                            KrbError::CredentialCacheError
                        })
                }
            }
        }
        None => {
            // The subsidiary name was not given in the residual
            match subsidiary_exists(collection, subsidiary_name.as_str())? {
                Some(subsidiary) => {
                    let stored_name = get_subsidiary_principal(&subsidiary)?.ok_or_else(|| {
                        error!(
                            ?collection,
                            ?subsidiary,
                            ?subsidiary_name,
                            ?name,
                            "Subsidiary ccache has no principal"
                        );
                        KrbError::CredentialCacheError
                    })?;
                    if &stored_name != name {
                        // If the stored principal do not match generate a random subsidiary name
                        let subsidiary_name = get_random_subsidiary_name(collection)?;
                        let subsidiary = collection.add_keyring(subsidiary_name.as_str())?;
                        Ok(subsidiary)
                    } else {
                        Ok(subsidiary)
                    }
                }
                None => {
                    let subsidiary = collection.add_keyring(subsidiary_name.as_str())?;
                    Ok(subsidiary)
                }
            }
        }
    }
}

fn get_primary_subsidiary_name(collection: &mut Keyring) -> Result<Option<String>, KrbError> {
    let primary_name: &str = "krb_ccache:primary";
    match collection.search_for_key::<User, &str, Option<&mut Keyring>>(primary_name, None) {
        Ok(k) => {
            let payload = k.read()?;
            let mut reader = binrw::io::Cursor::new(payload);
            let pn: PrimaryName = reader.read_type(binrw::Endian::Big).map_err(|err| {
                error!(collection=?collection, error=?err, "Failed to read primary name");
                KrbError::BinRWError
            })?;
            let pn: String = String::from_utf8_lossy(pn.strval.as_slice()).to_string();
            Ok(Some(pn))
        }
        Err(errno::Errno(libc::ENOKEY)) => Ok(None),
        Err(e) => Err(KrbError::from(e)),
    }
}

fn store_clock_skew(clock_skew: Duration, keyring: &mut Keyring) -> Result<Option<Key>, KrbError> {
    let key_name = "__krb5_time_offsets__";
    let offsets = TimeOffsets {
        secs: clock_skew.as_secs() as i32,
        usecs: clock_skew.subsec_micros() as i32,
    };
    let mut c = std::io::Cursor::new(Vec::new());
    offsets.write(&mut c).map_err(|err| {
        error!(keyring=?keyring, offsets=?offsets, error=?err, "Failed to store clock skew");
        KrbError::BinRWError
    })?;
    let vec = c.into_inner();
    let key = keyring.add_key::<User, &str, &[u8]>(key_name, vec.as_slice())?;
    Ok(Some(key))
}

fn store_credential(
    name: &Name,
    ticket: &EncTicket,
    kdc_reply_part: &KdcReplyPart,
    subsidiary: &mut Keyring,
) -> Result<(), KrbError> {
    // Get the SPN and use it as the key name (creds->server)
    let key_name: String = (&kdc_reply_part.server).into();
    let creds: CredentialV4 = CredentialV4::new(name, ticket, kdc_reply_part)?;
    let mut c = std::io::Cursor::new(Vec::new());
    creds.write(&mut c).map_err(|err| {
        error!(subsidiary=?subsidiary, name=?name,error=?err, "Failed to store credential");
        KrbError::BinRWError
    })?;
    let vec = c.into_inner();
    subsidiary
        .add_key::<User, &str, &[u8]>(key_name.as_str(), vec.as_slice())
        .map_err(KrbError::from)?;
    Ok(())
}

fn store_principal(name: &Name, subsidiary: &mut Keyring) -> Result<(), KrbError> {
    match get_subsidiary_principal(subsidiary)? {
        Some(stored) => {
            if &stored == name {
                Ok(())
            } else {
                error!(subsidiary=?subsidiary, stored_name=?stored, name=?name, "Stored principal do not match");
                Err(KrbError::CredentialCacheError)
            }
        }
        None => {
            let key_name = "__krb5_princ__";
            let princ: PrincipalV4 = name.try_into()?;
            let mut c = std::io::Cursor::new(Vec::new());
            princ.write(&mut c).map_err(|err| {
                error!(subsidiary=?subsidiary, name=?name, error=?err, "Failed to store principal");
                KrbError::BinRWError
            })?;
            let vec = c.into_inner();
            subsidiary
                .add_key::<User, &str, &[u8]>(key_name, vec.as_slice())
                .map_err(KrbError::from)?;
            Ok(())
        }
    }
}

fn store_primary_subsidiary_name(
    subsidiary_name: &str,
    collection: &mut Keyring,
) -> Result<String, KrbError> {
    let key_name: &str = "krb_ccache:primary";
    let pn: PrimaryName = PrimaryName {
        strval: subsidiary_name.as_bytes().to_vec(),
    };
    let mut c = std::io::Cursor::new(Vec::new());
    pn.write(&mut c).map_err(|err| {
                error!(subsidiary_name=?subsidiary_name, collection=?collection, error=?err, "Failed to store primary subsidiary name");
                KrbError::BinRWError
            })?;
    let vec = c.into_inner();
    collection
        .add_key::<User, &str, &[u8]>(key_name, vec.as_slice())
        .map_err(|e| {
            error!(?e, "Failed to add key");
            KrbError::from(e)
        })?;
    Ok(subsidiary_name.to_string())
}

pub(super) struct KeyringCredentialCacheContext {
    residual: Residual,
    collection: Keyring,
    subsidiary: Option<Keyring>,
}

impl CredentialCache for KeyringCredentialCacheContext {
    fn name(&mut self) -> Result<String, KrbError> {
        Ok(self.residual.to_string())
    }

    fn init(&mut self, name: &Name, clock_skew: Option<Duration>) -> Result<(), KrbError> {
        // Pick a subsidiary within collection
        let mut subsidiary = get_subsidiary_cache(name, &mut self.collection, &self.residual)?;
        subsidiary.clear()?;

        let desc = subsidiary.description().map_err(|e| {
            error!(?e, "Failed to parse keyring description");
            KrbError::CredentialCacheError
        })?;

        // If subsidiary was not given set as primary
        if self.residual.subsidiary.is_none() {
            trace!(?desc.description, "Set as primary subsidiary");
            store_primary_subsidiary_name(desc.description.as_str(), &mut self.collection)?;
        }

        // Store the principal name within the subsidiary cache
        trace!(
            ?name,
            ?subsidiary,
            ?desc,
            "Storing principal name in subsidiary cache"
        );
        store_principal(name, &mut subsidiary)?;

        // Store clockskew within subsidiary cache
        if let Some(cs) = clock_skew {
            trace!(?cs, ?subsidiary, "Storing clock skew in subsidiary cache");
            store_clock_skew(cs, &mut subsidiary)?;
        };

        trace!(?subsidiary, "Subsidiary cache initialized");
        self.subsidiary = Some(subsidiary);
        Ok(())
    }

    fn destroy(&mut self) -> Result<(), KrbError> {
        let subsidiary_name = match self.residual.subsidiary.as_deref() {
            Some(name) => name.to_string(),
            None => match get_primary_subsidiary_name(&mut self.collection)? {
                Some(name) => name,
                None => {
                    debug!(
                        concat!(
                            "No subsidiary cache was destroyed because the subsidiary name was not specified ",
                            "in the residual and the collection does not have a primary subsidiary defined"
                        )
                    );
                    return Ok(());
                }
            },
        };

        match self
            .collection
            .search_for_keyring(subsidiary_name.as_str(), None)
        {
            Ok(k) => self.collection.unlink_keyring(&k).map_err(|e| {
                error!(?e, "Failed to unlink subsidiary from collection");
                e.into()
            }),
            Err(errno::Errno(libc::ENOKEY)) => {
                trace!(?subsidiary_name, "Subsidiary does not exist");
                Ok(())
            }
            Err(e) => {
                error!(?e, "Failed to search for keyring");
                Err(e.into())
            }
        }
    }

    fn store(&mut self, credentials: &KerberosCredentials) -> Result<(), KrbError> {
        let Some(subsidiary) = self.subsidiary.as_mut() else {
            error!("Credential cache not initialized");
            return Err(KrbError::CredentialCacheError);
        };

        let stored_name = get_subsidiary_principal(subsidiary)?.ok_or_else(|| {
            error!(?subsidiary, "Subsidiary ccache has no principal");
            KrbError::CredentialCacheError
        })?;

        if stored_name != credentials.name {
            error!(
                ?stored_name,
                ?credentials.name,
                "Stored principal do not match"
            );
            return Err(KrbError::CredentialCacheError);
        }

        let desc = subsidiary.description().map_err(|e| {
            error!(?e, "Failed to parse keyring description");
            KrbError::CredentialCacheError
        })?;

        // Store the principal name within the subsidiary cache
        trace!(?desc, "Storing credentials in subsidiary cache");
        store_credential(
            &credentials.name,
            &credentials.ticket,
            &credentials.kdc_reply,
            subsidiary,
        )?;

        Ok(())
    }

    fn dump(&mut self) -> Result<(), KrbError> {
        let subsidiary_name = get_subsidiary_cache_name(&self.residual);

        let Some(subsidiary) = subsidiary_exists(&self.collection, &subsidiary_name)? else {
            error!("Credential cache not initialized");
            return Err(KrbError::CredentialCacheError);
        };

        let time_offsets = get_subsidiary_time_offsets(&subsidiary)?;
        println!("KDC time offset: {:?}", time_offsets);

        let stored_name = get_subsidiary_principal(&subsidiary)?;
        println!("Default principal: {:?}", stored_name);

        let (keys, _) = subsidiary.read().map_err(|e| {
            error!(?e, "Failed to read subsidiary");
            KrbError::CredentialCacheError
        })?;

        for (i, k) in keys.iter().enumerate() {
            let Ok(desc) = k.description() else {
                continue;
            };

            if desc.description == "__krb5_time_offsets__" || desc.description == "__krb5_princ__" {
                continue;
            }

            let payload = k.read()?;
            let mut reader = binrw::io::Cursor::new(payload);
            let v4: CredentialV4 = reader.read_type(binrw::Endian::Big).map_err(|err| {
                error!(error=?err);
                KrbError::BinRWError
            })?;

            println!("Credential [{i}]:");
            println!("{}", v4);
        }
        Ok(())
    }
}

fn get_or_create_keyring(parent: &mut Keyring, name: &str) -> Result<Keyring, Errno> {
    match parent.search_for_keyring(name, None) {
        Ok(k) => Ok(k),
        Err(errno::Errno(libc::ENOKEY)) => parent.add_keyring(name),
        Err(e) => Err(e),
    }
    .inspect_err(|e| error!(?parent, ?name, ?e, "Failed to get or create keyring"))
}

/// fetch or create a keyring for the given collection name within the anchor
fn get_collection(anchor: &str, collection: &str) -> Result<Keyring, KrbError> {
    let mut parent = match anchor {
        "process" => Keyring::attach_or_create(SpecialKeyring::Process)
            .inspect_err(|e| error!(?e, "Failed to attach or create process keyring")),
        "thread" => Keyring::attach_or_create(SpecialKeyring::Thread)
            .inspect_err(|e| error!(?e, "Failed to attach or create thread keyring")),
        "session" => Keyring::attach_or_create(SpecialKeyring::Session)
            .inspect_err(|e| error!(?e, "Failed to attach or create session keyring")),
        "user" => Keyring::attach_or_create(SpecialKeyring::User)
            .inspect_err(|e| error!(?e, "Failed to attach or create user keyring")),
        "persistent" => {
            let uid = match collection.parse::<u32>() {
                Ok(uid) => uid,
                Err(e) => {
                    error!(?collection, ?e, "Failed to parse collection name into uid");
                    return Err(KrbError::CredentialCacheError);
                }
            };
            // This check must be performed because new keys will be owned by the effective uid
            let euid = uzers::get_effective_uid();
            if uid != euid {
                error!(
                    ?uid,
                    ?euid,
                    "The collection name (uid) does not match the effective uid (euid)"
                );
                return Err(KrbError::CredentialCacheError);
            }
            // Must use raw calls to get the uid's persistent keyring
            let parent = keyctl_get_keyring_id(SpecialKeyring::Process.serial(), true)
                .inspect_err(|e| error!(?e, "Failed to attach or create process keyring"))?;
            let parent = keyctl_get_persistent(uid, parent)
                .inspect_err(|e| error!(?e, "Failed to attach to persistent keyring"))?;
            let parent = unsafe { Keyring::new(parent) };
            Ok(parent)
        }
        _ => Err(Errno(libc::ENOTSUP)),
    }?;

    let collection_name = match anchor {
        "persistent" => "_krb".to_string(),
        _ => format!("_krb_{collection}"),
    };

    get_or_create_keyring(&mut parent, &collection_name).map_err(|e| e.into())
}

pub(super) fn resolve(ccache_name: &str) -> Result<Box<dyn CredentialCache>, KrbError> {
    let residual = Residual::parse(ccache_name)?;
    debug!(?residual, "Parsed residual");

    let collection = get_collection(residual.anchor.as_str(), residual.collection.as_str())?;
    trace!(?collection, "Resolved collection within anchor");

    let kcc = KeyringCredentialCacheContext {
        residual,
        collection,
        subsidiary: None,
    };
    Ok(Box::new(kcc))
}

struct KeyringCredentialCacheCollection {
    pub residual: Residual,
    subsidiaries: Vec<Box<dyn CredentialCache>>,
}

impl CredentialCacheCollection for KeyringCredentialCacheCollection {
    fn primary(&mut self) -> Result<String, KrbError> {
        let mut col = get_collection(
            self.residual.anchor.as_ref(),
            self.residual.collection.as_ref(),
        )?;
        let primary_name = get_primary_subsidiary_name(&mut col)?;
        match primary_name {
            Some(p) => Ok(p),
            None => {
                error!("Failed to read primary credential cache name");
                Err(KrbError::CredentialCacheError)
            }
        }
    }
}

impl Deref for KeyringCredentialCacheCollection {
    type Target = Vec<Box<dyn CredentialCache>>;
    fn deref(&self) -> &Self::Target {
        &self.subsidiaries
    }
}
impl DerefMut for KeyringCredentialCacheCollection {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.subsidiaries
    }
}

pub(super) fn resolve_collection(
    name: &str,
) -> Result<Box<dyn CredentialCacheCollection<Target = Vec<Box<dyn CredentialCache>>>>, KrbError> {
    trace!(?name, "Resolving collection");

    let residual = Residual::parse(name)?;
    debug!(?residual, "Parsed residual");

    let collection = get_collection(residual.anchor.as_str(), residual.collection.as_str())?;
    trace!(?collection, "Resolved collection within anchor");

    // Now iterate subsidiaries
    let (_, keyrings) = collection.read().map_err(|e| {
        error!(?e, "Failed to read collection");
        KrbError::CredentialCacheError
    })?;
    trace!(?keyrings, "Read subsidiaries withing collection");

    let mut col = KeyringCredentialCacheCollection {
        residual,
        subsidiaries: vec![],
    };
    for k in keyrings {
        let desc = k.description().map_err(|e| {
            error!(?e, "Failed to get keyring description");
            KrbError::CredentialCacheError
        })?;
        trace!(?k, ?desc, "Got subsidiary description");

        let subsidiary_name = format!(
            "KEYRING:{}:{}:{}",
            col.residual.anchor.as_str(),
            col.residual.collection.as_str(),
            desc.description.as_str()
        );
        trace!(?subsidiary_name, "Resolving collection subisidiary");
        if let Ok(c) = super::resolve(Some(&subsidiary_name)) {
            col.deref_mut().push(c);
        }
    }
    Ok(Box::new(col))
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::process::Command;
    #[cfg(feature = "keyring")]
    use std::process::Stdio;

    #[tokio::test]
    async fn test_ccache_keyring_residual_parse() -> Result<(), KrbError> {
        let residual = Residual::parse("KEYRING:session");
        assert!(residual.is_err());
        let residual = Residual::parse("KEYRING:session:");
        assert!(residual.is_err());
        let residual = Residual::parse("KEYRING:session:1000")?;
        assert_eq!(
            residual,
            Residual {
                anchor: "session".to_string(),
                collection: "1000".to_string(),
                subsidiary: None
            }
        );
        let residual = Residual::parse("KEYRING:session:1000:")?;
        assert_eq!(
            residual,
            Residual {
                anchor: "session".to_string(),
                collection: "1000".to_string(),
                subsidiary: None
            }
        );
        let residual = Residual::parse("KEYRING:session:1000:foo")?;
        assert_eq!(
            residual,
            Residual {
                anchor: "session".to_string(),
                collection: "1000".to_string(),
                subsidiary: Some("foo".to_string())
            }
        );
        Ok(())
    }

    fn klist_all(ccache_name: &str) -> String {
        let output = Command::new("klist")
            .stderr(Stdio::null())
            .arg("-c")
            .arg(ccache_name)
            .arg("-A")
            .output()
            .expect("Unable to execute command klist");
        assert!(output.status.success());

        String::from_utf8_lossy(output.stdout.as_slice()).to_string()
    }

    #[tokio::test]
    async fn test_ccache_keyring_primary() -> Result<(), KrbError> {
        // No subsidiary in residual
        let ccache_name = Some("KEYRING:session:c1");

        let p1 = Name::Principal {
            name: "p1".to_string(),
            realm: "EXAMPLE.COM".to_string(),
        };
        let p2 = Name::Principal {
            name: "p2".to_string(),
            realm: "EXAMPLE.COM".to_string(),
        };
        let p3 = Name::Principal {
            name: "p3".to_string(),
            realm: "EXAMPLE.COM".to_string(),
        };

        let mut ccache = crate::ccache::resolve(ccache_name)?;
        let mut col = get_collection("session", "c1")?;

        // Will set primary
        ccache.init(&p1, None)?;
        let primary = get_primary_subsidiary_name(&mut col)?.expect("No primary key");
        assert!(primary == "c1");

        // Will generate a new subsidiary and override primary
        ccache.init(&p2, None)?;
        let random = get_primary_subsidiary_name(&mut col)?.expect("No primary key");
        assert!(random != "c1"); // subsidiary name random

        // Subsidiary specified, primary not overrided
        let ccache_name = Some("KEYRING:session:c1:s1");
        let mut ccache = crate::ccache::resolve(ccache_name)?;
        ccache.init(&p3, None)?;
        let primary = get_primary_subsidiary_name(&mut col)?.expect("No primary key");
        assert!(primary == random); // subsidiary name was given in residual, do not override

        // At this point, collection has 3 subsidiaries
        let ccache_name = "KEYRING:session:c1";
        let output = klist_all(ccache_name);
        assert!(output.contains("p1@EXAMPLE.COM"));
        assert!(output.contains("p2@EXAMPLE.COM"));
        assert!(output.contains("p3@EXAMPLE.COM"));

        // Destroy specifying the subsidiary deletes the specified subsidiary.
        let ccache_name = "KEYRING:session:c1:c1";
        let mut ccache = crate::ccache::resolve(Some(ccache_name))?;
        ccache.destroy()?;
        let ccache_name = "KEYRING:session:c1";
        let output = klist_all(ccache_name);
        assert!(!output.contains("p1@EXAMPLE.COM"));
        assert!(output.contains("p2@EXAMPLE.COM"));
        assert!(output.contains("p3@EXAMPLE.COM"));

        // Destroy without specifying the subsidiary deletes the primary, but the key remains
        let ccache_name = "KEYRING:session:c1";
        let mut ccache = crate::ccache::resolve(Some(ccache_name))?;
        ccache.destroy()?;
        let output = klist_all(ccache_name);
        assert!(!output.contains("p1@EXAMPLE.COM"));
        assert!(!output.contains("p2@EXAMPLE.COM"));
        assert!(output.contains("p3@EXAMPLE.COM"));

        // Remove collection keyring
        let mut col = Keyring::attach_or_create(SpecialKeyring::Session)?;
        if let Ok(k) = col.search_for_keyring("_krb_c1", None) {
            col.unlink_keyring(&k).expect("Failed to unlink");
        };

        Ok(())
    }

    #[tokio::test]
    async fn test_ccache_keyring() -> Result<(), KrbError> {
        if std::env::var("CI").is_ok() {
            // Skip this test in CI, as it requires a KDC running on localhost
            tracing::warn!("Skipping test_ccache_keyring in CI");
            return Ok(());
        }

        let ccache_name = Some("KEYRING:process:foo:bar");
        let mut ccache = crate::ccache::resolve(ccache_name)?;

        let credentials = crate::proto::get_tgt("testuser", "EXAMPLE.COM", "password").await?;
        ccache.init(&credentials.name, None)?;
        ccache.store(&credentials)?;

        // Store the same principal in the same subsidiary must succeed
        let credentials = crate::proto::get_tgt("testuser", "EXAMPLE.COM", "password").await?;
        ccache.store(&credentials)?;

        // Store a different principal in the same subsidiary must fail
        let credentials = crate::proto::get_tgt("testuser2", "EXAMPLE.COM", "password").await?;
        let r = ccache.store(&credentials);
        assert!(r.is_err());

        // Store a different principal in a different subsidiary must succeed
        let ccache_name_zap = Some("KEYRING:process:foo:zap");
        let mut ccache_zap = crate::ccache::resolve(ccache_name_zap)?;
        ccache_zap.init(&credentials.name, None)?;
        ccache_zap.store(&credentials)?;

        // If subsidiary not given a random one will be created
        let ccache_name_no_sub = Some("KEYRING:process:abc");
        let mut ccache_no_sub = crate::ccache::resolve(ccache_name_no_sub)?;
        ccache_no_sub.init(&credentials.name, None)?;
        ccache_no_sub.store(&credentials)?;

        Ok(())
    }
}
