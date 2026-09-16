mod cc_dir;
mod cc_file;

#[cfg(feature = "keyring")]
mod cc_keyring;

use crate::asn1::constants::encryption_types::EncryptionType as Asn1EncryptionType;
use crate::asn1::constants::PrincipalNameType;
use crate::asn1::encrypted_data::EncryptedData as Asn1EncryptedData;
use crate::asn1::tagged_ticket::TaggedTicket as Asn1TaggedTicket;
use crate::asn1::tagged_ticket::Ticket as Asn1Ticket;
use crate::asn1::ticket_flags::TicketFlags;
use crate::client::conf::KerberosConfig;
use crate::error::KrbError;
use crate::proto::KerberosCredentials;
use crate::proto::{EncTicket, EncryptedData, KdcReplyPart, Name, SessionKey};
use binrw::{binread, binwrite};
use chrono::prelude::DateTime;
use chrono::Utc;
use crypto_glue::der::{asn1::OctetString, Encode};
use std::env;
use std::fmt;
use std::ops::Deref;
use std::ops::DerefMut;
use std::path::Path;
use std::time::Duration;
use std::time::SystemTime;
use std::time::UNIX_EPOCH;
use tracing::{debug, error, trace};
use uzers::get_current_uid;

/* TODO:
 *   - Handle cache conf entries. CredentialCache::new() could take a KV pair collection
 *   - Handle multiple credentials. The time offset is global, as the primary name. The
 *     there is a list of credentials, the primary name usually matches the first's
 *     credential 'client' field.
 */

#[binwrite]
#[bw(big)]
#[binread]
#[derive(Debug)]
struct DataComponent {
    #[bw(try_calc(u32::try_from(value.len())))]
    value_len: u32,
    #[br(count = value_len)]
    value: Vec<u8>,
}

impl fmt::Display for DataComponent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for b in &self.value {
            write!(f, "{:02X}", b)?;
        }
        Ok(())
    }
}

#[binwrite]
#[bw(big)]
#[binread]
#[derive(Debug)]
struct PrincipalV4 {
    name_type: u32,
    #[bw(try_calc(u32::try_from(components.len())))]
    components_count: u32,
    realm: DataComponent,
    #[br(count = components_count)]
    components: Vec<DataComponent>,
}

impl fmt::Display for PrincipalV4 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name: Name = self.try_into().map_err(|_| fmt::Error)?;
        write!(f, "{}", name)
    }
}

#[binwrite]
#[bw(big)]
#[binread]
#[derive(Debug)]
enum Principal {
    V4(PrincipalV4),
}

impl fmt::Display for Principal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Principal::V4(v4) => {
                let name: Name = v4.try_into().map_err(|_| fmt::Error)?;
                write!(f, "{name}")
            }
        }
    }
}

#[binwrite]
#[bw(big)]
#[binread]
struct KeyBlockV4 {
    enc_type: u16,
    data: DataComponent,
}

impl fmt::Debug for KeyBlockV4 {
    #[cfg(not(feature = "developer"))]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeyBlockV4")
            .field("enc_type", &self.enc_type)
            .field("data", &"<SECRET>")
            .finish()
    }
    #[cfg(feature = "developer")]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeyBlockV4")
            .field("enc_type", &self.enc_type)
            .field("data", &self.data)
            .finish()
    }
}

impl fmt::Display for KeyBlockV4 {
    #[cfg(not(feature = "developer"))]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}] <SECRET>", self.enc_type)
    }
    #[cfg(feature = "developer")]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}] {}", self.enc_type, self.data)
    }
}

#[binwrite]
#[bw(big)]
#[binread]
#[derive(Debug)]
enum KeyBlock {
    V4(KeyBlockV4),
}

impl fmt::Display for KeyBlock {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            KeyBlock::V4(v4) => write!(f, "{}", v4),
        }
    }
}

#[binwrite]
#[bw(big)]
#[binread]
#[derive(Debug)]
struct Address {
    addr_type: u16,
    data: DataComponent,
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}] ", self.addr_type)?;
        for v in &self.data.value {
            write!(f, "{:02X}", v)?;
        }
        writeln!(f)
    }
}

#[binwrite]
#[bw(big)]
#[binread]
#[derive(Debug)]
struct Addresses {
    #[bw(try_calc(u32::try_from(addresses.len())))]
    count: u32,
    #[br(count = count)]
    addresses: Vec<Address>,
}

#[binwrite]
#[bw(big)]
#[binread]
#[derive(Debug)]
struct AuthDataComponent {
    ad_type: u16,
    data: DataComponent,
}

impl fmt::Display for AuthDataComponent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}]", self.ad_type)?;
        for v in &self.data.value {
            write!(f, "{:02X}", v)?;
        }
        writeln!(f)
    }
}

#[binwrite]
#[bw(big)]
#[binread]
#[derive(Debug)]
struct AuthData {
    #[bw(try_calc(u32::try_from(auth_data.len())))]
    count: u32,
    #[br(count = count)]
    auth_data: Vec<AuthDataComponent>,
}

#[binwrite]
#[bw(big)]
#[binread]
#[derive(Debug)]
enum Credential {
    V4(CredentialV4),
}

impl fmt::Display for Credential {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Credential::V4(v4) => write!(f, "{}", v4),
        }
    }
}

#[binwrite]
#[bw(big)]
#[binread]
#[derive(Debug)]
struct CredentialV4 {
    client: PrincipalV4,
    server: PrincipalV4,
    keyblock: KeyBlock,
    authtime: u32,
    starttime: u32,
    endtime: u32,
    renew_till: u32,
    is_skey: u8,
    ticket_flags: u32,
    addresses: Addresses,
    authdata: AuthData,
    ticket: DataComponent,
    second_ticket: DataComponent,
}

impl fmt::Display for CredentialV4 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "Client: {}", self.client)?;
        writeln!(f, "Server: {}", self.server)?;
        writeln!(f, "Key: {}", self.keyblock)?;

        let d = UNIX_EPOCH + Duration::from_secs(self.authtime.into());
        let d = DateTime::<Utc>::from(d);
        writeln!(f, "Authentication time: {}", d)?;

        let d = UNIX_EPOCH + Duration::from_secs(self.starttime.into());
        let d = DateTime::<Utc>::from(d);
        writeln!(f, "Start time; {}", d)?;

        let d = UNIX_EPOCH + Duration::from_secs(self.endtime.into());
        let d = DateTime::<Utc>::from(d);
        writeln!(f, "End time: {}", d)?;

        let d = UNIX_EPOCH + Duration::from_secs(self.renew_till.into());
        let d = DateTime::<Utc>::from(d);
        writeln!(f, "Renew until: {}", d)?;

        writeln!(f, "Is SKEY: {}", self.is_skey)?;

        let t = TicketFlags::from_bits(self.ticket_flags);
        writeln!(f, "Ticket flags: {}", t)?;

        writeln!(f, "Addresses:")?;
        for addr in &self.addresses.addresses {
            writeln!(f, "  {}", addr)?;
        }

        writeln!(f, "Authorization data:")?;
        for a in &self.authdata.auth_data {
            writeln!(f, "  {}", a)?;
        }

        writeln!(f, "Ticket: {}", self.ticket)?;
        writeln!(f, "Second Ticket: {}", self.second_ticket)?;

        Ok(())
    }
}

impl CredentialV4 {
    pub fn new(
        client: &Name,
        ticket: &EncTicket,
        enc_part: &KdcReplyPart,
    ) -> Result<Self, KrbError> {
        let cred: Self = CredentialV4 {
            client: client.try_into()?,
            server: (&enc_part.server).try_into()?,
            keyblock: KeyBlock::V4((&enc_part.key).try_into()?),
            authtime: enc_part
                .auth_time
                .duration_since(SystemTime::UNIX_EPOCH)
                .map_err(|_| KrbError::InsufficientData)?
                .as_secs() as u32,
            starttime: if let Some(start_time) = enc_part.start_time {
                start_time
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .map_err(|_| KrbError::InsufficientData)?
                    .as_secs() as u32
            } else {
                0u32
            },
            endtime: enc_part
                .end_time
                .duration_since(SystemTime::UNIX_EPOCH)
                .map_err(|_| KrbError::InsufficientData)?
                .as_secs() as u32,
            renew_till: if let Some(till) = enc_part.renew_until {
                till.duration_since(SystemTime::UNIX_EPOCH)
                    .map_err(|_| KrbError::InsufficientData)?
                    .as_secs() as u32
            } else {
                0u32
            },
            is_skey: 0u8,
            ticket_flags: enc_part.flags.bits().reverse_bits(),
            addresses: Addresses { addresses: vec![] },
            authdata: AuthData { auth_data: vec![] },
            ticket: DataComponent {
                value: match &ticket.enc_part {
                    EncryptedData::Aes256CtsHmacSha196 { kvno, data } => {
                        let t = Asn1Ticket {
                            tkt_vno: 5,
                            realm: (&enc_part.server).try_into()?,
                            sname: (&enc_part.server).try_into()?,
                            enc_part: Asn1EncryptedData {
                                etype: Asn1EncryptionType::AES256_CTS_HMAC_SHA1_96 as i32,
                                kvno: *kvno,
                                cipher: OctetString::new(data.clone())
                                    .map_err(|_| KrbError::DerEncodeOctetString)?,
                            },
                        };
                        let tt = Asn1TaggedTicket::new(t);
                        tt.to_der().map_err(|e| {
                            println!("{e:#?}");
                            KrbError::DerEncodeEncTicketPart
                        })?
                    }
                    EncryptedData::Opaque { etype, kvno, data } => {
                        let t = Asn1Ticket {
                            tkt_vno: 5,
                            realm: (&enc_part.server).try_into()?,
                            sname: (&enc_part.server).try_into()?,
                            enc_part: Asn1EncryptedData {
                                etype: *etype,
                                kvno: *kvno,
                                cipher: OctetString::new(data.clone())
                                    .map_err(|_| KrbError::DerEncodeOctetString)?,
                            },
                        };
                        let tt = Asn1TaggedTicket::new(t);
                        tt.to_der().map_err(|e| {
                            error!(?e, "DerEncodeEncTicketPart");
                            KrbError::DerEncodeEncTicketPart
                        })?
                    }
                },
            },
            second_ticket: DataComponent { value: vec![] },
        };
        Ok(cred)
    }
}

impl TryFrom<&Name> for PrincipalV4 {
    type Error = KrbError;

    fn try_from(name: &Name) -> Result<Self, Self::Error> {
        match name {
            Name::Principal { name, realm } => {
                let p: PrincipalV4 = PrincipalV4 {
                    name_type: PrincipalNameType::NtPrincipal as u32,
                    realm: DataComponent {
                        value: realm.as_bytes().into(),
                    },
                    components: vec![DataComponent {
                        value: name.as_bytes().into(),
                    }],
                };
                Ok(p)
            }
            Name::SrvInst {
                service,
                instance,
                realm,
            } => {
                let mut components: Vec<DataComponent> = vec![];
                components.push(DataComponent {
                    value: service.as_bytes().into(),
                });
                let iv: Vec<DataComponent> = instance
                    .iter()
                    .map(|x| DataComponent {
                        value: x.as_bytes().into(),
                    })
                    .collect();
                components.extend(iv);

                let p: PrincipalV4 = PrincipalV4 {
                    name_type: PrincipalNameType::NtSrvInst as u32,
                    realm: DataComponent {
                        value: realm.as_bytes().into(),
                    },
                    components,
                };
                Ok(p)
            }
            _ => Err(KrbError::PrincipalNameInvalidType),
        }
    }
}

impl TryInto<Name> for &PrincipalV4 {
    type Error = KrbError;

    fn try_into(self) -> Result<Name, Self::Error> {
        let name_type: i32 = self.name_type as i32;
        let name_type: PrincipalNameType = name_type.try_into().map_err(|err| {
            error!(?err, ?name_type, "invalid principal name type");
            KrbError::PrincipalNameInvalidType
        })?;

        match name_type {
            PrincipalNameType::NtPrincipal => {
                let n: Name = Name::Principal {
                    name: self
                        .components
                        .iter()
                        .map(|x| String::from_utf8_lossy(x.value.as_slice()).to_string())
                        .collect::<Vec<String>>()
                        .join(""),
                    realm: String::from_utf8_lossy(self.realm.value.as_slice()).to_string(),
                };
                Ok(n)
            }
            PrincipalNameType::NtSrvInst => {
                let n: Name = Name::SrvInst {
                    service: self
                        .components
                        .first()
                        .ok_or(KrbError::NameNotPrincipal)
                        .map(|x| String::from_utf8_lossy(x.value.as_slice()).to_string())?,
                    instance: self
                        .components
                        .get(1..)
                        .ok_or(KrbError::NameNotPrincipal)?
                        .iter()
                        .map(|x| String::from_utf8_lossy(x.value.as_slice()).to_string())
                        .collect::<Vec<String>>(),
                    realm: String::from_utf8_lossy(self.realm.value.as_slice()).to_string(),
                };
                Ok(n)
            }
            PrincipalNameType::NtSrvHst => {
                let n: Name = Name::SrvHst {
                    service: self
                        .components
                        .first()
                        .ok_or(KrbError::NameNotPrincipal)
                        .map(|x| String::from_utf8_lossy(x.value.as_slice()).to_string())?,
                    host: self
                        .components
                        .get(1..)
                        .ok_or(KrbError::NameNotServiceHost)?
                        .iter()
                        .map(|x| String::from_utf8_lossy(x.value.as_slice()).to_string())
                        .collect::<Vec<String>>()
                        .join("/"),
                    realm: String::from_utf8_lossy(self.realm.value.as_slice()).to_string(),
                };
                Ok(n)
            }
            _ => Err(KrbError::PrincipalNameInvalidType),
        }
    }
}

impl TryFrom<&SessionKey> for KeyBlockV4 {
    type Error = KrbError;

    fn try_from(value: &SessionKey) -> Result<Self, Self::Error> {
        match value {
            SessionKey::Aes256CtsHmacSha196 { k } => Ok(KeyBlockV4 {
                enc_type: 0x12,
                data: DataComponent { value: k.to_vec() },
            }),
        }
    }
}

#[cfg(feature = "keyring")]
fn default_ccache_name() -> String {
    "KEYRING:persistent:%{uid}".to_string()
}

#[cfg(not(feature = "keyring"))]
fn default_ccache_name() -> String {
    "FILE:/tmp/krb5cc_%{uid}".to_string()
}

fn parse_ccache_name(ccache: Option<&str>) -> Result<String, KrbError> {
    let uid = get_current_uid().to_string();

    let ccache_name = match ccache {
        Some(c) => c.to_string(),
        None => match env::var("KRB5CCNAME") {
            Ok(val) => val,
            _ => {
                let config = KerberosConfig::from_defaults().map_err(|e| {
                    error!("Failed to read config: {:?}", e);
                    KrbError::ConfigError(e)
                })?;
                match config.libdefaults("default_ccache_name") {
                    Some(v) => v,
                    _ => default_ccache_name(),
                }
            }
        },
    }
    .replace("%{uid}", uid.as_str());
    Ok(ccache_name)
}

pub trait CredentialCache {
    fn name(&mut self) -> Result<String, KrbError>;
    fn init(&mut self, name: &Name, clock_skew: Option<Duration>) -> Result<(), KrbError>;
    fn destroy(&mut self) -> Result<(), KrbError>;
    fn store(&mut self, credentials: &KerberosCredentials) -> Result<(), KrbError>;
    fn dump(&mut self) -> Result<(), KrbError>;
}

pub fn resolve(ccache_name: Option<&str>) -> Result<Box<dyn CredentialCache>, KrbError> {
    let ccache_name = parse_ccache_name(ccache_name)?;
    trace!(?ccache_name, "Resolving credential cache");

    if ccache_name.starts_with("FILE:") {
        return cc_file::resolve(ccache_name.as_str());
    }

    if ccache_name.starts_with("DIR:") {
        return cc_dir::resolve(ccache_name.as_str());
    }

    #[cfg(feature = "keyring")]
    if ccache_name.starts_with("KEYRING:") {
        return cc_keyring::resolve(ccache_name.as_str());
    }

    debug!(?ccache_name, "Unsupported credential cache type");
    Err(KrbError::UnsupportedCredentialCacheType)
}

pub trait CredentialCacheCollection: Deref + DerefMut {
    fn primary(&mut self) -> Result<String, KrbError>;
}

pub fn resolve_collection(
    ccache_name: Option<&str>,
) -> Result<Box<dyn CredentialCacheCollection<Target = Vec<Box<dyn CredentialCache>>>>, KrbError> {
    let ccache_name = parse_ccache_name(ccache_name)?;
    trace!(?ccache_name, "Resolving collection");

    if ccache_name.starts_with("DIR:") {
        let path = ccache_name.strip_prefix("DIR:").unwrap_or(&ccache_name);
        let path = Path::new(path);
        return cc_dir::resolve_collection(path);
    }

    #[cfg(feature = "keyring")]
    if ccache_name.starts_with("KEYRING:") {
        return cc_keyring::resolve_collection(ccache_name.as_str());
    }

    debug!(?ccache_name, "Unsupported credential cache type");
    Err(KrbError::UnsupportedCredentialCacheType)
}

#[cfg(test)]
mod tests {
    use tracing::warn;

    use super::*;
    use std::process::Command;
    #[cfg(feature = "keyring")]
    use std::process::Stdio;

    #[tokio::test]
    async fn test_ccache_file_store() -> Result<(), KrbError> {
        let _ = tracing_subscriber::fmt::try_init();
        if std::env::var("CI").is_ok() {
            // Skip this test in CI, as it requires a KDC running on localhost
            warn!("Skipping test_ccache_file_store in CI");
            return Ok(());
        }

        let creds = crate::proto::get_tgt("testuser", "EXAMPLE.COM", "password").await?;

        let path = "/tmp/krb5cc_krime";
        let ccache_name = format!("FILE:{path}");
        let mut ccache = super::resolve(Some(ccache_name.as_str()))?;
        ccache.init(&creds.name, None)?;
        ccache.store(&creds)?;
        assert!(std::fs::exists(path).expect("Unable to check if file exists"));

        // TODO load and compare

        // Test MIT can parse the created ccache
        let output = Command::new("klist")
            .arg("-c")
            .arg(ccache_name.as_str())
            .output()
            .expect("Unable to execute command klist");
        assert!(output.status.success());

        let output = String::from_utf8_lossy(output.stdout.as_slice()).to_string();
        assert!(output.contains("testuser@EXAMPLE.COM"));

        ccache.destroy()?;
        assert!(!std::fs::exists(path).expect("Unable to check if file exists"));

        Ok(())
    }

    #[tokio::test]
    #[cfg(feature = "keyring")]
    async fn test_ccache_keyring_store() -> Result<(), KrbError> {
        if std::env::var("CI").is_ok() {
            // Skip this test in CI, as it requires a KDC running on localhost
            warn!("Skipping get_tgt in CI");
            return Ok(());
        }

        let ccache_name = "KEYRING:session:abc";
        let ccname = Some(ccache_name);

        let mut ccache = super::resolve(ccname)?;
        let creds = crate::proto::get_tgt("testuser", "EXAMPLE.COM", "password").await?;
        ccache.init(&creds.name, None)?;
        ccache.store(&creds)?;

        let mut ccache = super::resolve(ccname)?;
        let creds = crate::proto::get_tgt("testuser2", "EXAMPLE.COM", "password").await?;
        ccache.init(&creds.name, None)?;
        ccache.store(&creds)?;

        let output = Command::new("klist")
            .stderr(Stdio::null())
            .arg("-c")
            .arg(ccache_name)
            .arg("-A")
            .output()
            .expect("Unable to execute command klist");
        assert!(output.status.success());

        let output = String::from_utf8_lossy(output.stdout.as_slice()).to_string();
        assert!(output.contains("testuser@EXAMPLE.COM"));
        assert!(output.contains("testuser2@EXAMPLE.COM"));

        Ok(())
    }
}
