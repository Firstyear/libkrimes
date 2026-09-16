mod ms_pac;
mod reply;
mod request;
mod time;

pub use self::reply::{
    AuthenticationReply, AuthenticationReplyBuilder, KerberosReply, PreauthErrorReply,
    TicketGrantReply,
};
pub use self::request::{
    AuthenticationRequest, AuthenticationRequestBuilder, KerberosRequest, TicketGrantRequest,
    TicketGrantRequestUnverified,
};
pub use self::time::{
    AuthenticationTimeBound, TicketGrantTimeBound, TicketRenewTimeBound, TimeBoundError,
};
use crate::asn1::ap_req::ApReq;
use crate::asn1::authenticator::Authenticator;
use crate::asn1::constants::PrincipalNameType;
use crate::asn1::ticket_flags::TicketFlags;
use crate::asn1::{
    constants::{encryption_types::EncryptionType, pa_data_types::PaDataType},
    enc_kdc_rep_part::EncKdcRepPart as Asn1EncKdcRepPart,
    enc_ticket_part::{EncTicketPart, TaggedEncTicketPart},
    encrypted_data::EncryptedData as KdcEncryptedData,
    encryption_key::EncryptionKey as KdcEncryptionKey,
    etype_info2::ETypeInfo2 as KdcETypeInfo2,
    kerberos_string::KerberosString,
    kerberos_time::KerberosTime,
    last_req::LastReqItem as KdcLastReqItem,
    pa_data::PaData,
    pa_enc_ts_enc::PaEncTsEnc,
    principal_name::PrincipalName,
    realm::Realm,
    tagged_enc_kdc_rep_part::TaggedEncKdcRepPart,
    tagged_ticket::TaggedTicket as Asn1Ticket,
    Ia5String, OctetString,
};
use crate::constants::{PBKDF2_SHA1_ITER, PBKDF2_SHA1_ITER_MINIMUM, RFC_PBKDF2_SHA1_ITER};
use crate::crypto::{
    checksum_hmac_sha1_96_aes256, decrypt_aes256_cts_hmac_sha1_96,
    derive_key_aes256_cts_hmac_sha1_96, encrypt_aes256_cts_hmac_sha1_96,
};
use crate::error::KrbError;
use crypto_glue::aes256::{self, Aes256Key};
use der::{Decode, Encode};
use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use std::fmt;
use std::time::{Duration, SystemTime};
use tracing::{error, trace};

// Zeroize blocked on https://github.com/RustCrypto/block-ciphers/issues/426
// use zeroize::Zeroizing;

#[derive(Debug, Default)]
pub struct Preauth {
    tgs_req: Option<ApReq>,
    // pa_fx_fast: Option<PaFxFastRequest>,
    // pa_fx_fast: Option<Vec<u8>>,
    enc_timestamp: Option<EncryptedData>,
    pa_fx_cookie: Option<Vec<u8>>,
}

#[derive(Clone, PartialEq, Eq)]
pub enum DerivedKey {
    Aes256CtsHmacSha196 {
        k: Aes256Key,
        i: u32,
        s: String,
        kvno: u32,
    },
}

impl DerivedKey {
    pub fn k(&self) -> Vec<u8> {
        match self {
            DerivedKey::Aes256CtsHmacSha196 { k, .. } => k.to_vec(),
        }
    }

    pub fn new_aes256_cts_hmac_sha1_96(
        passphrase: &str,
        salt: &str,
        iter_count: Option<u32>,
        kvno: u32,
    ) -> Result<Self, KrbError> {
        if passphrase.len() < 16 {
            // Due to how the cryptography of KRB works, we need to ensure not only that the password
            // is long, but also that the pkbdf2 rounds is high.
            return Err(KrbError::InsecurePassphrase);
        }
        let iter_count = iter_count
            .unwrap_or(PBKDF2_SHA1_ITER)
            .clamp(PBKDF2_SHA1_ITER_MINIMUM, u32::MAX);

        derive_key_aes256_cts_hmac_sha1_96(passphrase.as_bytes(), salt.as_bytes(), iter_count).map(
            |k| DerivedKey::Aes256CtsHmacSha196 {
                k,
                i: iter_count,
                s: salt.to_string(),
                kvno,
            },
        )
    }

    // Used to derive a key for the user. We have to do this to get the correct
    // etype from the enc data as pa_data may have many etype_info2 and the spec
    // doesn't call it an error to have multiple ... yay for confusing poorly
    // structured protocols.
    pub fn from_encrypted_reply(
        encrypted_data: &EncryptedData,
        pa_data_etype_info2: Option<&[EtypeInfo2]>,
        realm: &str,
        username: &str,
        passphrase: &str,
        kvno: u32,
    ) -> Result<Self, KrbError> {
        // If only Krb had put the *parameters* with the encrypted data, like any other
        // sane ecosystem.
        match encrypted_data {
            EncryptedData::Aes256CtsHmacSha196 { .. } => {
                // Find if we have an etype info?

                let maybe_etype_info2 = pa_data_etype_info2
                    .iter()
                    .flat_map(|slice| slice.iter())
                    .find(|etype_info2| {
                        matches!(&etype_info2.etype, EncryptionType::AES256_CTS_HMAC_SHA1_96)
                    });

                let (salt, iter_count) = if let Some(etype_info2) = maybe_etype_info2 {
                    let salt = etype_info2.salt.as_ref().cloned();

                    let iter_count = if let Some(s2kparams) = &etype_info2.s2kparams {
                        if s2kparams.len() != 4 {
                            return Err(KrbError::PreauthInvalidS2KParams);
                        };
                        let mut iter_count = [0u8; 4];
                        iter_count.copy_from_slice(s2kparams);

                        Some(u32::from_be_bytes(iter_count))
                    } else {
                        None
                    };

                    (salt, iter_count)
                } else {
                    (None, None)
                };

                let salt = salt.unwrap_or_else(|| format!("{realm}{username}"));

                let iter_count = iter_count.unwrap_or(RFC_PBKDF2_SHA1_ITER);

                derive_key_aes256_cts_hmac_sha1_96(
                    passphrase.as_bytes(),
                    salt.as_bytes(),
                    iter_count,
                )
                .map(|k| DerivedKey::Aes256CtsHmacSha196 {
                    k,
                    i: iter_count,
                    s: salt,
                    kvno,
                })
            }
            EncryptedData::Opaque { .. } => Err(KrbError::UnsupportedEncryption),
        }
    }

    // This is used in pre-auth timestamp as there is no kvno as I can see?
    pub fn from_etype_info2(
        etype_info2: &EtypeInfo2,
        realm: &str,
        username: &str,
        passphrase: &str,
        kvno: u32,
    ) -> Result<Self, KrbError> {
        let salt = etype_info2
            .salt
            .as_ref()
            .cloned()
            .unwrap_or_else(|| format!("{realm}{username}"));

        match &etype_info2.etype {
            EncryptionType::AES256_CTS_HMAC_SHA1_96 => {
                // Iter count is from the s2kparams
                let iter_count = if let Some(s2kparams) = &etype_info2.s2kparams {
                    if s2kparams.len() != 4 {
                        return Err(KrbError::PreauthInvalidS2KParams);
                    };
                    let mut iter_count = [0u8; 4];
                    iter_count.copy_from_slice(s2kparams);

                    u32::from_be_bytes(iter_count)
                } else {
                    // Assume the insecure default rfc value.
                    RFC_PBKDF2_SHA1_ITER
                };

                derive_key_aes256_cts_hmac_sha1_96(
                    passphrase.as_bytes(),
                    salt.as_bytes(),
                    iter_count,
                )
                .map(|k| DerivedKey::Aes256CtsHmacSha196 {
                    k,
                    i: iter_count,
                    s: salt,
                    kvno,
                })
            }
            _ => Err(KrbError::UnsupportedEncryption),
        }
    }

    pub(crate) fn encrypt_pa_enc_timestamp(
        &self,
        paenctsenc: &PaEncTsEnc,
    ) -> Result<EncryptedData, KrbError> {
        let data = paenctsenc
            .to_der()
            .map_err(|_| KrbError::DerEncodePaEncTsEnc)?;

        // https://www.rfc-editor.org/rfc/rfc4120#section-5.2.7.2
        let key_usage = 1;

        match self {
            DerivedKey::Aes256CtsHmacSha196 {
                k,
                i: _,
                s: _,
                kvno,
            } => encrypt_aes256_cts_hmac_sha1_96(k, &data, key_usage).map(|data| {
                EncryptedData::Aes256CtsHmacSha196 {
                    kvno: Some(*kvno),
                    data,
                }
            }),
        }
    }

    pub(crate) fn encrypt_as_rep_part(
        &self,
        enc_kdc_rep_part: Asn1EncKdcRepPart,
    ) -> Result<(EtypeInfo2, EncryptedData), KrbError> {
        let data = TaggedEncKdcRepPart::EncAsRepPart(enc_kdc_rep_part)
            .to_der()
            .map_err(|_| KrbError::DerEncodeEncKdcRepPart)?;

        let key_usage = 3;

        match self {
            DerivedKey::Aes256CtsHmacSha196 { i, s, k, kvno } => {
                let data = encrypt_aes256_cts_hmac_sha1_96(k, &data, key_usage)?;
                let enc_part = EncryptedData::Aes256CtsHmacSha196 {
                    kvno: Some(*kvno),
                    data,
                };

                let ei = EtypeInfo2 {
                    etype: EncryptionType::AES256_CTS_HMAC_SHA1_96,
                    salt: Some(s.clone()),
                    s2kparams: Some(i.to_be_bytes().to_vec()),
                };

                Ok((ei, enc_part))
            }
        }
    }

    pub(crate) fn encrypt_tgs(
        &self,
        ticket_inner: EncTicketPart,
    ) -> Result<EncryptedData, KrbError> {
        let data = TaggedEncTicketPart(ticket_inner)
            .to_der()
            .map_err(|_| KrbError::DerEncodeEncTicketPart)?;

        let key_usage = 2;

        match self {
            DerivedKey::Aes256CtsHmacSha196 {
                k,
                i: _,
                s: _,
                kvno,
            } => {
                let data = encrypt_aes256_cts_hmac_sha1_96(k, &data, key_usage)?;
                Ok(EncryptedData::Aes256CtsHmacSha196 {
                    kvno: Some(*kvno),
                    data,
                })
            }
        }
    }
}

impl fmt::Debug for DerivedKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut builder = f.debug_struct("DerivedKey");
        match self {
            DerivedKey::Aes256CtsHmacSha196 { i, s, .. } => builder
                .field("k", &"Aes256HmacSha1")
                .field("i", i)
                .field("s", s),
        }
        .finish()
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub enum SessionKey {
    Aes256CtsHmacSha196 { k: Aes256Key },
}

impl fmt::Debug for SessionKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut builder = f.debug_struct("SessionKey");
        match self {
            SessionKey::Aes256CtsHmacSha196 { .. } => builder.field("k", &"Aes256"),
        }
        .finish()
    }
}

impl TryInto<KdcEncryptionKey> for SessionKey {
    type Error = KrbError;

    fn try_into(self) -> Result<KdcEncryptionKey, KrbError> {
        match self {
            SessionKey::Aes256CtsHmacSha196 { k } => {
                let key_value =
                    OctetString::new(k.as_slice()).map_err(|_| KrbError::DerEncodeOctetString)?;

                Ok(KdcEncryptionKey {
                    key_type: EncryptionType::AES256_CTS_HMAC_SHA1_96 as i32,
                    key_value,
                })
            }
        }
    }
}

impl TryFrom<KdcEncryptionKey> for SessionKey {
    type Error = KrbError;

    fn try_from(kdc_enc_key: KdcEncryptionKey) -> Result<SessionKey, KrbError> {
        let etype: EncryptionType = EncryptionType::try_from(kdc_enc_key.key_type)
            .map_err(|_| KrbError::UnsupportedEncryption)?;

        match etype {
            EncryptionType::AES256_CTS_HMAC_SHA1_96 => {
                let mut k = Aes256Key::default();
                let byte_ref = kdc_enc_key.key_value.as_bytes();

                if byte_ref.len() != k.len() {
                    return Err(KrbError::InvalidEncryptionKey);
                }

                k.as_mut_slice().copy_from_slice(byte_ref);

                Ok(SessionKey::Aes256CtsHmacSha196 { k })
            }
            _ => Err(KrbError::UnsupportedEncryption),
        }
    }
}

impl SessionKey {
    fn new() -> Self {
        let k = aes256::new_key();
        SessionKey::Aes256CtsHmacSha196 { k }
    }

    fn decrypt_ap_req_authenticator(
        &self,
        enc_data: EncryptedData,
    ) -> Result<Authenticator, KrbError> {
        let key_usage = 7;

        let data = match (enc_data, self) {
            (
                EncryptedData::Aes256CtsHmacSha196 { kvno: _, data },
                SessionKey::Aes256CtsHmacSha196 { k },
            ) => decrypt_aes256_cts_hmac_sha1_96(k, &data, key_usage)?,
            (EncryptedData::Opaque { .. }, SessionKey::Aes256CtsHmacSha196 { .. }) => {
                return Err(KrbError::UnsupportedEncryption)
            }
        };

        Authenticator::from_der(&data).map_err(|_| KrbError::DerDecodeAuthenticator)
    }

    pub(crate) fn encrypt_tgs_rep_part(
        &self,
        enc_kdc_rep_part: Asn1EncKdcRepPart,
        is_sub_session_key: bool,
    ) -> Result<EncryptedData, KrbError> {
        let data = TaggedEncKdcRepPart::EncTgsRepPart(enc_kdc_rep_part)
            .to_der()
            .map_err(|_| KrbError::DerEncodeEncKdcRepPart)?;

        let (key_usage, kvno) = if is_sub_session_key {
            (9, Some(5))
        } else {
            (8, None)
        };

        match self {
            SessionKey::Aes256CtsHmacSha196 { k } => {
                let data = encrypt_aes256_cts_hmac_sha1_96(k, &data, key_usage)?;
                let enc_part = EncryptedData::Aes256CtsHmacSha196 { kvno, data };

                Ok(enc_part)
            }
        }
    }

    fn encrypt_ap_req_authenticator(
        &self,
        authenticator: &Authenticator,
    ) -> Result<EncryptedData, KrbError> {
        let data = authenticator
            .to_der()
            .map_err(|_| KrbError::DerEncodeAuthenticator)?;

        let key_usage = 7;
        match self {
            SessionKey::Aes256CtsHmacSha196 { k } => {
                encrypt_aes256_cts_hmac_sha1_96(k, &data, key_usage)
                    .map(|data| EncryptedData::Aes256CtsHmacSha196 { kvno: None, data })
            }
        }
    }

    pub(crate) fn checksum(&self, data: &[u8], key_usage: i32) -> Result<Vec<u8>, KrbError> {
        match self {
            SessionKey::Aes256CtsHmacSha196 { k } => {
                let checksum = checksum_hmac_sha1_96_aes256(data, k, key_usage)?;
                Ok(checksum)
            }
        }
    }
}

pub enum KdcPrimaryKey {
    Aes256 { k: Aes256Key, kvno: u32 },
}

impl fmt::Debug for KdcPrimaryKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut builder = f.debug_struct("KdcPrimaryKey");
        match self {
            KdcPrimaryKey::Aes256 { .. } => builder.field("k", &"Aes256"),
        }
        .finish()
    }
}

impl TryFrom<&[u8]> for KdcPrimaryKey {
    type Error = KrbError;

    fn try_from(key: &[u8]) -> Result<Self, Self::Error> {
        aes256::key_from_slice(key)
            .map(|k| {
                // TODO kvno from server_state
                let kvno = 1u32;
                KdcPrimaryKey::Aes256 { k, kvno }
            })
            .ok_or_else(|| {
                tracing::error!(key_len = %key.len(), expected = %aes256::key_size());
                KrbError::InvalidEncryptionKey
            })
    }
}

impl KdcPrimaryKey {
    pub(crate) fn encrypt_tgt(
        &self,
        ticket_inner: EncTicketPart,
    ) -> Result<EncryptedData, KrbError> {
        let data = TaggedEncTicketPart(ticket_inner)
            .to_der()
            .map_err(|_| KrbError::DerEncodeEncTicketPart)?;

        let key_usage = 2;

        match self {
            KdcPrimaryKey::Aes256 { k, kvno } => {
                let data = encrypt_aes256_cts_hmac_sha1_96(k, &data, key_usage)?;
                Ok(EncryptedData::Aes256CtsHmacSha196 {
                    kvno: Some(*kvno),
                    data,
                })
            }
        }
    }

    pub(crate) fn encrypt_tgs(
        &self,
        ticket_inner: EncTicketPart,
    ) -> Result<EncryptedData, KrbError> {
        let data = TaggedEncTicketPart(ticket_inner)
            .to_der()
            .map_err(|_| KrbError::DerEncodeEncTicketPart)?;

        let key_usage = 2;

        match self {
            KdcPrimaryKey::Aes256 { k, kvno } => {
                let data = encrypt_aes256_cts_hmac_sha1_96(k, &data, key_usage)?;
                Ok(EncryptedData::Aes256CtsHmacSha196 {
                    kvno: Some(*kvno),
                    data,
                })
            }
        }
    }
}

#[derive(Debug)]
pub struct Ticket {
    pub(crate) client_name: Name,
    pub(crate) auth_time: SystemTime,
    pub(crate) start_time: SystemTime,
    pub(crate) end_time: SystemTime,
    pub(crate) renew_until: Option<SystemTime>,
    pub(crate) session_key: SessionKey,
    pub(crate) flags: TicketFlags,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncTicket {
    tkt_vno: i8,
    service: Name,
    pub enc_part: EncryptedData,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum LastRequestItem {
    None(SystemTime),
    LastInitialTgt(SystemTime),
    LastInitial(SystemTime),
    TgtIssued(SystemTime),
    LastRenewal(SystemTime),
    LastRequest(SystemTime),
    PasswordExpire(SystemTime),
    AccountExpire(SystemTime),
}

impl TryFrom<KdcLastReqItem> for LastRequestItem {
    type Error = KrbError;

    fn try_from(last_req_item: KdcLastReqItem) -> Result<Self, Self::Error> {
        (&last_req_item).try_into()
    }
}

impl TryFrom<&KdcLastReqItem> for LastRequestItem {
    type Error = KrbError;

    fn try_from(last_req_item: &KdcLastReqItem) -> Result<Self, Self::Error> {
        trace!(?last_req_item);

        match last_req_item.lr_type {
            0 => Ok(LastRequestItem::None(last_req_item.lr_value.into())),
            1 => Ok(LastRequestItem::LastInitialTgt(
                last_req_item.lr_value.into(),
            )),
            2 => Ok(LastRequestItem::LastInitial(last_req_item.lr_value.into())),
            3 => Ok(LastRequestItem::TgtIssued(last_req_item.lr_value.into())),
            4 => Ok(LastRequestItem::LastRenewal(last_req_item.lr_value.into())),
            5 => Ok(LastRequestItem::LastRequest(last_req_item.lr_value.into())),
            6 => Ok(LastRequestItem::PasswordExpire(
                last_req_item.lr_value.into(),
            )),
            7 => Ok(LastRequestItem::AccountExpire(
                last_req_item.lr_value.into(),
            )),
            _ => Err(KrbError::LastRequestInvalidType),
        }
    }
}

impl TryFrom<LastRequestItem> for KdcLastReqItem {
    type Error = KrbError;
    fn try_from(value: LastRequestItem) -> Result<Self, Self::Error> {
        (&value).try_into()
    }
}

impl TryFrom<&LastRequestItem> for KdcLastReqItem {
    type Error = KrbError;

    fn try_from(value: &LastRequestItem) -> Result<Self, Self::Error> {
        let (lr_type, lr_value) = match *value {
            LastRequestItem::None(t) => (0, t),
            LastRequestItem::LastInitialTgt(t) => (1, t),
            LastRequestItem::LastInitial(t) => (2, t),
            LastRequestItem::TgtIssued(t) => (3, t),
            LastRequestItem::LastRenewal(t) => (4, t),
            LastRequestItem::LastRequest(t) => (5, t),
            LastRequestItem::PasswordExpire(t) => (6, t),
            LastRequestItem::AccountExpire(t) => (7, t),
        };

        Ok(Self {
            lr_type,
            lr_value: KerberosTime::from_system_time(lr_value).map_err(|err| {
                error!(?err, "KerberosTime::from_unix_duration");
                KrbError::DerEncodeKerberosTime
            })?,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(dead_code)]
// TODO: Remove the above dead_code!
pub struct KdcReplyPart {
    pub(crate) key: SessionKey,
    pub(crate) last_req: Vec<LastRequestItem>,
    pub(crate) nonce: i32,
    pub(crate) key_expiration: Option<SystemTime>,
    pub(crate) flags: TicketFlags,
    pub(crate) auth_time: SystemTime,
    pub(crate) start_time: Option<SystemTime>,
    pub(crate) end_time: SystemTime,
    pub(crate) renew_until: Option<SystemTime>,
    pub(crate) server: Name,
    // Shows the addresses the ticket may be used from. Mostly these are broken
    // by nat, and so aren't used. These are just to display that there are limits
    // to the client, the enforced addrs are in the ticket.
    // client_addresses: Vec<HostAddress>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EncryptedData {
    Aes256CtsHmacSha196 {
        kvno: Option<u32>,
        data: Vec<u8>,
    },
    Opaque {
        etype: i32,
        kvno: Option<u32>,
        data: Vec<u8>,
    },
}

#[derive(Debug, Default)]
pub struct PreauthData {
    // pub(crate) pa_fx_fast: bool,
    pub(crate) enc_timestamp: bool,
    pub(crate) pa_fx_cookie: Option<Vec<u8>>,
    pub(crate) etype_info2: Vec<EtypeInfo2>,
}

#[derive(Debug, Clone, PartialEq, Eq, Ord, PartialOrd, Serialize, Deserialize)]
pub enum Name {
    Principal {
        name: String,
        realm: String,
    },
    // Thanks to MIT KRB, it incorrectly sometimes uses name type 1 and 3 for
    // these two. So we have to store them as separate things, but they also need
    // to compare the same :(
    SrvPrincipal {
        service: String,
        host: String,
        realm: String,
    },
    SrvHst {
        service: String,
        host: String,
        realm: String,
    },
    SrvInst {
        service: String,
        instance: Vec<String>,
        realm: String,
    },
    /*
    Uid {
    }
    */
}

impl fmt::Display for Name {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Name::Principal { name, realm } => write!(f, "{}@{}", name, realm),

            Name::SrvPrincipal {
                service,
                host,
                realm,
            } => write!(f, "{}/{}@{}", service, host, realm),
            Name::SrvHst {
                service,
                host,
                realm,
            } => {
                write!(f, "{}/{}", service, host)?;
                if !realm.is_empty() {
                    write!(f, "@{realm}")?;
                }
                fmt::Result::Ok(())
            }
            Name::SrvInst {
                service,
                instance,
                realm,
            } => write!(f, "{}/{}@{}", service, instance.join("/"), realm),
        }
    }
}

#[derive(Debug, Clone)]
pub struct EtypeInfo2 {
    // The type of encryption for enc ts.
    etype: EncryptionType,

    salt: Option<String>,

    // For AES HMAC SHA1:
    //   The number of iterations is specified by the string-to-key parameters
    //   supplied.  The parameter string is four octets indicating an unsigned
    //   number in big-endian order.  This is the number of iterations to be
    //   performed.  If the value is 00 00 00 00, the number of iterations to
    //   be performed is 4,294,967,296 (2**32).  (Thus the minimum expressible
    //   iteration count is 1.)
    s2kparams: Option<Vec<u8>>,
}

fn sort_cryptographic_strength(a: &EtypeInfo2, b: &EtypeInfo2) -> Ordering {
    /*
    if a.etype == EncryptionType::AES256_CTS_HMAC_SHA384_192 {
        Ordering::Greater
    } else if b.etype == EncryptionType::AES256_CTS_HMAC_SHA384_192 {
        Ordering::Less
    } else if a.etype == EncryptionType::AES128_CTS_HMAC_SHA256_128 {
        Ordering::Greater
    } else if b.etype == EncryptionType::AES128_CTS_HMAC_SHA256_128 {
        Ordering::Less
    } else
    */
    if a.etype == EncryptionType::AES256_CTS_HMAC_SHA1_96 {
        Ordering::Greater
    } else if b.etype == EncryptionType::AES256_CTS_HMAC_SHA1_96 {
        Ordering::Less
    } else if a.etype == EncryptionType::AES128_CTS_HMAC_SHA1_96 {
        Ordering::Greater
    } else if b.etype == EncryptionType::AES128_CTS_HMAC_SHA1_96 {
        Ordering::Less
    } else {
        // Everything else is trash.
        Ordering::Equal
    }
}

impl TryFrom<Vec<PaData>> for PreauthData {
    type Error = KrbError;

    fn try_from(pavec: Vec<PaData>) -> Result<Self, Self::Error> {
        // Per https://www.rfc-editor.org/rfc/rfc4120#section-7.5.2
        // Build up the set of PaRep data
        // let mut pa_fx_fast = false;
        let mut enc_timestamp = false;
        let mut pa_fx_cookie = None;
        let mut etype_info2 = Vec::with_capacity(0);

        for PaData {
            padata_type,
            padata_value,
        } in pavec
        {
            let Ok(padt) = padata_type.try_into() else {
                // padatatype that we don't support
                continue;
            };

            match padt {
                PaDataType::PaEncTimestamp => enc_timestamp = true,
                PaDataType::PaEtypeInfo2 => {
                    // this is a sequence of etypeinfo2
                    let einfo2_sequence = KdcETypeInfo2::from_der(padata_value.as_bytes())
                        .map_err(|_| KrbError::DerDecodeEtypeInfo2)?;

                    for einfo2 in einfo2_sequence {
                        let Ok(etype) = EncryptionType::try_from(einfo2.etype) else {
                            // Invalid etype or we don't support it.
                            continue;
                        };

                        // Only proceed with what we support.
                        match etype {
                            EncryptionType::AES256_CTS_HMAC_SHA1_96 => {}
                            _ => continue,
                        };

                        // I think at this point we should ignore any etypes we don't support.
                        let salt = einfo2.salt.as_ref().map(String::from);
                        let s2kparams = einfo2.s2kparams.map(|v| v.as_bytes().to_vec());

                        etype_info2.push(EtypeInfo2 {
                            etype,
                            salt,
                            s2kparams,
                        });
                    }
                }
                // PaDataType::PaFxFast => pa_fx_fast = true,
                PaDataType::PaFxCookie => pa_fx_cookie = Some(padata_value.as_bytes().to_vec()),
                _ => {
                    // Ignore unsupported pa data types.
                }
            };
        }

        // Sort the etype_info by cryptographic strength.
        etype_info2.sort_unstable_by(sort_cryptographic_strength);

        Ok(PreauthData {
            // pa_fx_fast,
            pa_fx_cookie,
            enc_timestamp,
            etype_info2,
        })
    }
}

impl TryFrom<Vec<PaData>> for Preauth {
    type Error = KrbError;

    fn try_from(pavec: Vec<PaData>) -> Result<Self, Self::Error> {
        let mut preauth = Preauth::default();

        for PaData {
            padata_type,
            padata_value,
        } in pavec
        {
            let Ok(padt) = padata_type.try_into() else {
                // padatatype that we don't support
                continue;
            };

            match padt {
                PaDataType::PaTgsReq => {
                    // 5.2.7.1 - The padata_value contains an encoded AP-REQ
                    let ap_req = ApReq::from_der(padata_value.as_bytes())
                        .map_err(|_| KrbError::DerDecodePaData)?;

                    preauth.tgs_req = Some(ap_req);
                }
                PaDataType::PaEncTimestamp => {
                    let enc_timestamp = KdcEncryptedData::from_der(padata_value.as_bytes())
                        .map_err(|_| KrbError::DerDecodePaData)
                        .and_then(EncryptedData::try_from)?;
                    preauth.enc_timestamp = Some(enc_timestamp);
                }
                PaDataType::PaFxCookie => {
                    preauth.pa_fx_cookie = Some(padata_value.as_bytes().to_vec())
                }
                /*
                PaDataType::PaFxFast => {
                    let pa_fx_data = PaFxFastRequest::from_der(padata_value.as_bytes())
                        .map_err(|_| KrbError::DerDecodePaData)
                        .and_then(EncryptedData::try_from)?;
                    preauth.pa_fix_fast = Some(pa_fx_data);
                }
                */
                _ => {
                    // Ignore unsupported pa data types.
                }
            };
        }

        Ok(preauth)
    }
}

impl EncryptedData {
    fn decrypt_data(&self, base_key: &DerivedKey, key_usage: i32) -> Result<Vec<u8>, KrbError> {
        match (self, base_key) {
            (
                EncryptedData::Aes256CtsHmacSha196 { kvno: _, data },
                DerivedKey::Aes256CtsHmacSha196 { k, .. },
            ) => decrypt_aes256_cts_hmac_sha1_96(k, data, key_usage),
            (EncryptedData::Opaque { .. }, DerivedKey::Aes256CtsHmacSha196 { .. }) => {
                Err(KrbError::UnsupportedEncryption)
            }
        }
    }

    pub(crate) fn decrypt_enc_tgt(
        &self,
        primary_key: &KdcPrimaryKey,
    ) -> Result<EncTicketPart, KrbError> {
        let key_usage = 2;

        let data = match (self, primary_key) {
            (
                EncryptedData::Aes256CtsHmacSha196 { kvno: _, data },
                KdcPrimaryKey::Aes256 { k, kvno: _ },
            ) => decrypt_aes256_cts_hmac_sha1_96(k, data, key_usage)?,
            (EncryptedData::Opaque { .. }, KdcPrimaryKey::Aes256 { .. }) => {
                return Err(KrbError::UnsupportedEncryption);
            }
        };

        TaggedEncTicketPart::from_der(&data)
            .map_err(|err| {
                error!(?err, "DerDecodeEncKdcRepPart");
                KrbError::DerDecodeEncKdcRepPart
            })
            .map(|TaggedEncTicketPart(part)| part)
    }

    pub fn decrypt_enc_kdc_rep(&self, base_key: &DerivedKey) -> Result<KdcReplyPart, KrbError> {
        // RFC 4120 The key usage value for encrypting this field is 3 in an AS-REP
        // message, using the client's long-term key or another key selected
        // via pre-authentication mechanisms.
        let data = self.decrypt_data(base_key, 3)?;

        let tagged_kdc_enc_part = TaggedEncKdcRepPart::from_der(&data).map_err(|err| {
            error!(?err, "DerDecodeEncKdcRepPart");
            KrbError::DerDecodeEncKdcRepPart
        })?;

        // RFC states we should relax the tag check on these.
        let kdc_enc_part = match tagged_kdc_enc_part {
            TaggedEncKdcRepPart::EncTgsRepPart(part) | TaggedEncKdcRepPart::EncAsRepPart(part) => {
                part
            }
        };

        KdcReplyPart::try_from(kdc_enc_part)
    }

    pub fn decrypt_pa_enc_timestamp(&self, base_key: &DerivedKey) -> Result<SystemTime, KrbError> {
        // https://www.rfc-editor.org/rfc/rfc4120#section-5.2.7.2
        let data = self.decrypt_data(base_key, 1)?;

        let paenctsenc = PaEncTsEnc::from_der(&data).map_err(|_| KrbError::DerDecodePaEncTsEnc)?;

        trace!(?paenctsenc);

        let stime = paenctsenc.patimestamp.to_system_time();
        let usecs = paenctsenc
            .pausec
            .map(|s| Duration::from_micros(s as u64))
            .unwrap_or_default();

        let stime = stime + usecs;

        Ok(stime)
    }
}

impl TryFrom<KdcEncryptedData> for EncryptedData {
    type Error = KrbError;

    fn try_from(enc_data: KdcEncryptedData) -> Result<Self, Self::Error> {
        let kvno = enc_data.kvno;
        let data = enc_data.cipher.into_bytes();

        match EncryptionType::try_from(enc_data.etype) {
            Ok(etype) => match etype {
                EncryptionType::AES256_CTS_HMAC_SHA1_96 => {
                    // todo! there is some way to get a number of rounds here
                    // but I can't obviously see it?
                    Ok(EncryptedData::Aes256CtsHmacSha196 {
                        kvno,
                        data: data.to_vec(),
                    })
                }
                _ => Err(KrbError::UnsupportedEncryption),
            },
            Err(_) => Ok(EncryptedData::Opaque {
                etype: enc_data.etype,
                kvno: enc_data.kvno,
                data: data.to_vec(),
            }),
        }
    }
}

impl TryInto<KdcEncryptedData> for EncryptedData {
    type Error = KrbError;

    fn try_into(self) -> Result<KdcEncryptedData, KrbError> {
        match self {
            EncryptedData::Aes256CtsHmacSha196 { kvno, data } => Ok(KdcEncryptedData {
                etype: EncryptionType::AES256_CTS_HMAC_SHA1_96 as i32,
                kvno,
                cipher: OctetString::new(data).map_err(|e| {
                    println!("{e:#?}");
                    KrbError::UnsupportedEncryption // TODO
                })?,
            }),
            EncryptedData::Opaque { .. } => Err(KrbError::UnsupportedEncryption),
        }
    }
}

impl TryFrom<Asn1Ticket> for EncTicket {
    type Error = KrbError;

    fn try_from(tkt: Asn1Ticket) -> Result<Self, Self::Error> {
        let Asn1Ticket(tkt) = tkt;

        let service = Name::try_from((tkt.sname, tkt.realm))?;
        let enc_part = EncryptedData::try_from(tkt.enc_part)?;
        let tkt_vno = tkt.tkt_vno;

        Ok(EncTicket {
            tkt_vno,
            service,
            enc_part,
        })
    }
}

impl TryInto<Asn1Ticket> for EncTicket {
    type Error = KrbError;

    fn try_into(self) -> Result<Asn1Ticket, KrbError> {
        let t = crate::asn1::tagged_ticket::Ticket {
            tkt_vno: self.tkt_vno,
            realm: (&self.service).try_into()?,
            sname: (&self.service).try_into()?,
            enc_part: self.enc_part.try_into()?,
        };
        Ok(Asn1Ticket::new(t))
    }
}

impl Ticket {
    pub fn start_time(&self) -> SystemTime {
        self.start_time
    }

    pub fn end_time(&self) -> SystemTime {
        self.end_time
    }

    pub fn auth_time(&self) -> SystemTime {
        self.auth_time
    }

    pub fn renew_until(&self) -> Option<SystemTime> {
        self.renew_until
    }

    pub fn flags(&self) -> &TicketFlags {
        &self.flags
    }
}

impl TryFrom<Asn1EncKdcRepPart> for KdcReplyPart {
    type Error = KrbError;

    fn try_from(enc_kdc_rep_part: Asn1EncKdcRepPart) -> Result<Self, Self::Error> {
        trace!(?enc_kdc_rep_part);

        let key = SessionKey::try_from(enc_kdc_rep_part.key)?;
        let server = Name::try_from((enc_kdc_rep_part.server_name, enc_kdc_rep_part.server_realm))?;

        let last_req = enc_kdc_rep_part
            .last_req
            .iter()
            .map(|t| t.try_into())
            .collect::<Result<Vec<_>, _>>()?;
        let nonce = enc_kdc_rep_part.nonce;
        // let flags = enc_kdc_rep_part.flags.bits();
        let flags = enc_kdc_rep_part.flags;

        let key_expiration = enc_kdc_rep_part.key_expiration.map(|t| t.to_system_time());
        let start_time = enc_kdc_rep_part.start_time.map(|t| t.to_system_time());
        let renew_until = enc_kdc_rep_part.renew_till.map(|t| t.to_system_time());
        let auth_time = enc_kdc_rep_part.auth_time.to_system_time();
        let end_time = enc_kdc_rep_part.end_time.to_system_time();

        Ok(KdcReplyPart {
            key,
            last_req,
            nonce,
            key_expiration,
            flags,
            auth_time,
            start_time,
            end_time,
            renew_until,
            server,
        })
    }
}

impl Name {
    pub fn principal(name: &str, realm: &str) -> Self {
        Self::Principal {
            name: name.to_string(),
            realm: realm.to_string(),
        }
    }

    pub fn service(srvname: &str, hostname: &str, realm: &str) -> Self {
        Self::SrvPrincipal {
            service: srvname.to_string(),
            host: hostname.to_string(),
            realm: realm.to_string(),
        }
    }

    /// MIT KRB often confuses SrvHst and SrvPrincipal (name types 1 and 3). This
    /// normalises SrvHst to SrvPrincipal to assist with name matching.
    ///
    /// MS Windows uses SrvInst instead of SrvHst in TGS-REQ. This normalises
    /// SrvInst to SrvPrincipal if there is only one instance component and it
    /// looks like a DNS hostname
    pub fn service_hst_normalise(self) -> Self {
        match self {
            Self::SrvHst {
                service,
                host,
                realm,
            } => Self::SrvPrincipal {
                service,
                host,
                realm,
            },
            Self::SrvInst {
                service,
                instance,
                realm,
            } => {
                if instance.len() == 1 {
                    Self::SrvPrincipal {
                        service,
                        host: instance.first().expect("One instance").to_string(),
                        realm,
                    }
                } else {
                    Self::SrvInst {
                        service,
                        instance,
                        realm,
                    }
                }
            }
            ignore => ignore,
        }
    }

    pub fn service_krbtgt(realm: &str) -> Self {
        /*
         * RFC4120, section 7.3, Name of the TGS
         * The principal identifier of the ticket-granting service shall be
         * composed of three parts: the realm of the KDC issuing the TGS ticket,
         * and a two-part name of type NT-SRV-INST, with the first part "krbtgt"
         * and the second part the name of the realm that will accept the TGT.
         *
         * For example, a TGT issued by the ATHENA.MIT.EDU realm to be used to
         * get tickets from the ATHENA.MIT.EDU KDC has a principal identifier of
         * "ATHENA.MIT.EDU" (realm), ("krbtgt", "ATHENA.MIT.EDU") (name).
         *
         * A TGT issued by the ATHENA.MIT.EDU realm to be used to get tickets from the
         * MIT.EDU realm has a principal identifier of "ATHENA.MIT.EDU" (realm),
         * ("krbtgt", "MIT.EDU") (name).
         */
        Self::SrvInst {
            service: "krbtgt".to_string(),
            instance: vec![realm.to_string()],
            realm: realm.to_string(),
        }
    }

    #[tracing::instrument(level = "debug")]
    pub fn is_service_krbtgt(&self, check_realm: &str) -> bool {
        match self {
            // Cool bug - MIT KRB in an AS-REQ will send this with no instance, but then
            // expects an instance to be filled in. So sometimes for the krbtgt you need
            // an instance and sometimes you don't. How fun!
            Self::SrvInst {
                service,
                instance: _,
                realm,
            } => service == "krbtgt" && check_realm == realm,
            // Doesn't matter what we send this as, Heimdal fucks it up.
            Self::SrvPrincipal {
                service,
                host: _,
                realm,
            } => service == "krbtgt" && check_realm == realm,
            Self::Principal { name, realm } => name == "krbtgt" && check_realm == realm,
            _ => false,
        }
    }

    /// If the name is a PRINCIPAL then return it's name and realm compontents. If
    /// not, then an error is returned.
    pub fn principal_name(&self) -> Result<(&str, &str), KrbError> {
        trace!(principal_name = ?self);
        match self {
            Name::Principal { name, realm } => Ok((name.as_str(), realm.as_str())),
            _ => Err(KrbError::NameNotPrincipal),
        }
    }

    pub fn service_principal_name(&self) -> Result<(String, &str), KrbError> {
        trace!(principal_name = ?self);
        match self {
            Name::SrvPrincipal {
                service,
                host,
                realm,
            } => Ok((format!("{service}/{host}"), realm.as_str())),
            _ => Err(KrbError::NameNotServiceHost),
        }
    }
}

impl From<&Name> for String {
    fn from(val: &Name) -> Self {
        match val {
            Name::Principal { name, realm } => {
                format!("{name}@{realm}")
            }
            Name::SrvPrincipal {
                service,
                host,
                realm,
            } => {
                format!("{service}/{host}@{realm}")
            }
            Name::SrvInst {
                service,
                instance,
                realm,
            } => {
                format!("{service}/{}@{realm}", instance.join("/"))
            }
            Name::SrvHst {
                service,
                host,
                realm,
            } => {
                format!("{service}/{host}@{realm}")
            }
        }
    }
}

impl TryInto<Realm> for &Name {
    type Error = KrbError;

    fn try_into(self) -> Result<Realm, KrbError> {
        match self {
            Name::Principal { name: _, realm }
            | Name::SrvPrincipal {
                service: _,
                host: _,
                realm,
            }
            | Name::SrvInst {
                service: _,
                instance: _,
                realm,
            }
            | Name::SrvHst {
                service: _,
                host: _,
                realm,
            } => Ia5String::new(realm)
                .map(KerberosString)
                .map_err(|_| KrbError::DerEncodeKerberosString),
        }
    }
}

impl TryInto<PrincipalName> for &Name {
    type Error = KrbError;

    fn try_into(self) -> Result<PrincipalName, KrbError> {
        match self {
            Name::Principal { name, realm: _ } => {
                let name_string = vec![Ia5String::new(name)
                    .map(KerberosString)
                    .map_err(|_| KrbError::DerEncodeKerberosString)?];

                Ok(PrincipalName {
                    name_type: PrincipalNameType::NtPrincipal as i32,
                    name_string,
                })
            }
            Name::SrvPrincipal {
                service,
                host,
                realm: _,
            } => {
                let name_string = vec![
                    Ia5String::new(service)
                        .map(KerberosString)
                        .map_err(|_| KrbError::DerEncodeKerberosString)?,
                    Ia5String::new(host)
                        .map(KerberosString)
                        .map_err(|_| KrbError::DerEncodeKerberosString)?,
                ];

                Ok(PrincipalName {
                    name_type: PrincipalNameType::NtPrincipal as i32,
                    name_string,
                })
            }
            Name::SrvInst {
                service,
                instance,
                realm: _,
            } => {
                let mut name_string = Vec::with_capacity(instance.len() + 1);

                name_string.push(
                    Ia5String::new(service)
                        .map(KerberosString)
                        .map_err(|_| KrbError::DerEncodeKerberosString)?,
                );

                for item in instance.iter() {
                    name_string.push(
                        Ia5String::new(item)
                            .map(KerberosString)
                            .map_err(|_| KrbError::DerEncodeKerberosString)?,
                    );
                }

                Ok(PrincipalName {
                    name_type: PrincipalNameType::NtSrvInst as i32,
                    name_string,
                })
            }
            Name::SrvHst {
                service,
                host,
                realm: _,
            } => {
                let name_string = vec![
                    Ia5String::new(service)
                        .map(KerberosString)
                        .map_err(|_| KrbError::DerEncodeKerberosString)?,
                    Ia5String::new(host)
                        .map(KerberosString)
                        .map_err(|_| KrbError::DerEncodeKerberosString)?,
                ];

                Ok(PrincipalName {
                    name_type: PrincipalNameType::NtSrvHst as i32,
                    name_string,
                })
            }
        }
    }
}

impl TryInto<(PrincipalName, Realm)> for &Name {
    type Error = KrbError;

    fn try_into(self) -> Result<(PrincipalName, Realm), KrbError> {
        match self {
            Name::Principal { name, realm } => {
                let name_string = vec![Ia5String::new(name)
                    .map(KerberosString)
                    .map_err(|_| KrbError::DerEncodeKerberosString)?];

                let realm = Ia5String::new(realm)
                    .map(KerberosString)
                    .map_err(|_| KrbError::DerEncodeKerberosString)?;

                Ok((
                    PrincipalName {
                        name_type: PrincipalNameType::NtPrincipal as i32,
                        name_string,
                    },
                    realm,
                ))
            }
            Name::SrvPrincipal {
                service,
                host,
                realm,
            } => {
                let name_string = vec![
                    Ia5String::new(service)
                        .map(KerberosString)
                        .map_err(|_| KrbError::DerEncodeKerberosString)?,
                    Ia5String::new(host)
                        .map(KerberosString)
                        .map_err(|_| KrbError::DerEncodeKerberosString)?,
                ];

                let realm = Ia5String::new(realm)
                    .map(KerberosString)
                    .map_err(|_| KrbError::DerEncodeKerberosString)?;

                Ok((
                    PrincipalName {
                        name_type: PrincipalNameType::NtPrincipal as i32,
                        name_string,
                    },
                    realm,
                ))
            }
            Name::SrvInst {
                service,
                instance,
                realm,
            } => {
                let mut name_string = Vec::with_capacity(instance.len() + 1);

                name_string.push(
                    Ia5String::new(service)
                        .map(KerberosString)
                        .map_err(|_| KrbError::DerEncodeKerberosString)?,
                );

                for item in instance.iter() {
                    name_string.push(
                        Ia5String::new(item)
                            .map(KerberosString)
                            .map_err(|_| KrbError::DerEncodeKerberosString)?,
                    );
                }

                let realm = Ia5String::new(realm)
                    .map(KerberosString)
                    .map_err(|_| KrbError::DerEncodeKerberosString)?;

                Ok((
                    PrincipalName {
                        name_type: PrincipalNameType::NtSrvInst as i32,
                        name_string,
                    },
                    realm,
                ))
            }
            Name::SrvHst {
                service,
                host,
                realm,
            } => {
                let name_string = vec![
                    Ia5String::new(service)
                        .map(KerberosString)
                        .map_err(|_| KrbError::DerEncodeKerberosString)?,
                    Ia5String::new(host)
                        .map(KerberosString)
                        .map_err(|_| KrbError::DerEncodeKerberosString)?,
                ];

                let realm = Ia5String::new(realm)
                    .map(KerberosString)
                    .map_err(|_| KrbError::DerEncodeKerberosString)?;

                Ok((
                    PrincipalName {
                        name_type: PrincipalNameType::NtSrvHst as i32,
                        name_string,
                    },
                    realm,
                ))
            }
        }
    }
}

impl TryFrom<(&PrincipalName, &Realm)> for Name {
    type Error = KrbError;

    fn try_from((princ, realm): (&PrincipalName, &Realm)) -> Result<Self, Self::Error> {
        let PrincipalName {
            name_type,
            name_string,
        } = princ;

        let name_type: PrincipalNameType = (*name_type).try_into().map_err(|err| {
            error!(?err, ?name_type, "invalid principal name type");
            KrbError::PrincipalNameInvalidType
        })?;

        trace!(?name_type, ?name_string);

        // IMPORTANT!!!!!
        // MIT KRB5 has a bug in it's KVNO tool that causes it to send NtSrvHst as
        // NtPrinc instead. We need to detect this by checking how many elements are in the
        // name string and working around it!
        //
        // This is the sname from a TGS_REP sent by MIT KRB5
        // sname: Some(PrincipalName { name_type: 1, name_string: [KerberosString(Ia5String("HOST")), KerberosString(Ia5String("localhost"))] })

        match name_type {
            PrincipalNameType::NtPrincipal => {
                // MIT KRB will encode services an NtPrinc, so check the length.
                match name_string.as_slice() {
                    [name] => Ok(Name::Principal {
                        name: name.to_string(),
                        realm: realm.into(),
                    }),
                    [service, host] => Ok(Name::SrvPrincipal {
                        service: service.to_string(),
                        host: host.to_string(),
                        realm: realm.into(),
                    }),
                    _ => Err(KrbError::NameNumberOfComponents),
                }
            }
            PrincipalNameType::NtSrvInst => {
                #[allow(clippy::expect_used)]
                let (service, instance) = name_string
                    .split_first()
                    .ok_or(KrbError::NameNumberOfComponents)?;
                Ok(Name::SrvInst {
                    service: service.into(),
                    instance: instance.iter().map(|x| x.into()).collect(),
                    realm: realm.into(),
                })
            }
            PrincipalNameType::NtSrvHst => match name_string.as_slice() {
                [service, host] => Ok(Name::SrvHst {
                    service: service.to_string(),
                    host: host.to_string(),
                    realm: realm.into(),
                }),
                _ => Err(KrbError::NameNumberOfComponents),
            },
            _ => Err(KrbError::PrincipalNameInvalidType),
        }
    }
}

impl TryFrom<(PrincipalName, Realm)> for Name {
    type Error = KrbError;

    fn try_from((princ, realm): (PrincipalName, Realm)) -> Result<Self, Self::Error> {
        Self::try_from((&princ, &realm))
    }
}

impl Preauth {
    pub fn enc_timestamp(&self) -> Option<&EncryptedData> {
        self.enc_timestamp.as_ref()
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct KerberosCredentials {
    pub(crate) name: Name,
    pub(crate) ticket: EncTicket,
    pub(crate) kdc_reply: KdcReplyPart,
}

impl KerberosCredentials {
    pub fn new(name: Name, ticket: EncTicket, kdc_reply: KdcReplyPart) -> Self {
        KerberosCredentials {
            name,
            ticket,
            kdc_reply,
        }
    }

    pub fn name(&self) -> &Name {
        &self.name
    }
}

// TODO; This should probably be a test-only function or removed. Or find a way to make it a proper
// client.
#[cfg(test)]
pub async fn get_tgt(
    principal: &str,
    realm: &str,
    password: &str,
) -> Result<KerberosCredentials, KrbError> {
    use crate::KerberosTcpCodec;
    use futures::SinkExt;
    use futures::StreamExt;
    use tokio::net::TcpStream;
    use tokio_util::codec::Framed;

    let kdc_addr = option_env!("LIBKRIMES_TEST_KDC_ADDRESS").unwrap_or("127.0.0.1:55000");

    let stream = TcpStream::connect(kdc_addr)
        .await
        .expect("Unable to connect to localhost:55000");

    let mut krb_stream = Framed::new(stream, KerberosTcpCodec::default());

    let now = SystemTime::now();
    let client_name = Name::principal(principal, realm);
    let as_req = KerberosRequest::as_builder(
        &client_name,
        Name::service_krbtgt(realm),
        now + Duration::from_secs(3600),
    )
    .renew_until(Some(now + Duration::from_secs(86400 * 7)))
    .build();

    // Write a request
    krb_stream
        .send(as_req)
        .await
        .expect("Failed to transmit request");

    let response = krb_stream
        .next()
        .await
        .expect("Error reading from stream")
        .expect("No messages available in stream");

    let (name, ticket, kdc_reply): (Name, EncTicket, KdcReplyPart) = match response {
        KerberosReply::AS(AuthenticationReply {
            name,
            enc_part,
            pa_data,
            ticket,
        }) => {
            let etype_info = pa_data
                .as_ref()
                .map(|pa_inner| pa_inner.etype_info2.as_slice());

            let base_key = DerivedKey::from_encrypted_reply(
                &enc_part, etype_info, realm, principal, password, 1,
            )?;

            let kdc_reply = enc_part.decrypt_enc_kdc_rep(&base_key)?;
            (name, ticket, kdc_reply)
        }
        KerberosReply::ERR(err) => {
            panic!("{err:?}");
        }
        _ => unreachable!(),
    };

    Ok(KerberosCredentials {
        name,
        ticket,
        kdc_reply,
    })
}

#[cfg(test)]
mod tests {
    use super::SessionKey;
    use crate::asn1::ap_req::ApReqInner;
    use crate::asn1::kdc_req_body::KdcReqBody;
    use crate::proto::ApReq;
    use crate::proto::DerivedKey;
    use crate::proto::KdcPrimaryKey;
    use crate::proto::KerberosReply;
    use crate::proto::Preauth;
    use crate::proto::TicketGrantRequestUnverified;
    use crate::{cksum::ChecksumBuilder, constants::PBKDF2_SHA1_ITER_MINIMUM};
    use assert_hex::assert_eq_hex;
    use crypto_glue::aes256::{self, Aes256Key};
    use der::{asn1::Any, Decode};

    #[tokio::test]
    async fn test_ap_req_authenticator_checksum() {
        let kdc_req_body = "3072a0050303000081a20d1b0b4558414d504c452e434f4da3253023a003020103a11c301a1b04686f73741b127065707065722e6578616d706c652e636f6da511180f32303234313031313131303335395aa611180f32303234313031383130303335395aa706020436ce306ba8053003020112";
        let kdc_req_body = hex::decode(kdc_req_body).expect("Failed to decode sample");
        let kdc_req_body: Any = Any::from_der(&kdc_req_body).expect("Failed to DER decode sample");

        let session_key = "167391F64DA06DDE35752AFC110DCF6BFD797BF2B64027C98941ACDBDE3C356B";
        let session_key = hex::decode(session_key).expect("Failed to decode sample");

        let session_key =
            aes256::key_from_slice(&session_key).expect("Failed to create session key");

        let session_key = SessionKey::Aes256CtsHmacSha196 { k: session_key };
        let checksum = "E101C395D98466F1FE8B6D79";
        let checksum = hex::decode(checksum).expect("Failed to decode sample");

        let checksum_builder: ChecksumBuilder = session_key.into();
        let calculated_checksum = checksum_builder
            .compute_kdc_req_body(&kdc_req_body)
            .expect("Failed to compute checksum");
        let calculated_checksum = calculated_checksum.checksum.as_bytes();

        assert_eq_hex!(checksum, calculated_checksum);
    }

    #[test]
    fn ap_req_authenticator_cksum_sha_md5() {
        // Windows uses RSA-MD5 for the authenticator checksum...
        let ap_req = "6e8205503082054ca003020105a10302010ea20703050000000000a382049d6182049930820495a003020105a10c1b0a41464f524553542e4144a21f301da003020102a11630141b066b72627467741b0a41464f524553542e4144a382045d30820459a003020112a103020102a282044b04820447b379f2dd485edf834344017e20ddc7ecf945982d0ebc5141e81c8d0bc7f0ccba1a08f14cbbb8cc65865bcdc1a595df1e1b5627941ee0cfb089d844a62bca34c0962acbe00f14f3817192048ad70c07644434cc7172ec23fd5ca0fa5a17d35ea94496223e5e537c1477f06cc044dc991b678da7f6c2d064a3ef73073859776b1b81fa3f4e3140c87afb5b3460f9f4882d4559b996ae015ad54d52237dc9c659c84550904438e0c0ec05bc1e19b81b06cb8230b71131eed8fcc7a4955dd0625dd9b21978ecab851f71a6704178f52fecceec48137907e47d5de102764dc429099c02e7635f48d421016b3a6a37faa5f60fe41e041284885fa1d106588d87818ab397dbf6c4edc3c829bc0e1aa564caf606e0319249823ebeaa1a71872898365bdebaaa6828255b3aa8f843be36e59a24a23a2b4bad6be12d2ba039d72d521364efe6d13df4fdaa3cd6b40bcec50dfcee3503d96e61c5f0606e8052da1615aff4b3c03b1366d942751df08c0574cbb3a5643e76de07aeacacf0c4d401f2e1c510a710baa8aa7f29f7bfe2cab8a917355361892e100170acc14327bb4d4766903db725845e304156b2660c2c429e6b048dec8bd30bf549bede3a9ef121ef5366d70e0604dceda52c8976cca338076a29044c95bb53a0951d276070887dd7e05ea404d1edb44ccdf78a472baea182f1da3078c0dd718fc4c6fb347e5255af3ae49257e2b1d54839829974bc30057b4e21341116727252282d50716203cf17e6404da963560654045ab30a78574011f317f702c03b8c841ff3ffe171e9dc8b1717104a0f63c37aa923b7871e4d84733cac3845e48c8147d946b932f0f1c21ce2525ded17aed31720c626fdbffc972640160139ede6456c257c1789fc3160374017aad4c353450385be527b1f6826faa7ab2382d41232eff561fb930e9953c3cfa91722356f890302594e50aac78067c0af4c5e1c7a25b26ba14e56385bd7891f9c74a07be8d8b4644c78410c84ddda3ad1110a77038cdd999437114b85811eccf1aedd77ec62037c1ffcaf3d005530a6dcda2c222698e9637dab3beef6981476c1891e473572c5243c33f244f32e59071450203559925b94fc0a4535103f31951065bc8058669d68e39593d69e81ecc03d5a1676169732cf47cd4a5dcd087bdc64ddfb7d7d108496179c22830a3a22859b3270db5aa1180c80eceb41a81086a7683eddf9250bad56559b4fef2ef777134fbcf8c12c19467ca1048b70776296780294f23a52b08410d83179fbd243e28436f7a77b3b0ced820540fa9ca7e619c7271d33088c080e925d9402b48bf25650ab657c4583bdb9e0379c1dd5c346fc5a0e17a0e456a3a5308d71b4e7425d43117934b972c166714813bb3cfc76dc6fb46e34882b71b030a569bf17b4886ac436d006c49f17237822747143c8a13885653ea0eb2991deda997a15a0c110878e665de2fe05c32b0979e01d1df85e0d93a7e60460841d92888f9b6da2b56be8d638342e17a9d22bc1de52398c87a48798d4e18467932aead6648f81a48195308192a003020112a2818a04818779f6e43cb8d73417987b7fbddc4d35c5e9a5fe6e97d122e5356c82525fc10db4c21266335c3e7620c07ac4d4334d24f3cee81dc70e02bf0a5f94306bfbca254c9b83c4397141b4805ed7057a9150d1f71c5a5f7d57d1a9b8d576ee3a818cddb29f2ce5ebca5c27c885c67d7f481ddcef90702b6c601b17c06dc385b535e0cccf61c7724c3729c8".to_string();
        let ap_req = hex::decode(&ap_req).expect("Failed to decode hex stream");
        let ap_req: ApReqInner = ApReq::from_der(&ap_req).expect("Failed to decode").into();
        let ap_req: ApReq = ap_req.into();

        let req_body = "3081e8a00703050040810000a20c1b0a41464f524553542e4144a3273025a003020102a11e301c1b04636966731b1477696e326b32322d312e61666f726573742e6164a511180f32303337303931333032343830355aa70602042452e588a81230100201120201110201170201180202ff79aa773075a003020112a26e046caab014da39aea0046e079de6967cbe16c80ecd06d9ec7e8d00910d8c011f6771884ac73e81c8c9cdd75b2eed6d678da30e1c2fcc4222244a1d554984f44a1cfcddd8b2a39f0f9ca46cd5df1f44b7f9be51be7fd415fc270ab85523286061ea8e503bfeb5d28467eb6032be03".to_string();
        let req_body = hex::decode(&req_body).expect("Failed to decode hex stream");
        let req_body: KdcReqBody = KdcReqBody::from_der(&req_body).expect("Failed to decode");
        let req_body = Any::encode_from(&req_body).expect("Failed to decode");

        let t = TicketGrantRequestUnverified {
            preauth: Preauth {
                tgs_req: Some(ap_req),
                ..Default::default()
            },
            req_body,
        };

        let k = aes256::key_from_bytes([
            0xbd, 0xba, 0x8d, 0xaa, 0xe2, 0x43, 0xed, 0x02, 0xbb, 0xbc, 0x0a, 0x4a, 0x06, 0x73,
            0x02, 0x83, 0x9b, 0x82, 0xe7, 0x42, 0xd9, 0x41, 0x18, 0xdc, 0xbe, 0xc4, 0x2d, 0xb9,
            0x2d, 0x5c, 0x46, 0xbe,
        ]);
        let primary_key = KdcPrimaryKey::Aes256 { k, kvno: 1 };
        let realm = "AFOREST.AD";
        let res = t.validate(&primary_key, realm);
        println!("Validation result: {res:?}");
        assert!(res.is_ok());
    }

    #[test]
    fn test_derived_key() {
        use super::DerivedKey;

        let _ = tracing_subscriber::fmt::try_init();
        let _ = DerivedKey::new_aes256_cts_hmac_sha1_96(
            "a-secure-password",
            "salt",
            Some(PBKDF2_SHA1_ITER_MINIMUM),
            1,
        )
        .unwrap();
    }

    #[test]
    fn test_aad_tgt_cloud_message_buffer() {
        let as_rep = "6B82089E3082089AA003020105A10302010BA31E1B1C4B45524245524F532E4D4943524F534F46544F4E4C494E452E434F4DA42C302AA003020101A12330211B1F4164656C6556406368616E6472696F2E6F6E6D6963726F736F66742E636F6DA58206F5618206F1308206EDA003020105A11E1B1C4B45524245524F532E4D4943524F534F46544F4E4C494E452E434F4DA231302FA003020102A12830261B066B72627467741B1C4B45524245524F532E4D4943524F534F46544F4E4C494E452E434F4DA38206913082068DA0030201FFA28206840482068000007A06000001000120010000006530DCD58403D44EB011CDF42358FB4AD38784E5F55675485C82FF92A9D91CD24EA4CF2E63E71084F9091F88FB5D44B074C70C495D67704A8FF58C49E1EBC761E8EB79DCF5EEA5A91F8E17E7CB9DAFA9B536535C8C1915B9F880D9ACCFFB176D678401DB5BC82E378044AEC4AF2C64F369762AF45D9A0352A9011591ECDF809E90FB82F13185979E03CAA89E0482A2298FBDBC2463912DB27DDD5E63ACAFB7527B3C4892DF740942721DBAE6812FD08390F3FDC38A56683B977184F268F1C9B3AE8580AA39B3C268BBCF5EC68D546FBBA9DFE173A4480A2E46E6FBC6B8366D5036484B9EBC7296069789DE227EEC3C6E3251FFC751D06C67717679B26EBDDF32811590CC71343A1DE2F34829AF78812DEF97E7769A3809117B0051FF73AE015A6FD5CADB37B66621AC7DB68931809947AF5DCD10FB8C9E176772E4F3943BEE06178B1394091111A1054D2DD24446AB829A09D189D93E31554C01754C9F0BDE750132B304E29245D0F03042528120CA6FC7DA9B173D19039449F524D3E8AC9F2E46EE1A80C9F780E3AAF2B61A06840A1AD671DAEA81692953CAD8B5702E09480B4E52285DCE35BC764C5052FC055966FFEF9D78324A0BD3A326D3BF240FD5F7D86BED62CD2314778975D34643D23CA786F1D24328991F9B61BE01F2EB12740EA5DD325BF12912D38E57A27B116230A8954965D52D8F1D7626E1091BCA7236242534F8F533D49488ADF96A77D50BCC66BB5734F3EC3F251515A9DE7A6F4660ABD61F8B3858D727BB5EDF0A05A4FC2570A7AAF64BB8F4D935582CC2299FD31765B8AD06D357595E9407F8BCA43C770AC8C6BD09553C633A02B8579592146B1E4839259C06F9F87746EAE10E4E667AA3B36D2BF61F96B1A4BA8AE9E8F25254312C9FE626D7F101A094B7D5D49849066A8B29E4747D5D7C7F77C31BE7EE90F2AFA9D4683C8EDC4659945F90651BB4A72398432B6B443DAA5DDBA5252E8AFBE5F59261D676B94A6953D7B6493B67265BE2DF2DDEAFA20013EFB4D348D3CC4B3150FE7792AD834F3D834F5FC99917CB4E40B53EAA8FC90C87E4A04448E47A3B55BAAC0ADC185016A597B3A4C8A27E14F12A95E94F69A1E23A456B0BFDC5C6A6E22667C96E3C3F2A9B3406A05AADC5C83FBF2A87C16E8014540CAAE81E516ECA0907F63B7B8F0ACB810974F791414A26EBDFD9C0A698A0F5C6892D01C43748FE53B07897C59E6590A63D9BE41079AE6D29420B94F197DCC814A8C1D3B9BDE466A0DA810417B0E67D9A92DEE56F26395FCC00079A1FA3C0467088B59A93C57EAB860E4957E9C8AF0EA50BD240F1AD25DCDEFF1BC0AEA39314C70F9CE5FE409D221967D8B646406294C67DF99ECE17E92A4BF6EB8E91AC7549A185D79D017BC4F3EACBDCCECAB71DDFF532ACFF9E64C017CC92D688721E1B3953221E9461B53F3DDFE6F2D17D8AAAE54BA124A356035DDEC918E3F75A98BB46FBBA5B646920C868E6772884B0FD2F7D2F06BD9A5BE30A615F572C158CC2FDA3E77542B8FBA48FAE233D631F8C53AD6DF3F6A2BAAC5C521D598E168DF4B3ED38062C77E43BD8FAF167276F154320ADBA98EACCF10B075B6A3766676AD74A16F16749BBED9D5930951F9624BDAB56D2AD00F1E14AD281DD8BF5477B02ED1D9C1BE19EB470575A30D9D55FCECAACCFC2826BC552E156344BBA60F72393B6A98F700C3D63417E27A61EA71D7F525915995B284C0B011A1B94CA34E2115ABAD1DC9D8A0A88F0548A4B45DF7702C32F6BEB5FDE46A57A9305BEF0E487410889F943B98DE13E8711F2B75021A50018002EECF6B5720E12B79AA9DCAC4C1AFFADABA62B0562C022CE960C50996734469267708C13BA859D68DEEBAD1C2A215502063096C396354B3DD7254E7948C4658D035DFDF6D9646EA7400A82768660838EB6C4F2533654D151C7281CD679F8B268DC42D938BE837251C4E281A8ECA700F07EC200EC8BD138DD54A51C7D95FC3393AD6B7471D660515FE53967335B29469B6347DF72B2DAC2CA15F95AC103160289D5F14F6F82602DCFFF3EB43D395A14F6E3C22267243D36A54783BF098117436E904E705AC9B2FAF66A743EAE76D6B44301868603631264DCD1DE204CF0B74C925BB5D94856F2F86A780E86DC7E1F4B657FFCB5BB83C9C9926B6C90EE9CFC0F34DFDA3D5B4D7EB52320DF9420F05181CD122A98C6FC4AB25F18D30A7ADA78D55126CA555041E78A155E267CD863C91E263527D439726E2E7246F995F806AF4FCCFD116F212B0613CB98B5AAD37B256D4EB028D1F56F63CA7312793AD576283445A3AF82F4E8679FDEC7FAA50BFAB26C2000A682014530820141A003020112A282013804820134B0678D3A29C20DC1516DBAF42073E6077FB7685A47162FEF6D0F320265FF6BC412D9C38D6B06986C41ACD73D1B0E135AD00BD76D74B726E03CC06C8AA2DA3AECAAD7FB6101C639E394CA772726C672075C604A88CFDEB20156A53E5331E4862B194BF09A2FF9CA401740AF6C880E393B4744521B9B87F6A91F0CE2CFAB7F98087AD61C2B5CCE3E649A2E344CA4CFB1409C06EE5F5E096FBDF0E567A4CC128025A28B704272214AE3247BDE7D1DAB8A1B927CA2792514B39835EECC84B10AFCB46942208670E6DDD0FFA408B44F5E609347842406E1ECF11AB8827EFC3C4726516F0EA7414DEEC9860E8E194EB48E5E0DE9021B049329A32BBC046671FED42E5C6C39695B7D09F105091B05346C7DB767319EEADD8749AEA91C74DB28D39CFA8DDF4FC3D43FF7318E4209FDB5CC75A2EE2A92EE55".to_string();
        let as_rep = hex::decode(as_rep).expect("Failed to decode hex stream");
        let as_rep = KerberosReply::try_from(as_rep.as_slice()).expect("Failed to decode");
        let KerberosReply::AS(as_rep) = as_rep else {
            panic!()
        };
        // Comes as JWE in "client_key" json field
        let key = "A5381D189DAABE3FC406CF03EF514BDC20C66D6213CFF7CCCBA311EADB0362E6".to_string();
        let key = hex::decode(key).expect("Failed to decode hex stream");
        let key: Aes256Key = aes256::key_from_slice(&key).expect("Invalid key");
        let key = DerivedKey::Aes256CtsHmacSha196 {
            k: key,
            i: 0,
            s: String::new(),
            kvno: 1,
        };
        let _kdc_rep = as_rep
            .enc_part
            .decrypt_enc_kdc_rep(&key)
            .expect("Failed to decrypt");
    }
}
