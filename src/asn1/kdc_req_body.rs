use super::encrypted_data::EncryptedData;
use super::host_addresses::HostAddresses;
use super::kdc_options::KdcOptions;
use super::kerberos_time::KerberosTime;
use super::principal_name::PrincipalName;
use super::realm::Realm;
use super::tagged_ticket::TaggedTicket;
use der::{asn1::BitString, Sequence};

/// ```text
/// KDC-REQ-BODY    ::= SEQUENCE {
///         kdc-options             [0] KDCOptions,
///         cname                   [1] PrincipalName OPTIONAL
///                                     -- Used only in AS-REQ --,
///         realm                   [2] Realm
///                                     -- Server's realm
///                                     -- Also client's in AS-REQ --,
///         sname                   [3] PrincipalName OPTIONAL,
///         from                    [4] KerberosTime OPTIONAL,
///         till                    [5] KerberosTime,
///         rtime                   [6] KerberosTime OPTIONAL,
///         nonce                   [7] UInt32,
///         etype                   [8] SEQUENCE OF Int32 -- EncryptionType
///                                     -- in preference order --,
///         addresses               [9] HostAddresses OPTIONAL,
///         enc-authorization-data  [10] EncryptedData OPTIONAL
///                                     -- AuthorizationData --,
///         additional-tickets      [11] SEQUENCE OF Ticket OPTIONAL
///                                         -- NOTE: not empty
/// }
/// ```
#[derive(Debug, Eq, PartialEq, Sequence)]
pub(crate) struct KdcReqBody {
    //
    // #[asn1(context_specific = "0")]
    // pub(crate) kdc_options: KdcOptions,

    // I'm not sure what's going on but it looks like this KdcOptions type
    // isn't correctly writing a full u32 (it's truncated to u8) and when the flags
    // are set they have bits swapped. :(
    #[asn1(context_specific = "0")]
    pub(crate) kdc_options: BitString,

    #[asn1(context_specific = "1", optional = "true")]
    pub(crate) cname: Option<PrincipalName>,
    #[asn1(context_specific = "2")]
    pub(crate) realm: Realm,
    #[asn1(context_specific = "3", optional = "true")]
    pub(crate) sname: Option<PrincipalName>,
    #[asn1(context_specific = "4", optional = "true")]
    pub(crate) from: Option<KerberosTime>,
    #[asn1(context_specific = "5")]
    pub(crate) till: KerberosTime,
    #[asn1(context_specific = "6", optional = "true")]
    pub(crate) rtime: Option<KerberosTime>,
    #[asn1(context_specific = "7")]
    pub(crate) nonce: u32,
    #[asn1(context_specific = "8")]
    pub(crate) etype: Vec<i32>,
    #[asn1(context_specific = "9", optional = "true")]
    pub(crate) addresses: Option<HostAddresses>,
    #[asn1(context_specific = "10", optional = "true")]
    pub(crate) enc_authorization_data: Option<EncryptedData>,
    #[asn1(context_specific = "11", optional = "true")]
    pub(crate) additional_tickets: Option<Vec<TaggedTicket>>,
}
