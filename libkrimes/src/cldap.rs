use bitflags::bitflags;
use bytes::BytesMut;
use crypto_glue::rand::{self, prelude::*};
use futures_util::sink::SinkExt;
use ldap3_proto::proto::LdapOp;
use ldap3_proto::simple::DisconnectionNotice;
use ldap3_proto::simple::ServerOps;
use ldap3_proto::LdapCodec;
use ldap3_proto::LdapFilter;
use ldap3_proto::LdapMsg;
use ldap3_proto::LdapPartialAttribute;
use ldap3_proto::LdapResultCode;
use ldap3_proto::LdapSearchResultEntry;
use ldap3_proto::LdapSearchScope;
use ldap3_proto::SearchRequest;
use serde::ser::Serializer;
use serde::Deserialize;
use serde_binary::Encode;
use std::ffi::{CStr, OsString};
use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::net::SocketAddr;
use std::os::unix::ffi::OsStringExt;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio_util::codec::BytesCodec;
use tokio_util::codec::Decoder;
use tokio_util::codec::Encoder;
use tokio_util::udp::UdpFramed;
use tracing::{debug, error, trace, warn};
use uuid::Uuid;

#[derive(Debug)]
pub enum CldapConfigError {
    DnsHostNameNotDefined,
    DnsDomainNameNotDefined,
}

pub struct CldapConfig {
    address: String,
    netbios_server_name: Option<String>,
    netbios_domain_name: Option<String>,
    domain_sid: String,
    domain_guid: Uuid,
    dns_domain_name: String,
    dns_forest_name: String,
    dns_host_name: String,
}

#[derive(Debug, Default, Clone, Deserialize)]
pub struct CldapConfigBuilder {
    address: String,

    hostname_from_system: Option<bool>,
    domain_from_system: Option<bool>,

    netbios_server_name: Option<String>,
    netbios_domain_name: Option<String>,
    domain_sid: Option<String>,
    domain_guid: Option<Uuid>,
    dns_domain_name: Option<String>,
    dns_host_name: Option<String>,
}

impl CldapConfig {
    pub fn builder() -> CldapConfigBuilder {
        CldapConfigBuilder::default()
    }
    pub fn address(&self) -> &str {
        self.address.as_str()
    }
}

impl CldapConfigBuilder {
    pub fn hostname_from_system(mut self, allow: bool) -> Self {
        self.hostname_from_system = Some(allow);
        self
    }

    pub fn domainname_from_system(mut self, allow: bool) -> Self {
        self.domain_from_system = Some(allow);
        self
    }

    pub fn random_sid(&self) -> String {
        let mut rng = rand::rng();
        let d1 = rng.random::<u32>();
        let d2 = rng.random::<u32>();
        let d3 = rng.random::<u32>();
        format!("S-1-5-21-{d1}-{d2}-{d3}")
    }

    fn get_hostname(&self) -> Result<String, CldapConfigError> {
        let mut buf: Vec<u8> = Vec::with_capacity(256);
        let ptr = buf.as_mut_ptr().cast();
        let len = buf.capacity() as libc::size_t;

        let res = unsafe { libc::gethostname(ptr, len) };
        if res == -1 {
            let res = errno::errno();
            let code = res.0;
            error!("Failed to get host name from system: {code} ({res})");
            return Err(CldapConfigError::DnsHostNameNotDefined);
        }

        unsafe {
            buf.as_mut_ptr().wrapping_add(len - 1).write(0);
            let len = CStr::from_ptr(buf.as_ptr().cast()).count_bytes();
            buf.set_len(len);
        }

        let host_name = OsString::from_vec(buf);
        let host_name = host_name.into_string().map_err(|e| {
            error!("Failed to get host name from string {e:?}");
            CldapConfigError::DnsHostNameNotDefined
        })?;

        trace!(?host_name);

        Ok(host_name)
    }

    fn get_domainname(&self) -> Result<Option<String>, CldapConfigError> {
        let mut buf: Vec<u8> = Vec::with_capacity(256);
        let ptr = buf.as_mut_ptr().cast();
        let len = buf.capacity();

        #[cfg(target_os = "macos")]
        let res = unsafe { libc::getdomainname(ptr, len as libc::c_int) };
        #[cfg(target_os = "linux")]
        let res = unsafe { libc::getdomainname(ptr, len as libc::size_t) };

        if res == -1 {
            let res = errno::errno();
            let code = res.0;
            error!("Failed to get domain name: {code} ({res})");
            return Err(CldapConfigError::DnsDomainNameNotDefined);
        }

        unsafe {
            buf.as_mut_ptr().wrapping_add(len - 1).write(0);
            let len = CStr::from_ptr(buf.as_ptr().cast()).count_bytes();
            buf.set_len(len);
        }

        if buf.is_empty() {
            return Ok(None);
        }

        let domain_name = OsString::from_vec(buf);
        let domain_name = domain_name.into_string().map_err(|e| {
            error!("Failed to get domain name from string {e:?}");
            CldapConfigError::DnsDomainNameNotDefined
        })?;
        trace!(?domain_name);

        if domain_name.to_lowercase() == "(none)" {
            return Ok(None);
        }

        Ok(Some(domain_name))
    }

    pub fn build(&self) -> Result<CldapConfig, CldapConfigError> {
        let dns_domain_name = match &self.dns_domain_name {
            Some(name) => Ok(name.clone()),
            None => {
                if self.domain_from_system.is_some_and(|x| x) {
                    self.get_domainname()?
                        .ok_or(CldapConfigError::DnsDomainNameNotDefined)
                } else {
                    Err(CldapConfigError::DnsDomainNameNotDefined)
                }
            }
        }?;

        let dns_host_name = match &self.dns_host_name {
            Some(dns_host_name) => Ok(dns_host_name.clone()),
            None => {
                if self.hostname_from_system.is_some_and(|x| x) {
                    let hostname = self.get_hostname()?;
                    Ok(format!("{hostname}.{dns_domain_name}"))
                } else {
                    Err(CldapConfigError::DnsHostNameNotDefined)
                }
            }
        }?;

        let domain_sid = match &self.domain_sid {
            Some(sid) => sid.clone(),
            None => self.random_sid(),
        };

        Ok(CldapConfig {
            address: self.address.clone(),
            netbios_server_name: self.netbios_server_name.clone(),
            netbios_domain_name: self.netbios_domain_name.clone(),
            domain_sid,
            domain_guid: self.domain_guid.unwrap_or(Uuid::new_v4()),
            dns_domain_name: dns_domain_name.clone(),
            dns_forest_name: dns_domain_name,
            dns_host_name,
        })
    }
}

/// Operation code set in the request and response of an LDAP ping
#[allow(dead_code)]
#[derive(Debug)]
enum OperationCode {
    PrimaryQuery,
    PrimaryResponse,
    SamLogonRequest,
    SamLogonResponse,
    SamPauseResponse,
    SamUserUnknown,
    SamLogonResponseEx,
    SamLogonPauseResponseEx,
    SamUserUnknownEx,
}

impl OperationCode {
    fn value(&self) -> u16 {
        match *self {
            Self::PrimaryQuery => 7,
            Self::PrimaryResponse => 12,
            Self::SamLogonRequest => 18,
            Self::SamLogonResponse => 19,
            Self::SamPauseResponse => 20,
            Self::SamUserUnknown => 21,
            Self::SamLogonResponseEx => 23,
            Self::SamLogonPauseResponseEx => 24,
            Self::SamUserUnknownEx => 25,
        }
    }
}

bitflags! {
    #[derive(Debug, Clone, Default)]
    struct DsFlags: u32 {
        /// Server holds the PDC FSMO role
        const DS_PDC = 1 << 0;
        /// Server is a Global Catalog server
        const DS_GC = 1 << 2;
        /// Server is an LDAP server
        const DS_LDAP = 1 << 3;
        /// Server is a Domain Controller
        const DS_DS = 1 << 4;
        /// Server is a Kerberos server
        const DS_KDC = 1 << 5;
        /// Server runs Win32 Time Service
        const DS_TIMESERV = 1 << 6;
        /// Server is on the same site as the client
        const DS_CLOSEST = 1 << 7;
        /// Server is not a Read-Only Domain Controller
        const DS_WRITABLE = 1 << 8;
        /// Server is a reliable time server
        const DS_GOOD_TIMESERV = 1 << 9;
        // The Naming Context is an Application Naming Context
        const DS_NDNC = 1 << 10;
        // The server is a Read-Only domain controller
        const DS_SELECT_SECRET_DOMAIN_6 = 1 << 11;
        // The server is a Rear-Write domain controller running Windows Server >= 2008
        const DS_FULL_SECRET_DOMAIN_6 = 1 << 12;
        // The server runs Active Directory Web services
        const DS_WS_FLAG = 1 << 13;
        // The server is Windows Server >= 2012
        const DS_DS_8 = 1 << 14;
        // The server is Windows Server >= 2012R2
        const DS_DS_9 = 1 << 15;
        // The server is Windows Server >= 2016
        const DS_DS_10 = 1 << 16;
        // The server has a DNS name
        const DS_DNS_CONTROLLER = 1 << 29;
        // The Naming Context is a default Naming Context
        const DS_DNS_DOMAIN = 1 << 30;
        // The Naming Context is the forest root
        const DS_DNS_FOREST = 1 << 31;
    }
}

bitflags! {
    #[derive(Debug, Clone)]
    struct NetLogonNtVersion: u32 {
        const NT_VERSION_1 = 1 << 0;
        const NT_VERSION_5 = 1 << 1;
        const NT_VERSION_5EX = 1 << 2;
        const NT_VERSION_5EX_WITH_IP = 1 << 3;
        const NT_VERSION_WITH_CLOSEST_SITE = 1 << 4;
        const NT_VERSION_AVOID_NT4EMUL = 1 << 24;
        const NT_VERSION_PDC = 1 << 28;
        const NT_VERSION_IP = 1 << 29;
        const NT_VERSION_LOCAL = 1 << 30;
        const NT_VERSION_GC = 1 << 31;
    }
}

fn serialize_domain_name(
    name: &Option<String>,
    ser: &mut serde_binary::Serializer,
) -> serde_binary::Result<()> {
    if let Some(name) = name {
        for label in name.split('.') {
            ser.serialize_u8(label.len() as u8)?;
            ser.serialize_bytes(label.as_bytes())?;
        }
    }
    ser.serialize_u8(0x00)?;
    Ok(())
}

fn serialize_dc_sock_addr(
    addr: &IpAddr,
    ser: &mut serde_binary::Serializer,
) -> serde_binary::Result<()> {
    ser.serialize_u8(16u8)?;
    ser.serialize_u16(c_types::AF_INET as u16)?;
    ser.serialize_u16(0u16)?;
    match addr {
        IpAddr::V4(ip) => ser.serialize_u32(ip.to_bits()),
        _ => {
            let ip = Ipv4Addr::new(127, 0, 0, 1);
            ser.serialize_bytes(&ip.octets())
        }
    }?;
    ser.serialize_u64(0u64)?;
    Ok(())
}

fn serialize_unicode_name(
    name: &Option<String>,
    ser: &mut serde_binary::Serializer,
) -> serde_binary::Result<()> {
    if let Some(name) = name {
        for c in name.encode_utf16() {
            ser.serialize_u16(c)?;
        }
    }
    ser.serialize_u8(0)?;
    Ok(())
}

#[derive(Debug)]
struct NetLogonSamLogonResponse {
    opcode: OperationCode,
    unicode_logon_server: Option<String>,
    unicode_user_name: Option<String>,
    unicode_domain_name: Option<String>,
    domain_guid: Uuid,
    null_guid: Uuid,
    dns_forest_name: Option<String>,
    dns_domain_name: Option<String>,
    dns_host_name: Option<String>,
    dc_ip_address: Option<IpAddr>,
    flags: DsFlags,
    nt_version: NetLogonNtVersion,
    lmnt_token: u16,
    lm20_token: u16,
}

impl Encode for NetLogonSamLogonResponse {
    fn encode(&self, ser: &mut serde_binary::Serializer) -> serde_binary::Result<()> {
        ser.serialize_u16(self.opcode.value())?;
        serialize_unicode_name(&self.unicode_logon_server, ser)?;
        serialize_unicode_name(&self.unicode_user_name, ser)?;
        serialize_unicode_name(&self.unicode_domain_name, ser)?;
        ser.serialize_bytes(&self.domain_guid.to_bytes_le())?;
        ser.serialize_bytes(&self.null_guid.to_bytes_le())?;
        serialize_domain_name(&self.dns_forest_name, ser)?;
        serialize_domain_name(&self.dns_domain_name, ser)?;
        serialize_domain_name(&self.dns_host_name, ser)?;

        let ip_addr_bytes = match self
            .dc_ip_address
            .unwrap_or(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)))
        {
            IpAddr::V6(_) => [127, 0, 0, 1],
            IpAddr::V4(v4) => v4.octets(),
        };
        ser.serialize_bytes(&ip_addr_bytes)?;

        ser.serialize_u32(self.flags.bits())?;
        ser.serialize_u32(self.nt_version.bits())?;
        ser.serialize_u16(self.lmnt_token)?;
        ser.serialize_u16(self.lm20_token)?;
        Ok(())
    }
}

#[derive(Debug)]
struct NetLogonSamLogonResponseNT40 {
    opcode: OperationCode,
    unicode_logon_server: Option<String>,
    unicode_user_name: Option<String>,
    unicode_domain_name: Option<String>,
    nt_version: NetLogonNtVersion,
    lmnt_token: u16,
    lm20_token: u16,
}

impl Encode for NetLogonSamLogonResponseNT40 {
    fn encode(&self, ser: &mut serde_binary::Serializer) -> serde_binary::Result<()> {
        ser.serialize_u16(self.opcode.value())?;
        serialize_unicode_name(&self.unicode_logon_server, ser)?;
        serialize_unicode_name(&self.unicode_user_name, ser)?;
        serialize_unicode_name(&self.unicode_domain_name, ser)?;
        ser.serialize_u32(self.nt_version.bits())?;
        ser.serialize_u16(self.lmnt_token)?;
        ser.serialize_u16(self.lm20_token)?;
        Ok(())
    }
}

#[derive(Debug)]
struct NetLogonSamLogonResponseEx {
    opcode: OperationCode,
    sbz: u16,
    flags: DsFlags,
    domain_guid: Uuid,
    dns_forest_name: Option<String>,
    dns_domain_name: Option<String>,
    dns_host_name: Option<String>,
    netbios_domain_name: Option<String>,
    netbios_server_name: Option<String>,
    user_name: Option<String>,
    dc_site_name: Option<String>,
    client_site_name: Option<String>,
    dc_sock_addr: Option<IpAddr>,
    next_closest_site_name: Option<String>,
    nt_version: NetLogonNtVersion,
    lmnt_token: u16,
    lm20_token: u16,
}

impl Encode for NetLogonSamLogonResponseEx {
    fn encode(&self, ser: &mut serde_binary::Serializer) -> serde_binary::Result<()> {
        ser.serialize_u16(self.opcode.value())?;
        ser.serialize_u16(self.sbz)?;
        ser.serialize_u32(self.flags.bits())?;
        ser.serialize_bytes(&self.domain_guid.to_bytes_le())?;

        serialize_domain_name(&self.dns_forest_name, ser)?;
        serialize_domain_name(&self.dns_domain_name, ser)?;
        serialize_domain_name(&self.dns_host_name, ser)?;
        serialize_domain_name(&self.netbios_domain_name, ser)?;
        serialize_domain_name(&self.netbios_server_name, ser)?;
        serialize_domain_name(&self.user_name, ser)?;
        serialize_domain_name(&self.dc_site_name, ser)?;
        serialize_domain_name(&self.client_site_name, ser)?;

        // Only included if client requested
        if let Some(addr) = self.dc_sock_addr {
            serialize_dc_sock_addr(&addr, ser)?;
        }

        // Only included if client requested
        if self.next_closest_site_name.is_some() {
            serialize_domain_name(&self.next_closest_site_name, ser)?;
        }

        ser.serialize_u32(self.nt_version.bits())?;
        ser.serialize_u16(self.lmnt_token)?;
        ser.serialize_u16(self.lm20_token)?;
        Ok(())
    }
}

#[derive(Debug)]
enum LdapPingResponse {
    V5Ex(NetLogonSamLogonResponseEx),
    V5(NetLogonSamLogonResponse),
    NT40(NetLogonSamLogonResponseNT40),
}

impl Encode for LdapPingResponse {
    fn encode(&self, ser: &mut serde_binary::Serializer) -> serde_binary::Result<()> {
        match self {
            Self::V5Ex(v5ex) => v5ex.encode(ser),
            Self::V5(v5) => v5.encode(ser),
            Self::NT40(nt4) => nt4.encode(ser),
        }
    }
}

#[derive(Debug)]
enum LdapResponseState {
    Unbind,
    Disconnect(LdapMsg),
    Respond(LdapMsg),
    MultiPartResponse(Vec<LdapMsg>),
}

#[derive(Debug, Default)]
#[allow(dead_code)]
struct LdapPingFilter {
    dns_domain: Option<String>,
    host: Option<String>,
    dns_host_name: Option<String>,
    user: Option<String>,
    aac: Option<String>,
    domain_sid: Option<String>,
    domain_guid: Option<Uuid>,
    nt_ver: Option<NetLogonNtVersion>,
}

fn parse_cldap_ping_filter(f: &LdapFilter, r: &mut LdapPingFilter) -> Result<(), ()> {
    // If any of the elements is specified more than once, the filter is invalid
    match f {
        LdapFilter::And(v) => {
            for i in v {
                parse_cldap_ping_filter(i, r)?;
            }
            Ok(())
        }
        LdapFilter::Equality(k, v) => match k.to_lowercase().as_str() {
            "dnsdomain" => match r.dns_domain {
                Some(_) => Err(()),
                None => {
                    r.dns_domain = Some(v.clone());
                    Ok(())
                }
            },
            "host" => match r.host {
                Some(_) => Err(()),
                None => {
                    r.host = Some(v.clone());
                    Ok(())
                }
            },
            "dnshostname" => match r.dns_host_name {
                Some(_) => Err(()),
                None => {
                    r.dns_host_name = Some(v.clone());
                    Ok(())
                }
            },
            "user" => match r.user {
                Some(_) => Err(()),
                None => {
                    r.user = Some(v.clone());
                    Ok(())
                }
            },
            "aac" => match r.aac {
                Some(_) => Err(()),
                None => {
                    let _bits: u32 = v.parse().map_err(|_| ())?;
                    // TODO Validate and validate bit set
                    r.aac = Some(v.clone());
                    Ok(())
                }
            },
            "domainsid" => match r.domain_sid {
                Some(_) => Err(()),
                None => {
                    r.domain_sid = Some(v.clone());
                    Ok(())
                }
            },
            "domainguid" => match r.domain_guid {
                Some(_) => Err(()),
                None => {
                    let bytes: [u8; 16] = v.as_bytes().try_into().map_err(|_| ())?;
                    let uuid: Uuid = Uuid::from_bytes_le(bytes);
                    r.domain_guid = Some(uuid);
                    Ok(())
                }
            },
            "ntver" => match r.nt_ver {
                Some(_) => Err(()),
                None => {
                    let bytes: [u8; 4] = v.as_bytes().try_into().map_err(|e| error!("{:?}", e))?;
                    let bits: u32 = u32::from_le_bytes(bytes);
                    if let Some(flags) = NetLogonNtVersion::from_bits(bits) {
                        r.nt_ver = Some(flags);
                        Ok(())
                    } else {
                        error!("Failed to build LdapPingFlags from bits {:?}", bits);
                        Err(())
                    }
                }
            },
            _ => Err(()),
        },
        _ => Err(()),
    }
}

fn gen_invalid_filter(sr: &SearchRequest) -> LdapResponseState {
    let empty = LdapSearchResultEntry {
        dn: String::new(),
        attributes: vec![],
    };
    let res = vec![
        LdapMsg {
            msgid: sr.msgid,
            op: LdapOp::SearchResultEntry(empty),
            ctrl: vec![],
        },
        sr.gen_success(),
    ];
    LdapResponseState::MultiPartResponse(res)
}

fn do_cldap_ping_internal(
    cfg: &CldapConfig,
    filter: &LdapPingFilter,
) -> Result<LdapPingResponse, ()> {
    if let Some(f_domain_guid) = &filter.domain_guid {
        if f_domain_guid != &cfg.domain_guid {
            debug!(
                "Filter domain GUID {:?} does not match the configured one {:?}",
                filter.domain_guid, cfg.domain_guid
            );
            return Err(());
        }
    }

    if let Some(f_domain_sid) = &filter.domain_sid {
        if f_domain_sid.to_lowercase() != cfg.domain_sid.to_lowercase() {
            debug!(
                "Filter domain SID {:?} does not match the configured one {:?}",
                f_domain_sid, cfg.domain_sid
            );
            return Err(());
        }
    }

    if let Some(f_domain_name) = &filter.dns_domain {
        if f_domain_name.to_lowercase() != cfg.dns_domain_name.to_lowercase() {
            debug!(
                "Filter domain {:?} does not match the configured one {:?}",
                filter.dns_domain, cfg.dns_domain_name
            );
            return Err(());
        }
    }

    if let Some(aac) = &filter.aac {
        // TODO
        warn!("Client set Account Access Control {aac:?} in CLDAP filter, will be ignored",);
    }

    if let Some(user) = &filter.user {
        // TODO Search the user by uid
        // TODO Check user account control (uac) and filter.aac
        warn!("Client set user account {user:?} in CLDAP filter, will be ignored",);
    }

    let req_nt_ver = filter
        .nt_ver
        .as_ref()
        .unwrap_or(&NetLogonNtVersion::NT_VERSION_5);

    let netbios_server_name = cfg.netbios_server_name.clone();
    let netbios_domain_name = cfg.netbios_domain_name.clone();
    let domain_guid = cfg.domain_guid;

    let dns_forest_name = Some(cfg.dns_forest_name.clone());
    let dns_domain_name = Some(cfg.dns_domain_name.clone());
    let dns_host_name = Some(cfg.dns_host_name.clone());

    let dc_ip_address = if req_nt_ver.contains(NetLogonNtVersion::NT_VERSION_5EX_WITH_IP) {
        warn!(
            "Client set {:?}, will be ignored",
            NetLogonNtVersion::NT_VERSION_5EX_WITH_IP
        );
        None
    } else {
        None
    };

    let dc_site_name = Some("milky-way".to_string());
    let client_site_name = Some("milky-way".to_string());
    let next_closest_site_name =
        if req_nt_ver.contains(NetLogonNtVersion::NT_VERSION_WITH_CLOSEST_SITE) {
            Some("andromeda".to_string())
        } else {
            None
        };

    let config_repond_as_nt40 = false;
    let response: LdapPingResponse = if config_repond_as_nt40
        && !req_nt_ver.contains(NetLogonNtVersion::NT_VERSION_AVOID_NT4EMUL)
    {
        let nt4 = NetLogonSamLogonResponseNT40 {
            opcode: if filter.user.is_some() {
                // The LDAP ping can be abused to verify if a user account exists in the server. If
                // the filter contains a user name always answer user unknown.
                OperationCode::SamUserUnknown
            } else {
                OperationCode::SamLogonResponse
            },
            unicode_logon_server: netbios_server_name,
            unicode_user_name: filter.user.clone(),
            unicode_domain_name: netbios_domain_name,
            nt_version: NetLogonNtVersion::NT_VERSION_1,
            lmnt_token: 0xFFFF,
            lm20_token: 0xFFFF,
        };
        LdapPingResponse::NT40(nt4)
    } else if req_nt_ver.contains(NetLogonNtVersion::NT_VERSION_5EX)
        || req_nt_ver.contains(NetLogonNtVersion::NT_VERSION_5EX_WITH_IP)
    {
        let mut v5ex = NetLogonSamLogonResponseEx {
            opcode: if filter.user.is_some() {
                // The LDAP ping can be abused to verify if a user account exists in the server. If
                // the filter contains a user name always answer user unknown.
                OperationCode::SamUserUnknownEx
            } else {
                OperationCode::SamLogonResponseEx
            },
            sbz: 0,
            flags: DsFlags::DS_KDC,
            domain_guid,
            dns_forest_name,
            dns_domain_name,
            dns_host_name,
            netbios_domain_name,
            netbios_server_name,
            user_name: filter.user.clone(),
            dc_site_name,
            client_site_name,
            dc_sock_addr: dc_ip_address,
            next_closest_site_name,
            nt_version: NetLogonNtVersion::NT_VERSION_1 | NetLogonNtVersion::NT_VERSION_5EX,
            lmnt_token: 0xFFFF,
            lm20_token: 0xFFFF,
        };
        if req_nt_ver.contains(NetLogonNtVersion::NT_VERSION_WITH_CLOSEST_SITE) {
            v5ex.nt_version |= NetLogonNtVersion::NT_VERSION_WITH_CLOSEST_SITE;
        }
        if req_nt_ver.contains(NetLogonNtVersion::NT_VERSION_5EX_WITH_IP) {
            v5ex.nt_version |= NetLogonNtVersion::NT_VERSION_5EX_WITH_IP;
        }
        LdapPingResponse::V5Ex(v5ex)
    } else if req_nt_ver.contains(NetLogonNtVersion::NT_VERSION_5) {
        let v5 = NetLogonSamLogonResponse {
            opcode: if filter.user.is_some() {
                // The LDAP ping can be abused to verify if a user account exists in the server. If
                // the filter contains a user name always answer user unknown.
                OperationCode::SamUserUnknown
            } else {
                OperationCode::SamLogonResponse
            },
            unicode_logon_server: netbios_server_name,
            unicode_user_name: filter.user.clone(),
            unicode_domain_name: netbios_domain_name,
            domain_guid,
            null_guid: Uuid::nil(),
            dns_forest_name,
            dns_domain_name,
            dns_host_name,
            dc_ip_address,
            flags: DsFlags::DS_DS,
            nt_version: NetLogonNtVersion::NT_VERSION_1 | NetLogonNtVersion::NT_VERSION_5,
            lmnt_token: 0xFFFF,
            lm20_token: 0xFFFF,
        };
        LdapPingResponse::V5(v5)
    } else {
        let nt4 = NetLogonSamLogonResponseNT40 {
            opcode: if filter.user.is_some() {
                // The LDAP ping can be abused to verify if a user account exists in the server. If
                // the filter contains a user name always answer user unknown.
                OperationCode::SamUserUnknown
            } else {
                OperationCode::SamLogonResponse
            },
            unicode_logon_server: netbios_server_name,
            unicode_user_name: filter.user.clone(),
            unicode_domain_name: netbios_domain_name,
            nt_version: NetLogonNtVersion::NT_VERSION_1,
            lmnt_token: 0xFFFF,
            lm20_token: 0xFFFF,
        };
        LdapPingResponse::NT40(nt4)
    };

    Ok(response)
}

async fn do_cldap_ping(cfg: &CldapConfig, sr: &SearchRequest) -> LdapResponseState {
    // First step is filter validation [MS-ADTS] section 6.3.3.1
    debug!("Parsing LDAP Ping filter: {:?}", sr.filter);
    let mut filter = LdapPingFilter::default();
    if parse_cldap_ping_filter(&sr.filter, &mut filter).is_err() {
        return gen_invalid_filter(sr);
    }
    debug!("LDAP Ping filter: {:?}", filter);

    let Ok(response) = do_cldap_ping_internal(cfg, &filter) else {
        return gen_invalid_filter(sr);
    };
    debug!("LDAP Ping response: {:?}", response);

    let Ok(v) = serde_binary::encode(&response, serde_binary::binary_stream::Endian::Little) else {
        return gen_invalid_filter(sr);
    };

    let attr: LdapPartialAttribute = LdapPartialAttribute {
        atype: "NetLogon".to_string(),
        vals: vec![v],
    };

    let entry = LdapSearchResultEntry {
        dn: String::new(),
        attributes: vec![attr],
    };

    let res = vec![
        LdapMsg {
            msgid: sr.msgid,
            op: LdapOp::SearchResultEntry(entry),
            ctrl: vec![],
        },
        sr.gen_success(),
    ];

    LdapResponseState::MultiPartResponse(res)
}

async fn do_cldap(
    cfg: &CldapConfig,
    server_op: ServerOps,
) -> Result<LdapResponseState, LdapResultCode> {
    match server_op {
        ServerOps::SimpleBind(sbr) => Ok(LdapResponseState::Respond(sbr.gen_error(
            LdapResultCode::UnwillingToPerform,
            "Unwilling to perform".to_string(),
        ))),
        ServerOps::Unbind(_) => Ok(LdapResponseState::Unbind),
        ServerOps::Compare(cr) => Ok(LdapResponseState::Respond(cr.gen_error(
            LdapResultCode::UnwillingToPerform,
            "Unwilling to perform".to_string(),
        ))),
        ServerOps::Whoami(wr) => Ok(LdapResponseState::Respond(
            wr.gen_operror("Unwilling to perform"),
        )),
        ServerOps::Search(sr) => {
            if sr.base.is_empty() && sr.scope == LdapSearchScope::Base {
                let req_attrs: Vec<String> = sr.attrs.iter().map(|a| a.to_lowercase()).collect();

                let netlogon = "netlogon".to_string();
                if req_attrs.len() == 1 && req_attrs.contains(&netlogon) {
                    return Ok(do_cldap_ping(cfg, &sr).await);
                }
            }

            Ok(LdapResponseState::Respond(sr.gen_error(
                LdapResultCode::UnwillingToPerform,
                "Unwilling to perform".to_string(),
            )))
        }
    }
}

async fn handle_cldaprequest(cfg: &CldapConfig, protomsg: LdapMsg) -> Option<LdapResponseState> {
    let res = match ServerOps::try_from(protomsg) {
        Ok(server_op) => do_cldap(cfg, server_op).await.unwrap_or_else(|e| {
            error!("do_cldap failed -> {:?}", e);
            LdapResponseState::Disconnect(DisconnectionNotice::r#gen_response(
                LdapResultCode::Other,
                "Internal Server Error",
            ))
        }),
        Err(_) => LdapResponseState::Disconnect(DisconnectionNotice::r#gen_response(
            LdapResultCode::ProtocolError,
            "Invalid Request",
        )),
    };
    Some(res)
}

pub async fn process(
    config: &CldapConfig,
    sock: Arc<UdpSocket>,
    client_address: SocketAddr,
    mut msg: BytesMut,
) {
    let mut ldap_codec = LdapCodec::default();
    let Ok(Some(protomsg)) = ldap_codec.decode(&mut msg) else {
        error!("Failed to decode");
        return;
    };

    match handle_cldaprequest(config, protomsg).await {
        Some(LdapResponseState::Respond(rmsg)) => {
            let mut udp_codec = UdpFramed::new(sock, ldap_codec);
            if let Err(e) = udp_codec.send((rmsg, client_address)).await {
                error!("Error sending response: {}", e);
            }
        }
        Some(LdapResponseState::MultiPartResponse(v)) => {
            // Must reply in a single datagram
            let mut bytes = BytesMut::new();
            for rmsg in v.into_iter() {
                if let Err(e) = ldap_codec.encode(rmsg, &mut bytes) {
                    error!("Error encoding LdapMsg: {}", e);
                    return;
                }
            }
            let mut codec = UdpFramed::new(sock, BytesCodec::new());
            if let Err(e) = codec.send((bytes.freeze(), client_address)).await {
                error!("Error sending response: {}", e);
            }
        }
        Some(LdapResponseState::Disconnect(rmsg)) => {
            let mut codec = UdpFramed::new(sock, ldap_codec);
            if let Err(e) = codec.send((rmsg, client_address)).await {
                error!("Error sending response: {}", e);
            }
        }
        _ => {
            error!("Internal server error");
        }
    };
}
