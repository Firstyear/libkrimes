mod as_rep;
mod error_rep;
mod tgs_rep;

use super::{
    AuthenticationTimeBound, DerivedKey, EncTicket, EncryptedData, EtypeInfo2, Name, PreauthData,
    TicketGrantRequest, TicketGrantTimeBound, TicketRenewTimeBound,
};
use crate::asn1::{
    constants::{errors::KrbErrorCode, message_types::KrbMessageType, pa_data_types::PaDataType},
    enc_kdc_rep_part::EncKdcRepPart,
    etype_info2::ETypeInfo2Entry as KdcETypeInfo2Entry,
    kdc_rep::KdcRep,
    kerberos_string::KerberosString,
    kerberos_time::KerberosTime,
    krb_error::{KrbError as KdcKrbError, MethodData},
    krb_kdc_rep::KrbKdcRep,
    pa_data::PaData,
    transited_encoding::TransitedEncoding,
    Ia5String, OctetString,
};
use crate::error::KrbError;
use crypto_glue::der::{Decode, Encode};
use std::time::{Duration, SystemTime};

pub use as_rep::{AuthenticationReply, AuthenticationReplyBuilder};
pub use error_rep::{ErrorReply, KerberosReplyPreauthBuilder, PreauthErrorReply};
pub use tgs_rep::{
    KerberosReplyTicketGrantBuilder, KerberosReplyTicketRenewBuilder, TicketGrantReply,
};
use tracing::{error, trace};

#[derive(Debug)]
pub enum KerberosReply {
    AS(AuthenticationReply),
    TGS(TicketGrantReply),
    PA(PreauthErrorReply),
    ERR(ErrorReply),
}

impl KerberosReply {
    pub fn preauth_builder(service: Name, stime: SystemTime) -> KerberosReplyPreauthBuilder {
        KerberosReplyPreauthBuilder::new(service, stime)
    }

    pub fn authentication_builder(
        client: Name,
        server: Name,
        time_bounds: AuthenticationTimeBound,
        nonce: i32,
    ) -> AuthenticationReplyBuilder {
        AuthenticationReplyBuilder::new(client, server, time_bounds, nonce)
    }

    pub fn ticket_renew_builder(
        ticket_grant_request: TicketGrantRequest,
        time_bounds: TicketRenewTimeBound,
    ) -> KerberosReplyTicketRenewBuilder {
        KerberosReplyTicketRenewBuilder::new(ticket_grant_request, time_bounds)
    }

    pub fn ticket_grant_builder(
        ticket_grant_request: TicketGrantRequest,
        time_bounds: TicketGrantTimeBound,
    ) -> KerberosReplyTicketGrantBuilder {
        KerberosReplyTicketGrantBuilder::new(ticket_grant_request, time_bounds)
    }

    pub fn error_request_invalid(service: Name, stime: SystemTime) -> KerberosReply {
        let code = KrbErrorCode::KrbErrGeneric;
        let error_text =
            Some("The Kerberos Client sent a malformed and invalid request.".to_string());
        KerberosReply::ERR(ErrorReply::new(code, service, error_text, stime))
    }

    pub fn error_request_failed_validation(service: Name, stime: SystemTime) -> KerberosReply {
        let code = KrbErrorCode::KrbErrGeneric;
        let error_text = Some(
            "The Kerberos Client sent a request that was cryptographically invalid.".to_string(),
        );
        KerberosReply::ERR(ErrorReply::new(code, service, error_text, stime))
    }

    pub fn error_no_etypes(service: Name, stime: SystemTime) -> KerberosReply {
        let code = KrbErrorCode::KdcErrEtypeNosupp;
        let error_text =
            Some("Client and Server do not have overlapping encryption type support.".to_string());
        KerberosReply::ERR(ErrorReply::new(code, service, error_text, stime))
    }

    pub fn error_preauth_failed(service: Name, stime: SystemTime) -> KerberosReply {
        let code = KrbErrorCode::KdcErrPreauthFailed;
        let error_text =
            Some("Preauthentication Failed - Check your password is correct.".to_string());
        KerberosReply::ERR(ErrorReply::new(code, service, error_text, stime))
    }

    pub fn error_client_principal(service: Name, stime: SystemTime) -> KerberosReply {
        let code = KrbErrorCode::KdcErrPreauthFailed;
        let error_text =
            Some("Preauthentication Failed - Client Name was not a valid Principal.".to_string());
        KerberosReply::ERR(ErrorReply::new(code, service, error_text, stime))
    }

    pub fn error_client_realm(service: Name, stime: SystemTime) -> KerberosReply {
        let code = KrbErrorCode::KdcErrWrongRealm;
        let error_text =
            Some("Preauthentication Failed - Check your realm is correct.".to_string());
        KerberosReply::ERR(ErrorReply::new(code, service, error_text, stime))
    }

    pub fn error_client_username(service: Name, stime: SystemTime) -> KerberosReply {
        let code = KrbErrorCode::KdcErrCPrincipalUnknown;
        let error_text =
            Some("Preauthentication Failed - Check your username is correct.".to_string());
        KerberosReply::ERR(ErrorReply::new(code, service, error_text, stime))
    }

    pub fn error_service_name(service: Name, stime: SystemTime) -> KerberosReply {
        let code = KrbErrorCode::KdcErrSPrincipalUnknown;
        let error_text = Some("Ticket Request Failed - Service Name not found.".to_string());
        KerberosReply::ERR(ErrorReply::new(code, service, error_text, stime))
    }

    pub fn error_as_not_krbtgt(service: Name, stime: SystemTime) -> KerberosReply {
        let code = KrbErrorCode::KdcErrSvcUnavailable;
        let error_text = Some(
            "Authentication (ASREQ) must only be for service instance `krbtgt@REALM`.".to_string(),
        );
        KerberosReply::ERR(ErrorReply::new(code, service, error_text, stime))
    }

    pub fn error_no_key(service: Name, stime: SystemTime) -> KerberosReply {
        let code = KrbErrorCode::KrbApErrNokey;
        let error_text = Some("No Key Available".to_string());
        KerberosReply::ERR(ErrorReply::new(code, service, error_text, stime))
    }

    pub fn error_clock_skew(service: Name, stime: SystemTime) -> KerberosReply {
        let code = KrbErrorCode::KrbApErrSkew;
        let error_text = Some("Clock Skew too great".to_string());
        KerberosReply::ERR(ErrorReply::new(code, service, error_text, stime))
    }

    pub fn error_cannot_postdate(service: Name, stime: SystemTime) -> KerberosReply {
        let code = KrbErrorCode::KdcErrCannotPostdate;
        let error_text = Some("Ticket not elegible for postdating".to_string());
        KerberosReply::ERR(ErrorReply::new(code, service, error_text, stime))
    }

    pub fn error_never_valid(service: Name, stime: SystemTime) -> KerberosReply {
        let code = KrbErrorCode::KdcErrNeverValid;
        let error_text = Some("Requested ticket start time is later than end time".to_string());
        KerberosReply::ERR(ErrorReply::new(code, service, error_text, stime))
    }

    pub fn error_renew_denied(service: Name, stime: SystemTime) -> KerberosReply {
        let code = KrbErrorCode::KdcErrPolicy;
        let error_text = Some("Requested ticket is unable to be renewed".to_string());
        KerberosReply::ERR(ErrorReply::new(code, service, error_text, stime))
    }

    pub fn error_inappropiate_checksum(service: Name, stime: SystemTime) -> KerberosReply {
        let code = KrbErrorCode::KrbApErrInappCksum;
        let error_text = Some("Inappropriate type of checksum in message".to_string());
        KerberosReply::ERR(ErrorReply::new(code, service, error_text, stime))
    }

    pub fn error_unsupported_checksum(service: Name, stime: SystemTime) -> KerberosReply {
        let code = KrbErrorCode::KdcErrSumtypeNosupp;
        let error_text = Some("KDC has no support for checksum type".to_string());
        KerberosReply::ERR(ErrorReply::new(code, service, error_text, stime))
    }

    pub fn error_internal(service: Name, stime: SystemTime) -> KerberosReply {
        let code = KrbErrorCode::KrbErrGeneric;
        let error_text = Some("Internal Server Error".to_string());
        KerberosReply::ERR(ErrorReply::new(code, service, error_text, stime))
    }
}

impl TryFrom<KrbKdcRep> for KerberosReply {
    type Error = KrbError;

    fn try_from(rep: KrbKdcRep) -> Result<Self, KrbError> {
        match rep {
            KrbKdcRep::AsRep(kdc_rep) | KrbKdcRep::TgsRep(kdc_rep) => {
                KerberosReply::try_from(kdc_rep)
            }
            KrbKdcRep::ErrRep(err_rep) => KerberosReply::try_from(err_rep),
        }
    }
}

impl TryFrom<KdcKrbError> for KerberosReply {
    type Error = KrbError;

    fn try_from(rep: KdcKrbError) -> Result<Self, KrbError> {
        // assert the pvno and msg_type
        if rep.pvno != 5 {
            return Err(KrbError::InvalidPvno);
        }

        let service = Name::try_from((rep.service_name, rep.service_realm))?;

        let msg_type =
            KrbMessageType::try_from(rep.msg_type).map_err(|_| KrbError::InvalidMessageType)?;

        if !matches!(msg_type, KrbMessageType::KrbError) {
            return Err(KrbError::InvalidMessageDirection);
        }

        let error_code = KrbErrorCode::try_from(rep.error_code).map_err(|_| {
            error!(?rep.error_code, "Unable to encode error code");
            KrbError::DerEncodeKrbErrorCode
        })?;

        let stime = rep.stime.to_system_time();
        let microsecs = Duration::from_micros(rep.susec as u64);

        let stime = stime + microsecs;

        match error_code {
            KrbErrorCode::KdcErrPreauthRequired => {
                let edata = rep.error_data.ok_or(KrbError::MissingPaData)?;

                let pavec: Vec<PaData> = MethodData::from_der(edata.as_bytes())
                    .map_err(|_| KrbError::DerDecodePaData)?;

                let pa_data = PreauthData::try_from(pavec)?;

                Ok(KerberosReply::PA(PreauthErrorReply {
                    pa_data,
                    service,
                    stime,
                }))
            }
            code => {
                let error_text = rep.error_text.as_ref().map(|s| s.to_string());
                let error = ErrorReply::new(code, service, error_text, stime);
                Ok(KerberosReply::ERR(error))
            }
        }
    }
}

impl TryInto<KrbKdcRep> for KerberosReply {
    type Error = KrbError;

    fn try_into(self) -> Result<KrbKdcRep, KrbError> {
        match self {
            KerberosReply::AS(AuthenticationReply {
                name,
                enc_part,
                pa_data,
                ticket,
            }) => {
                let pa_data: Option<Vec<PaData>> = match pa_data {
                    Some(data) => {
                        let etype_padata_vec = data
                            .etype_info2
                            .iter()
                            .map(|einfo| {
                                let salt = einfo
                                    .salt
                                    .as_ref()
                                    .map(Ia5String::new)
                                    .transpose()
                                    .map_err(|_| KrbError::DerEncodeKerberosString)?
                                    .map(KerberosString);
                                let s2kparams = einfo
                                    .s2kparams
                                    .as_ref()
                                    .map(|data| OctetString::new(data.to_owned()))
                                    .transpose()
                                    .map_err(|_| KrbError::DerEncodeOctetString)?;
                                Ok(KdcETypeInfo2Entry {
                                    etype: einfo.etype as i32,
                                    salt,
                                    s2kparams,
                                })
                            })
                            .collect::<Result<Vec<_>, KrbError>>()?;

                        let etype_padata_value = etype_padata_vec
                            .to_der()
                            .and_then(OctetString::new)
                            .map_err(|_| KrbError::DerEncodeOctetString)?;

                        let pavec = vec![PaData {
                            padata_type: PaDataType::PaEtypeInfo2 as u32,
                            padata_value: etype_padata_value,
                        }];
                        Some(pavec)
                    }
                    None => None,
                };

                let as_rep = KdcRep {
                    pvno: 5,
                    msg_type: KrbMessageType::KrbAsRep as u8,
                    padata: pa_data,
                    crealm: (&name).try_into()?,
                    cname: (&name).try_into()?,
                    ticket: ticket.try_into()?,
                    enc_part: enc_part.try_into()?,
                };

                Ok(KrbKdcRep::AsRep(as_rep))
            }
            KerberosReply::TGS(TicketGrantReply {
                client_name,
                enc_part,
                ticket,
            }) => {
                let tgs_rep = KdcRep {
                    pvno: 5,
                    msg_type: KrbMessageType::KrbTgsRep as u8,
                    padata: None,
                    crealm: (&client_name).try_into()?,
                    cname: (&client_name).try_into()?,
                    ticket: ticket.try_into()?,
                    enc_part: enc_part.try_into()?,
                };

                Ok(KrbKdcRep::TgsRep(tgs_rep))
            }
            KerberosReply::PA(PreauthErrorReply {
                pa_data,
                service,
                stime,
            }) => {
                let error_code = KrbErrorCode::KdcErrPreauthRequired as i32;
                // The pre-auth data is stuffed into error_data. Because of course kerberos can't
                // do nice things.
                let etype_padata_vec = pa_data
                    .etype_info2
                    .iter()
                    .map(|einfo| {
                        let salt = einfo
                            .salt
                            .as_ref()
                            .map(Ia5String::new)
                            .transpose()
                            .map_err(|_| KrbError::DerEncodeKerberosString)?
                            .map(KerberosString);

                        let s2kparams = einfo
                            .s2kparams
                            .as_ref()
                            .map(|data| OctetString::new(data.to_owned()))
                            .transpose()
                            .map_err(|_| KrbError::DerEncodeOctetString)?;
                        Ok(KdcETypeInfo2Entry {
                            etype: einfo.etype as i32,
                            salt,
                            s2kparams,
                        })
                    })
                    .collect::<Result<Vec<KdcETypeInfo2Entry>, KrbError>>()?;

                let etype_padata_value = etype_padata_vec
                    .to_der()
                    .and_then(OctetString::new)
                    .map_err(|_| KrbError::DerEncodeOctetString)?;

                let pavec = vec![
                    PaData {
                        padata_type: PaDataType::PaEncTimestamp as u32,
                        padata_value: OctetString::new([])
                            .map_err(|_| KrbError::DerEncodeOctetString)?,
                    },
                    PaData {
                        padata_type: PaDataType::PaEtypeInfo2 as u32,
                        padata_value: etype_padata_value,
                    },
                ];

                let error_data = pavec
                    .to_der()
                    .and_then(OctetString::new)
                    .map(Some)
                    .map_err(|_| KrbError::DerEncodeOctetString)?;

                let error_text = Ia5String::new("Preauthentication Required")
                    .map(KerberosString)
                    .ok();

                let stime = stime
                    .duration_since(SystemTime::UNIX_EPOCH)
                    // We need to stip the fractional part.
                    .map(|t| Duration::from_secs(t.as_secs()))
                    .unwrap_or_default();

                let stime = KerberosTime::from_unix_duration(stime)
                    .map_err(|_| KrbError::DerEncodeKerberosTime)?;

                let (service_name, service_realm) = (&service).try_into()?;

                let krb_error = KdcKrbError {
                    pvno: 5,
                    msg_type: KrbMessageType::KrbError as u8,
                    ctime: None,
                    cusec: None,
                    stime,
                    susec: 0,
                    error_code,
                    crealm: None,
                    cname: None,
                    service_realm,
                    service_name,
                    error_text,
                    error_data,
                };

                Ok(KrbKdcRep::ErrRep(krb_error))
            }
            KerberosReply::ERR(error) => {
                let error_code = error.code().clone() as i32;

                let error_text = error
                    .text()
                    .as_ref()
                    .and_then(|et| Ia5String::new(&et).map(KerberosString).ok());

                let stime = error
                    .server_time()
                    .duration_since(SystemTime::UNIX_EPOCH)
                    // We need to stip the fractional part.
                    .map(|t| Duration::from_secs(t.as_secs()))
                    .unwrap_or_default();

                let stime = KerberosTime::from_unix_duration(stime)
                    .map_err(|_| KrbError::DerEncodeKerberosTime)?;

                let (service_name, service_realm) = error.service().try_into()?;

                let krb_error = KdcKrbError {
                    pvno: 5,
                    msg_type: KrbMessageType::KrbError as u8,
                    ctime: None,
                    cusec: None,
                    stime,
                    susec: 0,
                    error_code,
                    crealm: None,
                    cname: None,
                    service_realm,
                    service_name,
                    error_text,
                    error_data: None,
                };

                Ok(KrbKdcRep::ErrRep(krb_error))
            }
        }
    }
}

impl TryFrom<KdcRep> for KerberosReply {
    type Error = KrbError;

    fn try_from(rep: KdcRep) -> Result<Self, KrbError> {
        // assert the pvno and msg_type
        if rep.pvno != 5 {
            return Err(KrbError::InvalidPvno);
        }

        let msg_type =
            KrbMessageType::try_from(rep.msg_type).map_err(|_| KrbError::InvalidMessageType)?;

        match msg_type {
            KrbMessageType::KrbAsRep => {
                let enc_part = EncryptedData::try_from(rep.enc_part)?;
                trace!(?enc_part);

                let pa_data = rep.padata.map(PreauthData::try_from).transpose()?;
                trace!(?pa_data);

                let name = (rep.cname, rep.crealm).try_into()?;
                let ticket = EncTicket::try_from(rep.ticket)?;

                Ok(KerberosReply::AS(AuthenticationReply {
                    name,
                    pa_data,
                    enc_part,
                    ticket,
                }))
            }
            KrbMessageType::KrbTgsRep => {
                let enc_part = EncryptedData::try_from(rep.enc_part)?;
                trace!(?enc_part);

                let client_name = (rep.cname, rep.crealm).try_into()?;

                let ticket = EncTicket::try_from(rep.ticket)?;

                Ok(KerberosReply::TGS(TicketGrantReply {
                    client_name,
                    enc_part,
                    ticket,
                }))
            }
            _ => Err(KrbError::InvalidMessageDirection),
        }
    }
}

/* Convenience trait for EntraID which provides the raw ASN.1 AS-REP in the PRT */
impl TryFrom<&[u8]> for KerberosReply {
    type Error = KrbError;
    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        match KrbKdcRep::from_der(value) {
            Ok(krb_kdc_rep) => krb_kdc_rep.try_into(),
            Err(_) => Err(KrbError::InvalidMessageType),
        }
    }
}
