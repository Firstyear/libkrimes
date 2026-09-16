mod as_req;
mod tgs_req;

use super::{EncryptedData, Name, Preauth};
use crate::asn1::{
    constants::{
        encryption_types::EncryptionType, message_types::KrbMessageType, pa_data_types::PaDataType,
    },
    encrypted_data::EncryptedData as KdcEncryptedData,
    kdc_req::KdcReq,
    kdc_req_body::KdcReqBody,
    kerberos_time::KerberosTime,
    krb_kdc_req::KrbKdcReq,
    pa_data::PaData,
    OctetString,
};
use crate::error::KrbError;
use crypto_glue::der::{asn1::Any, Encode};
use std::time::SystemTime;
use tracing::trace;

pub use as_req::{AuthenticationRequest, AuthenticationRequestBuilder};
pub use tgs_req::{TicketGrantRequest, TicketGrantRequestBuilder, TicketGrantRequestUnverified};

#[derive(Debug)]
pub enum KerberosRequest {
    AS(Box<AuthenticationRequest>),
    TGS(Box<TicketGrantRequestUnverified>),
}

impl KerberosRequest {
    pub fn as_builder(
        client_name: &Name,
        service_name: Name,
        until: SystemTime,
    ) -> AuthenticationRequestBuilder {
        AuthenticationRequestBuilder::new(client_name.clone(), service_name, until)
    }

    pub fn tgs_builder(
        service_name: Name,
        now: SystemTime,
        until: SystemTime,
    ) -> TicketGrantRequestBuilder {
        TicketGrantRequestBuilder::new(service_name, now, until)
    }
}

impl TryInto<KrbKdcReq> for &KerberosRequest {
    type Error = KrbError;

    fn try_into(self) -> Result<KrbKdcReq, Self::Error> {
        match self {
            KerberosRequest::AS(
                /*
                AuthenticationRequest {
                    nonce,
                    client_name,
                    service_name,
                    from,
                    until,
                    renew,
                    preauth,
                    etypes,
                    kdc_options,
                }
                */
                auth_req,
            ) => {
                let padata = if auth_req.preauth.pa_fx_cookie.is_some()
                    || auth_req.preauth.enc_timestamp.is_some()
                {
                    let mut padata_inner = Vec::with_capacity(2);

                    if let Some(fx_cookie) = &auth_req.preauth.pa_fx_cookie {
                        let padata_value = OctetString::new(fx_cookie.clone())
                            .map_err(|_| KrbError::DerEncodeOctetString)?;
                        padata_inner.push(PaData {
                            padata_type: PaDataType::PaFxCookie as u32,
                            padata_value,
                        })
                    }

                    if let Some(enc_data) = &auth_req.preauth.enc_timestamp {
                        let padata_value = match enc_data {
                            EncryptedData::Aes256CtsHmacSha196 { kvno: _, data } => {
                                let cipher = OctetString::new(data.clone())
                                    .map_err(|_| KrbError::DerEncodeOctetString)?;
                                KdcEncryptedData {
                                    etype: EncryptionType::AES256_CTS_HMAC_SHA1_96 as i32,
                                    kvno: None,
                                    cipher,
                                }
                            }
                            EncryptedData::Opaque { .. } => {
                                return Err(KrbError::UnsupportedEncryption);
                            }
                        };

                        // Need to encode the padata value now.
                        let padata_value = padata_value
                            .to_der()
                            .and_then(OctetString::new)
                            .map_err(|_| KrbError::DerEncodeOctetString)?;

                        padata_inner.push(PaData {
                            padata_type: PaDataType::PaEncTimestamp as u32,
                            padata_value,
                        })
                    }

                    /*
                    padata_inner.push(PaData {
                        padata_type: PaDataType::PadataAsFreshness as u32,
                        padata_value: OctetString::new(&[]).map_err(|_| KrbError::DerEncodeOctetString)?,
                    });

                    padata_inner.push(PaData {
                        padata_type: PaDataType::EncpadataReqEncPaRep as u32,
                        padata_value: OctetString::new(&[]).map_err(|_| KrbError::DerEncodeOctetString)?,
                    });
                    */

                    Some(padata_inner)
                } else {
                    None
                };

                let (cname, realm) = (&auth_req.client_name).try_into()?;
                let sname = (&auth_req.service_name).try_into()?;

                let req_body = KdcReqBody {
                    kdc_options: auth_req.kdc_options,
                    cname: Some(cname),
                    // Per the RFC this is the "servers realm" in an AsReq but also the clients. So it's really
                    // not clear if the sname should have the realm or not or if this can be divergent between
                    // the client and server realm. What a clownshow, completely of their own making by trying
                    // to reuse structures in inconsistent ways. For now, we copy whatever bad behaviour mit
                    // krb does, because it's probably wrong, but it's the reference impl.
                    realm,
                    sname: Some(sname),
                    from: auth_req
                        .from
                        .map(|t| {
                            KerberosTime::from_system_time(t)
                                .map_err(|_| KrbError::DerEncodeKerberosTime)
                        })
                        .transpose()?,
                    till: KerberosTime::from_system_time(auth_req.until)
                        .map_err(|_| KrbError::DerEncodeKerberosTime)?,
                    rtime: auth_req
                        .renew
                        .map(|t| {
                            KerberosTime::from_system_time(t)
                                .map_err(|_| KrbError::DerEncodeKerberosTime)
                        })
                        .transpose()?,
                    nonce: auth_req.nonce,
                    etype: auth_req.etypes.iter().map(|e| *e as i32).collect(),
                    addresses: None,
                    enc_authorization_data: None,
                    additional_tickets: None,
                };

                let req_body = Any::encode_from(&req_body).map_err(|_| KrbError::DerEncodeAny)?;

                Ok(KrbKdcReq::AsReq(KdcReq {
                    pvno: 5,
                    msg_type: KrbMessageType::KrbAsReq as u8,
                    padata,
                    req_body,
                }))
            }
            KerberosRequest::TGS(unverified_tgs_req) => {
                let padata = if unverified_tgs_req.preauth.tgs_req.is_some() {
                    let mut padata_inner = Vec::with_capacity(1);

                    if let Some(ap_req) = &unverified_tgs_req.preauth.tgs_req {
                        let padata_value = ap_req
                            .to_der()
                            .and_then(OctetString::new)
                            .map_err(|_| KrbError::DerEncodeApReq)?;
                        padata_inner.push(PaData {
                            padata_type: PaDataType::PaTgsReq as u32,
                            padata_value,
                        });
                    }

                    Some(padata_inner)
                } else {
                    None
                };

                Ok(KrbKdcReq::TgsReq(KdcReq {
                    pvno: 5,
                    msg_type: KrbMessageType::KrbTgsReq as u8,
                    padata,
                    req_body: unverified_tgs_req.req_body.clone(),
                }))
            }
        }
    }
}

impl TryFrom<KrbKdcReq> for KerberosRequest {
    type Error = KrbError;

    fn try_from(req: KrbKdcReq) -> Result<Self, KrbError> {
        match req {
            KrbKdcReq::TgsReq(kdc_req) | KrbKdcReq::AsReq(kdc_req) => {
                KerberosRequest::try_from(kdc_req)
            }
        }
    }
}

impl TryFrom<KdcReq> for KerberosRequest {
    type Error = KrbError;

    fn try_from(req: KdcReq) -> Result<Self, Self::Error> {
        // assert the pvno and msg_type
        if req.pvno != 5 {
            return Err(KrbError::InvalidPvno);
        }

        let msg_type =
            KrbMessageType::try_from(req.msg_type).map_err(|_| KrbError::InvalidMessageType)?;

        match msg_type {
            KrbMessageType::KrbAsReq => {
                let req_body = req
                    .req_body
                    .decode_as::<KdcReqBody>()
                    .map_err(|_| KrbError::DerDecodeKdcReqBody)?;

                // Filter and use only the finest of etypes.
                let etypes = req_body
                    .etype
                    .iter()
                    .filter_map(|etype| {
                        EncryptionType::try_from(*etype)
                            .ok()
                            .and_then(|etype| match etype {
                                EncryptionType::AES256_CTS_HMAC_SHA1_96 => Some(etype),
                                _ => None,
                            })
                    })
                    .collect();

                let preauth = req
                    .padata
                    .map(Preauth::try_from)
                    .transpose()?
                    .unwrap_or_default();
                trace!(?preauth);

                trace!(?req_body);

                let realm = &req_body.realm;
                let cname = &req_body.cname.ok_or(KrbError::MissingClientName)?;
                let sname = &req_body
                    .sname
                    .ok_or(KrbError::MissingServiceNameWithRealm)?;

                let client_name: Name = (cname, realm).try_into()?;
                let service_name: Name = (sname, realm).try_into()?;

                let from = req_body.from.map(|t| t.to_system_time());
                let until = req_body.till.to_system_time();
                let renew = req_body.rtime.map(|t| t.to_system_time());
                let nonce = req_body.nonce;
                let kdc_options = req_body.kdc_options;

                // addresses,
                // enc_authorization_data,
                // additional_tickets,

                Ok(KerberosRequest::AS(Box::new(AuthenticationRequest {
                    nonce,
                    client_name,
                    service_name,
                    from,
                    until,
                    renew,
                    etypes,
                    preauth,
                    kdc_options,
                })))
            }
            KrbMessageType::KrbTgsReq => {
                trace!(?req);

                // IMPORTANT! At this point, since we don't yet have the session key, req_body
                // shouldn't be parsed. We need to process padata first to get the tgs and
                // relevant info *before* we can proceed, as we need to checksum the bytes
                // of the req_body.
                //
                // There is a MAJOR RISK that at this point, we will fail to checksum, since
                // our current design forces us to recanonicalise req_body to checksum it!!!
                //
                // We might be able to avoid this by the use of pa-fx-fast but that has it's
                // own bag of complexity ...
                let preauth = req
                    .padata
                    .map(Preauth::try_from)
                    .transpose()?
                    .unwrap_or_default();
                trace!(?preauth);

                Ok(KerberosRequest::TGS(Box::new(
                    TicketGrantRequestUnverified {
                        preauth,
                        req_body: req.req_body,
                    },
                )))
            }
            _ => Err(KrbError::InvalidMessageDirection),
        }
    }
}
