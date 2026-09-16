use crate::asn1::{
    ap_options::{ApFlags, ApOptions},
    ap_req::{ApReq, ApReqInner},
    authenticator::{Authenticator, AuthenticatorInner},
    authorization_data::AuthorizationData,
    encryption_key::EncryptionKey,
    kdc_req_body::KdcReqBody as Asn1KdcReqBody,
    kerberos_flags::KerberosFlags,
    tagged_ticket::TaggedTicket,
    ticket_flags::TicketFlags,
};
use crate::cksum::ChecksumBuilder;
use crate::proto::{
    EncTicket, EncryptedData, EncryptionType, KdcEncryptedData, KdcPrimaryKey, KerberosRequest,
    KerberosTime, KrbError, Name, Preauth, SessionKey, Ticket,
};
use crypto_glue::der::asn1::{Any, OctetString};
use crypto_glue::rand::{rng, RngExt};
use std::time::SystemTime;
use tracing::trace;

#[derive(Debug)]
pub struct TicketGrantRequestUnverified {
    pub preauth: Preauth,
    // pub(crate) req_body: Vec<u8>,
    pub(crate) req_body: Any,
}

#[derive(Debug)]
pub struct TicketGrantRequest {
    pub(crate) nonce: i32,
    pub(crate) service_name: Name,
    pub(crate) etypes: Vec<EncryptionType>,
    pub(crate) sub_session_key: Option<SessionKey>,
    pub(crate) client_time: SystemTime,
    pub(crate) from: Option<SystemTime>,
    pub(crate) until: SystemTime,
    pub(crate) renew: Option<SystemTime>,

    pub(crate) ticket: Ticket,
}

#[derive(Debug)]
struct ApReqBuilder {
    client_name: Name,
    ticket: EncTicket,
    session_key: SessionKey,
}

#[derive(Debug)]
pub struct TicketGrantRequestBuilder {
    service_name: Name,
    client_time: SystemTime,
    from: Option<SystemTime>,
    until: SystemTime,
    renew: Option<SystemTime>,
    // preauth: Option<Preauth>,
    etypes: Vec<EncryptionType>,
    ap_req_builder: Option<ApReqBuilder>,
}

impl TicketGrantRequestUnverified {
    pub fn validate(
        &self,
        primary_key: &KdcPrimaryKey,
        realm: &str,
    ) -> Result<TicketGrantRequest, KrbError> {
        trace!(?self, "Validating ap-req");

        // Destructure the ticket grant to make it easier to handle.
        let TicketGrantRequestUnverified {
            preauth:
                Preauth {
                    tgs_req,
                    // pa_fx_fast: _,
                    enc_timestamp: _,
                    pa_fx_cookie: _,
                },
            req_body,
        } = self;

        let Some(ap_req) = tgs_req else {
            return Err(KrbError::TgsMissingPaApReq);
        };

        let ap_req: &ApReqInner = ap_req.as_ref();

        if ap_req.pvno != 5 || ap_req.msg_type != 14 {
            return Err(KrbError::TgsInvalidPaApReq);
        };

        let ap_req_ticket = &ap_req.ticket.0;
        let ap_req_authenticator = EncryptedData::try_from(ap_req.authenticator.clone())?;
        // let ap_req_options = ap_req.ap_options;

        trace!(?ap_req_ticket, "ticket");
        trace!(?ap_req_authenticator, "authenticator");

        // Decrypt the ticket. This should be the TGT and contains the session
        // key used for encryption of the authenticator.
        if ap_req_ticket.realm.as_str() != realm {
            return Err(KrbError::TgsNotForRealm);
        }

        let ap_req_ticket_service_name =
            Name::try_from((&ap_req_ticket.sname, &ap_req_ticket.realm))?;

        if !ap_req_ticket_service_name.is_service_krbtgt(realm) {
            tracing::error!(?ap_req_ticket_service_name, "TgsTicketIsNotTgt");
            return Err(KrbError::TgsTicketIsNotTgt);
        }

        let ap_req_ticket_enc = EncryptedData::try_from(ap_req_ticket.enc_part.clone())?;

        let enc_ticket_part = ap_req_ticket_enc.decrypt_enc_tgt(primary_key)?;

        trace!(?enc_ticket_part, "enc-ticket-part");

        // Get the session Key.

        let session_key = SessionKey::try_from(enc_ticket_part.key)?;

        // Decrypt the authenticator
        let authenticator = session_key.decrypt_ap_req_authenticator(ap_req_authenticator)?;

        let authenticator: AuthenticatorInner = authenticator.into();

        trace!(?authenticator, "authenticator");

        let Some(his_checksum) = authenticator.cksum else {
            return Err(KrbError::TgsAuthMissingChecksum);
        };

        let checksum_builder: ChecksumBuilder =
            (his_checksum.checksum_type, Some(session_key.clone())).try_into()?;
        let checksum = checksum_builder.compute_kdc_req_body(req_body)?;

        // Validate that the checksum matches what our authenticator contains.
        if checksum != his_checksum {
            tracing::debug!(?checksum, ?his_checksum);
            return Err(KrbError::TgsAuthChecksumFailure);
        }

        let req_body = req_body
            .decode_as::<Asn1KdcReqBody>()
            .map_err(|_| KrbError::DerDecodeKdcReqBody)?;

        trace!(?req_body);

        let Some(service_princ) = req_body.sname else {
            return Err(KrbError::TgsKdcReqMissingServiceName);
        };

        // ==================================================================
        //
        // WARNING WARNING WARNING WARNING
        //
        // Below this line is where we now trust that the inputs are valid and checksummed
        // so that we can proceed with the release of the TGS to the KDC.

        let sub_session_key = authenticator
            .subkey
            .map(SessionKey::try_from)
            // Invert the Option<Result> to Result<Option>
            .transpose()?;

        let nonce = req_body.nonce;

        let ticket = {
            let client_name = Name::try_from((enc_ticket_part.cname, enc_ticket_part.crealm))?;
            let auth_time = enc_ticket_part.auth_time.to_system_time();

            let flags = enc_ticket_part.flags;

            let start_time = enc_ticket_part
                .start_time
                .map(|t| t.to_system_time())
                .ok_or(KrbError::TgsKdcMissingStartTime)?;

            let end_time = enc_ticket_part.end_time.to_system_time();
            let renew_until = enc_ticket_part.renew_till.map(|t| t.to_system_time());

            Ticket {
                flags,
                client_name,
                session_key,
                start_time,
                end_time,
                renew_until,
                auth_time,
            }
        };

        let service_name = Name::try_from((service_princ, req_body.realm))?;

        let from = req_body.from.map(|t| t.to_system_time());
        let until = req_body.till.to_system_time();
        let renew = req_body.rtime.map(|t| t.to_system_time());
        let client_time = authenticator.ctime.to_system_time();

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

        Ok(TicketGrantRequest {
            nonce,
            service_name,
            client_time,
            from,
            until,
            renew,
            etypes,
            sub_session_key,
            ticket,
        })
    }
}

impl TicketGrantRequest {
    pub fn service_name(&self) -> &Name {
        &self.service_name
    }

    pub fn client_time(&self) -> &SystemTime {
        &self.client_time
    }

    /// This is the time the client requested the ticket grant to start at. This value
    /// MUST be validated within the bounds of the ticket validity.
    pub fn requested_start_time(&self) -> Option<SystemTime> {
        self.from
    }

    /// This is the time the client requested the ticket grant to end at. This value
    /// MUST be validated within the bounds of the ticket validity.
    pub fn requested_end_time(&self) -> SystemTime {
        self.until
    }

    /// This is the time the client requested the ticket grant to be renewable until.
    /// This value MUST be validated within the bounds of the tickets renewable validity.
    pub fn requested_renew_until(&self) -> Option<SystemTime> {
        self.renew
    }

    /// The cryptographically verified ticket granting ticket that this KDC or a trusted
    /// KDC issued to the client.
    pub fn ticket_granting_ticket(&self) -> &Ticket {
        &self.ticket
    }

    pub fn ticket_flags(&self) -> &TicketFlags {
        &self.ticket.flags
    }

    pub fn etypes(&self) -> &[EncryptionType] {
        &self.etypes
    }
}

impl TicketGrantRequestBuilder {
    pub fn new(service_name: Name, now: SystemTime, until: SystemTime) -> Self {
        let etypes = vec![EncryptionType::AES256_CTS_HMAC_SHA1_96];
        Self {
            service_name,
            from: None,
            until,
            renew: None,
            // preauth: None,
            etypes,
            ap_req_builder: None,
            client_time: now,
        }
    }

    pub fn from(mut self, from: Option<SystemTime>) -> Self {
        self.from = from;
        self
    }

    pub fn renew_until(mut self, renew: Option<SystemTime>) -> Self {
        self.renew = renew;
        self
    }

    pub fn preauth_ap_req(
        mut self,
        client: &Name,
        ticket: &EncTicket,
        session_key: &SessionKey,
    ) -> Result<Self, KrbError> {
        let ap_req_builder: ApReqBuilder = ApReqBuilder {
            client_name: client.clone(),
            ticket: ticket.clone(),
            session_key: session_key.clone(),
        };
        self.ap_req_builder = Some(ap_req_builder);
        Ok(self)
    }

    pub fn build(self) -> Result<KerberosRequest, KrbError> {
        let TicketGrantRequestBuilder {
            service_name,
            from,
            until,
            renew,
            // preauth: _,
            etypes,
            ap_req_builder,
            client_time,
        } = self;

        let ap_req_builder = ap_req_builder.ok_or(
            // This will be removed soon
            KrbError::MissingPaData,
        )?;

        // BUG IN MIT KRB5 - If the value is greater than i32 max you get:
        // Jun 28 03:47:41 3e79497ab6b5 krb5kdc[1](Error): ASN.1 value too large - while dispatching (tcp)
        // Heimdal for whatever reason will happily send negative values, so no idea
        // how they get away with it when we don't ....
        let nonce: i32 = rng().random();
        let nonce = nonce.abs();

        // So far we don't use preauth-here
        // let preauth = preauth.unwrap_or_default();

        let mut kdc_options = KerberosFlags::none();
        kdc_options |= KerberosFlags::Renewable;
        kdc_options |= KerberosFlags::Canonicalize;

        let (_, realm) = (&service_name).try_into()?;
        let sname = (&service_name).try_into()?;

        let req_body = Asn1KdcReqBody {
            kdc_options,
            cname: None,
            realm,
            sname: Some(sname),
            from: from
                .map(|t| {
                    KerberosTime::from_system_time(t).map_err(|_| KrbError::DerEncodeKerberosTime)
                })
                .transpose()?,
            till: KerberosTime::from_system_time(until)
                .map_err(|_| KrbError::DerEncodeKerberosTime)?,
            rtime: renew
                .map(|t| {
                    KerberosTime::from_system_time(t).map_err(|_| KrbError::DerEncodeKerberosTime)
                })
                .transpose()?,
            nonce,
            etype: etypes.iter().map(|e| *e as i32).collect(),
            addresses: None,
            enc_authorization_data: None,
            additional_tickets: None,
        };

        let req_body = Any::encode_from(&req_body).map_err(|_| KrbError::DerEncodeAny)?;

        //  The checksum in the authenticator is to be computed over the KDC-REQ-BODY encoding.
        let checksum_builder =
            ChecksumBuilder::HmacSha196Aes256(ap_req_builder.session_key.clone());
        let checksum = checksum_builder.compute_kdc_req_body(&req_body)?;

        // The encrypted authenticator is included in the AP-REQ; it certifies
        // to a server that the sender has recent knowledge of the encryption
        // key in the accompanying ticket, to help the server detect replays.
        // It also assists in the selection of a "true session key" to use with
        // the particular session. It is encrypted in the ticket's session key,
        // with a key usage value of 11 in normal application exchanges, or 7
        // when used as the PA-TGS-REQ PA-DATA field of a TGS-REQ exchange (see
        // Section 5.4.1)
        let (client_name, client_realm) = (&ap_req_builder.client_name).try_into()?;
        let subkey: Option<EncryptionKey> = None;
        let sequence_number: Option<u32> = None;
        let authorization_data: Option<AuthorizationData> = None;
        let authenticator: Authenticator = Authenticator::new(
            client_name,
            client_realm,
            client_time,
            Some(checksum),
            subkey,
            sequence_number,
            authorization_data,
        )?;
        let authenticator: EncryptedData = ap_req_builder
            .session_key
            .encrypt_ap_req_authenticator(&authenticator)?;
        let authenticator: KdcEncryptedData = match authenticator {
            EncryptedData::Aes256CtsHmacSha196 { kvno, data } => {
                let cipher =
                    OctetString::new(data.clone()).map_err(|_| KrbError::DerEncodeOctetString)?;
                KdcEncryptedData {
                    etype: EncryptionType::AES256_CTS_HMAC_SHA1_96 as i32,
                    kvno,
                    cipher,
                }
            }
            EncryptedData::Opaque { .. } => return Err(KrbError::UnsupportedEncryption),
        };

        let ap_options: ApOptions = ApFlags::none();

        let ticket: TaggedTicket = ap_req_builder.ticket.try_into()?;
        let ap_req: ApReq = ApReq::new(ap_options, ticket, authenticator);

        let preauth = Preauth {
            tgs_req: Some(ap_req),
            ..Default::default()
        };

        Ok(KerberosRequest::TGS(Box::new(
            TicketGrantRequestUnverified { preauth, req_body },
        )))
    }
}
