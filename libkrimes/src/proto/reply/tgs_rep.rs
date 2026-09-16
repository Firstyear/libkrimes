use crate::asn1::{
    authorization_data::AuthorizationData,
    constants::authorization_data_types::AuthorizationDataType, enc_ticket_part::EncTicketPart,
    encryption_key::EncryptionKey as KdcEncryptionKey,
};
use crate::proto::ms_pac::AdWin2kPac;
use crate::proto::reply::{EncKdcRepPart, KerberosReply, TransitedEncoding};
use crate::proto::request::TicketGrantRequest;
use crate::proto::time::{TicketGrantTimeBound, TicketRenewTimeBound};
use crate::proto::{
    DerivedKey, EncTicket, EncryptedData, KdcPrimaryKey, KerberosTime, KrbError, Name, SessionKey,
    Ticket, TicketFlags,
};
use crypto_glue::der::{asn1::OctetString, Encode};

#[derive(Debug)]
pub struct TicketGrantReply {
    pub client_name: Name,
    pub enc_part: EncryptedData,
    pub ticket: EncTicket,
}

pub struct KerberosReplyTicketGrantBuilder {
    nonce: i32,
    service_name: Name,
    sub_session_key: Option<SessionKey>,
    pac: Option<AdWin2kPac>,
    time_bounds: TicketGrantTimeBound,
    ticket: Ticket,
    flags: TicketFlags,
}

impl KerberosReplyTicketGrantBuilder {
    pub fn new(
        ticket_grant_request: TicketGrantRequest,
        time_bounds: TicketGrantTimeBound,
    ) -> Self {
        let TicketGrantRequest {
            nonce,
            service_name,
            from: _,
            until: _,
            renew: _,
            etypes: _,
            sub_session_key,
            client_time: _,
            ticket,
        } = ticket_grant_request;

        let mut flags = TicketFlags::none();
        if time_bounds.renew_until().is_some() {
            flags |= TicketFlags::Renewable;
        }
        // From is what the client requested.
        // Now is the kdc time.
        // ticket.start_time is when the ticket began.
        Self {
            nonce,
            service_name,

            sub_session_key,

            pac: None,

            time_bounds,
            ticket,

            flags,
        }
    }
    pub fn build(mut self, service_key: &DerivedKey) -> Result<KerberosReply, KrbError> {
        let service_session_key = SessionKey::new();
        let service_session_key: KdcEncryptionKey = service_session_key.try_into()?;

        let (cname, crealm) = (&self.ticket.client_name).try_into()?;
        let (server_name, server_realm) = (&self.service_name).try_into()?;

        let auth_time = KerberosTime::from_system_time(self.ticket.auth_time)
            .map_err(|_| KrbError::DerEncodeKerberosTime)?;
        let start_time = Some(
            KerberosTime::from_system_time(self.time_bounds.start_time())
                .map_err(|_| KrbError::DerEncodeKerberosTime)?,
        );
        let end_time = KerberosTime::from_system_time(self.time_bounds.end_time())
            .map_err(|_| KrbError::DerEncodeKerberosTime)?;

        let renew_till = if let Some(renew_until) = self.time_bounds.renew_until() {
            self.flags |= TicketFlags::Renewable;
            Some(
                KerberosTime::from_system_time(renew_until)
                    .map_err(|_| KrbError::DerEncodeKerberosTime)?,
            )
        } else {
            None
        };

        // TGS_REP The ciphertext is encrypted with the sub-session key
        // from the authenticator.
        // If absent, the session key is used (with no kvno).
        // 5.4.2 reads as though the the clients version number is used here for kvno?

        // KeyUsage == 8 for session key, or == 9 for subkey.
        // let enc_part = EncTGSRepPart == EncKDCRepPart;

        let enc_kdc_rep_part = EncKdcRepPart {
            key: service_session_key.clone(),
            // Not 100% clear on this field.
            last_req: Vec::with_capacity(0),
            nonce: self.nonce,
            key_expiration: None,
            flags: self.flags,
            auth_time,
            start_time,
            end_time,
            renew_till,
            server_realm,
            server_name,
            client_addresses: None,
            encrypted_pa_data: None,
        };

        // Encrypt this with the original tickets sub_session_key so that they
        // can decrypt this and get the service_session_key out.
        let enc_part = if let Some(sub_session_key) = self.sub_session_key {
            sub_session_key.encrypt_tgs_rep_part(enc_kdc_rep_part, true)?
        } else {
            self.ticket
                .session_key
                .encrypt_tgs_rep_part(enc_kdc_rep_part, false)?
        };

        // An MS-PAC is required for Samba to work.
        let authorization_data = if let Some(pac) = self.pac {
            // Need to work out the signatures here.

            let pac_data_inner =
                OctetString::new(pac.to_bytes()).map_err(|_| KrbError::DerEncodeOctetString)?;

            let pac_data = AuthorizationData {
                ad_type: AuthorizationDataType::AdWin2kPac.into(),
                ad_data: pac_data_inner,
            }
            .to_der()
            .and_then(OctetString::new)
            .map_err(|_| KrbError::DerEncodeOctetString)?;

            Some(vec![AuthorizationData {
                ad_type: AuthorizationDataType::AdIfRelevant.into(),
                ad_data: pac_data,
            }])
        } else {
            None
        };

        let transited = TransitedEncoding {
            tr_type: 1,
            // Since no transit has occured, we record an empty str.
            contents: OctetString::new(*b"").map_err(|_| KrbError::DerEncodeOctetString)?,
        };

        // EncTicketPart
        // Encrypted to the key of the service - this is what the ticket holder
        // forwards to the service to that it is aware of it's service session key.
        let ticket_inner = EncTicketPart {
            flags: self.flags,
            key: service_session_key,
            crealm,
            cname,
            transited,
            auth_time,
            start_time,
            end_time,
            renew_till,
            client_addresses: None,
            authorization_data,
        };

        let ticket_enc_part = service_key.encrypt_tgs(ticket_inner)?;

        let ticket = EncTicket {
            tkt_vno: 5,
            service: self.service_name,
            enc_part: ticket_enc_part,
        };

        let client_name = self.ticket.client_name;

        Ok(KerberosReply::TGS(TicketGrantReply {
            client_name,
            enc_part,
            ticket,
        }))
    }
}

pub struct KerberosReplyTicketRenewBuilder {
    nonce: i32,
    service_name: Name,
    sub_session_key: Option<SessionKey>,
    time_bounds: TicketRenewTimeBound,
    ticket: Ticket,
}

impl KerberosReplyTicketRenewBuilder {
    pub fn new(
        ticket_grant_request: TicketGrantRequest,
        time_bounds: TicketRenewTimeBound,
    ) -> Self {
        let TicketGrantRequest {
            nonce,
            service_name,
            from: _,
            until: _,
            renew: _,
            etypes: _,
            sub_session_key,
            client_time: _,
            ticket,
        } = ticket_grant_request;
        Self {
            nonce,
            service_name,

            sub_session_key,

            time_bounds,

            ticket,
        }
    }

    pub fn build(self, primary_key: &KdcPrimaryKey) -> Result<KerberosReply, KrbError> {
        let (cname, crealm) = (&self.ticket.client_name).try_into()?;
        let (server_name, server_realm) = (&self.service_name).try_into()?;

        let auth_time = KerberosTime::from_system_time(self.ticket.auth_time)
            .map_err(|_| KrbError::DerEncodeKerberosTime)?;
        let start_time = Some(
            KerberosTime::from_system_time(self.time_bounds.start_time())
                .map_err(|_| KrbError::DerEncodeKerberosTime)?,
        );
        let end_time = KerberosTime::from_system_time(self.time_bounds.end_time())
            .map_err(|_| KrbError::DerEncodeKerberosTime)?;
        let renew_till = Some(
            KerberosTime::from_system_time(self.time_bounds.renew_until())
                .map_err(|_| KrbError::DerEncodeKerberosTime)?,
        );

        let session_key: KdcEncryptionKey = self.ticket.session_key.clone().try_into()?;

        // TGS_REP The ciphertext is encrypted with the sub-session key
        // from the authenticator.
        // If absent, the session key is used (with no kvno).
        // 5.4.2 reads as though the the clients version number is used here for kvno?

        // KeyUsage == 8 for session key, or == 9 for subkey.
        // let enc_part = EncTGSRepPart == EncKDCRepPart;

        let enc_kdc_rep_part = EncKdcRepPart {
            key: session_key.clone(),
            // Not 100% clear on this field.
            last_req: Vec::with_capacity(0),
            nonce: self.nonce,
            key_expiration: None,
            flags: self.ticket.flags,
            auth_time,
            start_time,
            end_time,
            renew_till,
            server_realm,
            server_name,
            client_addresses: None,
            encrypted_pa_data: None,
        };

        let enc_part = if let Some(sub_session_key) = self.sub_session_key {
            sub_session_key.encrypt_tgs_rep_part(enc_kdc_rep_part, true)?
        } else {
            self.ticket
                .session_key
                .encrypt_tgs_rep_part(enc_kdc_rep_part, false)?
        };

        let authorization_data = None;

        let transited = TransitedEncoding {
            tr_type: 1,
            // Since no transit has occured, we record an empty str.
            contents: OctetString::new(*b"").map_err(|_| KrbError::DerEncodeOctetString)?,
        };

        // EncTicketPart
        // Encrypted to the key of the service
        let ticket_inner = EncTicketPart {
            flags: self.ticket.flags,
            key: session_key,
            crealm,
            cname,
            transited,
            auth_time,
            start_time,
            end_time,
            renew_till,
            client_addresses: None,
            authorization_data,
        };

        let ticket_enc_part = primary_key.encrypt_tgs(ticket_inner)?;

        let ticket = EncTicket {
            tkt_vno: 5,
            service: self.service_name,
            enc_part: ticket_enc_part,
        };

        let client_name = self.ticket.client_name;

        Ok(KerberosReply::TGS(TicketGrantReply {
            client_name,
            enc_part,
            ticket,
        }))
    }
}
