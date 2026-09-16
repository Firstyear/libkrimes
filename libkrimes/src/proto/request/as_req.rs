use crate::asn1::kerberos_flags::KerberosFlags;
use crate::asn1::pa_enc_ts_enc::PaEncTsEnc;
use crate::proto::{DerivedKey, KerberosRequest, KerberosTime, KrbError, PreauthData};
use crate::proto::{EncryptionType, Name, Preauth};
use crypto_glue::rand::{rng, Rng};
use std::time::Duration;
use std::time::SystemTime;
use tracing::trace;

#[derive(Debug)]
pub struct AuthenticationRequest {
    pub nonce: i32,
    pub client_name: Name,
    pub service_name: Name,
    pub from: Option<SystemTime>,
    pub until: SystemTime,
    pub renew: Option<SystemTime>,
    pub preauth: Preauth,
    pub etypes: Vec<EncryptionType>,
    pub kdc_options: KerberosFlags,
}

#[derive(Debug)]
pub struct AuthenticationRequestBuilder {
    client_name: Name,
    service_name: Name,
    from: Option<SystemTime>,
    until: SystemTime,
    renew: Option<SystemTime>,
    preauth: Option<Preauth>,
    etypes: Vec<EncryptionType>,
}

impl AuthenticationRequestBuilder {
    pub fn new(client_name: Name, service_name: Name, until: SystemTime) -> Self {
        let etypes = vec![EncryptionType::AES256_CTS_HMAC_SHA1_96];
        Self {
            client_name,
            service_name,
            from: None,
            until,
            renew: None,
            preauth: None,
            etypes,
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

    pub fn preauth_enc_ts(
        mut self,
        pa_data: &PreauthData,
        epoch_seconds: Duration,
        user_key: &DerivedKey,
    ) -> Result<Self, KrbError> {
        // Major TODO: Can we actually use a reasonable amount of iterations?
        if !pa_data.enc_timestamp {
            return Err(KrbError::PreauthUnsupported);
        }

        // Strip any excess time.
        let usecs = epoch_seconds.subsec_micros();
        let epoch_seconds = Duration::from_secs(epoch_seconds.as_secs());

        let patimestamp = KerberosTime::from_unix_duration(epoch_seconds)
            .map_err(|_| KrbError::PreauthInvalidUnixTs)?;

        let paenctsenc = PaEncTsEnc {
            patimestamp,
            pausec: Some(usecs),
        };

        trace!(?paenctsenc);

        let enc_timestamp = user_key.encrypt_pa_enc_timestamp(&paenctsenc)?;

        // fx cookie always has to be sent.
        let pa_fx_cookie = pa_data.pa_fx_cookie.clone();

        self.preauth = Some(Preauth {
            enc_timestamp: Some(enc_timestamp),
            pa_fx_cookie,
            ..Default::default()
        });

        Ok(self)
    }

    pub fn build(self) -> KerberosRequest {
        let AuthenticationRequestBuilder {
            client_name,
            service_name,
            from,
            until,
            renew,
            preauth,
            etypes,
        } = self;

        // BUG IN MIT KRB5 - If the value is greater than i32 max you get:
        // Jun 28 03:47:41 3e79497ab6b5 krb5kdc[1](Error): ASN.1 value too large - while dispatching (tcp)
        // Heimdal for whatever reason will happily send negative values, so no idea
        // how they get away with it when we don't ....
        let nonce: i32 = rng().random();
        let nonce = nonce.abs();

        let preauth = preauth.unwrap_or_default();

        let mut kdc_options = KerberosFlags::none();
        kdc_options |= KerberosFlags::Renewable;

        KerberosRequest::AS(Box::new(AuthenticationRequest {
            nonce,
            client_name,
            service_name,
            from,
            until,
            renew,
            preauth,
            etypes,
            kdc_options,
        }))
    }
}
