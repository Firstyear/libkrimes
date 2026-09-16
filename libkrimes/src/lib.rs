#![deny(warnings)]
#![warn(unused_extern_crates)]
// Enable some groups of clippy lints.
#![deny(clippy::suspicious)]
#![deny(clippy::perf)]
// Specific lints to enforce.
#![deny(clippy::todo)]
#![allow(clippy::unimplemented)]
#![deny(clippy::unwrap_used)]
// #![warn(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::await_holding_lock)]
#![deny(clippy::needless_pass_by_value)]
#![deny(clippy::trivially_copy_pass_by_ref)]
#![deny(clippy::disallowed_types)]
#![deny(clippy::manual_let_else)]
#![allow(clippy::unreachable)]

mod asn1;
pub mod ccache;
pub(crate) mod cksum;
pub mod cldap;
pub mod client;
pub(crate) mod constants;
pub(crate) mod crypto;
pub mod error;
pub mod keytab;
pub mod proto;

use crate::asn1::{krb_kdc_rep::KrbKdcRep, krb_kdc_req::KrbKdcReq};
use crate::constants::DEFAULT_IO_MAX_SIZE;
use bytes::Buf;
use bytes::BytesMut;
use crypto_glue::der::{Decode, Encode};
use proto::{KerberosReply, KerberosRequest};
use std::io;
use tokio_util::codec::{Decoder, Encoder};

// This is the client codec. Decodes into a KerberosReply, encodes into a KerberosRequest
pub struct KerberosTcpCodec {
    max_size: usize,
}

impl Default for KerberosTcpCodec {
    fn default() -> Self {
        KerberosTcpCodec {
            max_size: DEFAULT_IO_MAX_SIZE,
        }
    }
}

impl Decoder for KerberosTcpCodec {
    type Item = KerberosReply;
    type Error = io::Error;

    fn decode(&mut self, buf: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        // XDR record marking (RFC1831):
        //   A record is composed of one or more fragments. Each fragment has a 32 bit
        //   header where the leftmost bit is a boolean indicating if this is the last
        //   fragment of a record, and next 31 bits are the length of the fragment.
        //
        //   MIT does not set the end-of-record flag, assumes that a KRB PDU fits in a
        //   fragment, i.e, its length is always less that (2**31)-1.
        let mut xdr_hdr: [u8; 4] = [0x00, 0x00, 0x00, 0x00];

        if buf.len() < 4 {
            // We need exactly 4 bytes to proceed.
            return Ok(None);
        }

        let (buf_xdr_hdr, data) = buf.split_at(4);

        xdr_hdr.copy_from_slice(buf_xdr_hdr);

        // Reset end-of-record flag before parsing header into record length
        xdr_hdr[0] &= 0xEF;
        let xdr_record_len = u32::from_be_bytes(xdr_hdr) as usize;

        if xdr_record_len > self.max_size {
            // The requested record size is too large, fail. This prevents
            // denial of service attacks by requesting huge buffers.
            return Err(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "request limit",
            ));
        }

        if data.len() < xdr_record_len {
            // We need more data to proceed, the buffer hasn't filled yet.
            return Ok(None);
        }

        let (xdr_record_buf, _remainder) = data.split_at(xdr_record_len);

        let krb_kdc_rep = KrbKdcRep::from_der(xdr_record_buf)
            .map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidInput, err))?;

        // Now, finally indicate that the buffer can advance, as we have completed
        // our reads.
        buf.advance(4 + xdr_record_len);

        KerberosReply::try_from(krb_kdc_rep)
            .map(Some)
            .map_err(|_err| std::io::Error::new(std::io::ErrorKind::InvalidInput, "data"))
    }
}

impl Encoder<KerberosRequest> for KerberosTcpCodec {
    type Error = io::Error;

    fn encode(&mut self, msg: KerberosRequest, buf: &mut BytesMut) -> Result<(), Self::Error> {
        let req: KrbKdcReq = (&msg)
            .try_into()
            .map_err(|_err| std::io::Error::new(std::io::ErrorKind::InvalidInput, "data"))?;

        let der_bytes = req
            .to_der()
            .map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidInput, err))?;

        // XDR record marking (RFC1831):
        //   A record is composed of one or more fragments. Each fragment has a 32 bit
        //   header where the leftmost bit is a boolean indicating if this is the last
        //   fragment of a record, and next 31 bits are the length of the fragment.
        //
        //   MIT does not set the end-of-record flag, assumes that a KRB PDU fits in a
        //   fragment, i.e, its length is always less that (2**31)-1.
        let d_len = der_bytes.len() as u32;
        let xdr_hdr: [u8; 4] = d_len.to_be_bytes();

        buf.clear();
        buf.extend_from_slice(&xdr_hdr);
        buf.extend_from_slice(&der_bytes);

        Ok(())
    }
}

// This is the server codec. Decodes into a KerberosRequest, encodes into a KerberosReply
pub struct KdcTcpCodec {
    max_size: usize,
}

impl Default for KdcTcpCodec {
    fn default() -> Self {
        KdcTcpCodec {
            max_size: DEFAULT_IO_MAX_SIZE,
        }
    }
}

impl Decoder for KdcTcpCodec {
    type Item = KerberosRequest;
    type Error = io::Error;

    fn decode(&mut self, buf: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        // XDR record marking (RFC1831):
        //   A record is composed of one or more fragments. Each fragment has a 32 bit
        //   header where the leftmost bit is a boolean indicating if this is the last
        //   fragment of a record, and next 31 bits are the length of the fragment.
        //
        //   MIT does not set the end-of-record flag, assumes that a KRB PDU fits in a
        //   fragment, i.e, its length is always less that (2**31)-1.
        let mut xdr_hdr: [u8; 4] = [0x00, 0x00, 0x00, 0x00];

        if buf.len() < 4 {
            // We need exactly 4 bytes to proceed.
            return Ok(None);
        }

        let (buf_xdr_hdr, data) = buf.split_at(4);

        xdr_hdr.copy_from_slice(buf_xdr_hdr);

        // Reset end-of-record flag before parsing header into record length
        xdr_hdr[0] &= 0xEF;
        let xdr_record_len = u32::from_be_bytes(xdr_hdr) as usize;

        if xdr_record_len > self.max_size {
            // The requested record size is too large, fail. This prevents
            // denial of service attacks by requesting huge buffers.
            return Err(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "request limit",
            ));
        }

        if data.len() < xdr_record_len {
            // We need more data to proceed, the buffer hasn't filled yet.
            return Ok(None);
        }

        let (xdr_record_buf, _remainder) = data.split_at(xdr_record_len);

        let krb_kdc_rep = KrbKdcReq::from_der(xdr_record_buf)
            .map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidInput, err))?;

        // Now, finally indicate that the buffer can advance, as we have completed
        // our reads.
        buf.advance(4 + xdr_record_len);

        KerberosRequest::try_from(krb_kdc_rep)
            .map(Some)
            .map_err(|_err| std::io::Error::new(std::io::ErrorKind::InvalidInput, "data"))
    }
}

impl Encoder<KerberosReply> for KdcTcpCodec {
    type Error = io::Error;

    fn encode(&mut self, msg: KerberosReply, buf: &mut BytesMut) -> io::Result<()> {
        let krb_kdc_rep: KrbKdcRep = msg
            .try_into()
            .map_err(|_err| std::io::Error::new(std::io::ErrorKind::InvalidInput, "data"))?;

        let der_bytes = krb_kdc_rep
            .to_der()
            .map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidInput, err))?;

        // XDR record marking (RFC1831):
        //   A record is composed of one or more fragments. Each fragment has a 32 bit
        //   header where the leftmost bit is a boolean indicating if this is the last
        //   fragment of a record, and next 31 bits are the length of the fragment.
        //
        //   MIT does not set the end-of-record flag, assumes that a KRB PDU fits in a
        //   fragment, i.e, its length is always less that (2**31)-1.

        let d_len = der_bytes.len() as u32;
        let xdr_hdr: [u8; 4] = d_len.to_be_bytes();

        buf.clear();
        buf.extend_from_slice(&xdr_hdr);
        buf.extend_from_slice(&der_bytes);

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::KerberosReply;
    use futures::SinkExt;
    use tokio::net::TcpStream;
    use tokio_util::codec::Framed;

    use std::time::{Duration, SystemTime};

    use super::KerberosTcpCodec;
    use crate::proto::{AuthenticationReply, DerivedKey, KerberosRequest, Name, PreauthErrorReply};
    use futures::StreamExt;
    use tracing::{trace, warn};

    #[tokio::test]
    async fn test_localhost_kdc_no_preauth() {
        let _ = tracing_subscriber::fmt::try_init();

        if std::env::var("CI").is_ok() {
            // Skip this test in CI, as it requires a KDC running on localhost
            warn!("Skipping test_localhost_kdc_no_preauth in CI");
            return;
        }

        let kdc_addr = option_env!("LIBKRIMES_TEST_KDC_ADDRESS").unwrap_or("127.0.0.1:55000");

        let stream = TcpStream::connect(kdc_addr)
            .await
            .expect("Unable to connect to kdc");

        let mut krb_stream = Framed::new(stream, KerberosTcpCodec::default());

        let now = SystemTime::now();
        let client_name = Name::principal("testuser", "EXAMPLE.COM");
        let as_req = KerberosRequest::as_builder(
            &client_name,
            Name::service_krbtgt("EXAMPLE.COM"),
            now + Duration::from_secs(3600),
        )
        .renew_until(Some(now + Duration::from_secs(86400 * 7)))
        .build();

        // Write a request
        krb_stream
            .send(as_req)
            .await
            .expect("Failed to transmit request");

        let response = krb_stream.next().await;

        let (ticket, cleartext) = match response {
            Some(Ok(KerberosReply::AS(AuthenticationReply {
                name,
                enc_part,
                pa_data,
                ticket,
            }))) => {
                assert_eq!(name, client_name);

                let etype_info = pa_data
                    .as_ref()
                    .map(|pa_inner| pa_inner.etype_info2.as_slice());

                let base_key = DerivedKey::from_encrypted_reply(
                    &enc_part,
                    etype_info,
                    "EXAMPLE.COM",
                    "testuser",
                    "password",
                    1,
                )
                .expect("Failed to derive base key");

                (
                    ticket,
                    enc_part
                        .decrypt_enc_kdc_rep(&base_key)
                        .expect("Failed to decrypt"),
                )
            }
            _ => unreachable!(),
        };

        // MIT expects UDP over TCP...
        let stream = TcpStream::connect(kdc_addr)
            .await
            .expect("Unable to connect to kdc");

        let mut krb_stream = Framed::new(stream, KerberosTcpCodec::default());

        let session_key = cleartext.key;

        let now = SystemTime::now();
        let tgs_req = KerberosRequest::tgs_builder(
            Name::service("host", "pepper.example.com", "EXAMPLE.COM"),
            now,
            now + Duration::from_secs(3600),
        )
        .renew_until(Some(now + Duration::from_secs(86400 * 7)))
        .preauth_ap_req(&client_name, &ticket, &session_key)
        .expect("Failed to build PREAUTH-AP-REQ")
        .build()
        .expect("Failed to build AP-REQ");

        krb_stream
            .send(tgs_req)
            .await
            .expect("Failed to transmit request");
        let response = krb_stream.next().await;
        match response {
            Some(Ok(KerberosReply::TGS(_))) => {}
            _ => unreachable!(),
        };
    }

    #[tokio::test]
    async fn test_localhost_kdc_preauth() {
        let _ = tracing_subscriber::fmt::try_init();

        if std::env::var("CI").is_ok() {
            // Skip this test in CI, as it requires a KDC running on localhost
            warn!("Skipping test_localhost_kdc_preauth in CI");
            return;
        }

        let kdc_addr = option_env!("LIBKRIMES_TEST_KDC_ADDRESS").unwrap_or("127.0.0.1:55000");

        let stream = TcpStream::connect(kdc_addr)
            .await
            .expect("Unable to connect to kdc");

        let mut krb_stream = Framed::new(stream, KerberosTcpCodec::default());

        let now = SystemTime::now();

        let client_name = Name::principal("testuser_preauth", "EXAMPLE.COM");
        let as_req = KerberosRequest::as_builder(
            &client_name,
            Name::service_krbtgt("EXAMPLE.COM"),
            now + Duration::from_secs(3600),
        )
        .renew_until(Some(now + Duration::from_secs(86400 * 7)))
        .build();

        // Write a request
        krb_stream
            .send(as_req)
            .await
            .expect("Failed to transmit request");

        let response = krb_stream.next().await;

        trace!(?response);
        assert!(response.is_some());
        let response = response.unwrap();
        assert!(response.is_ok());
        let response = response.unwrap();

        let KerberosReply::PA(PreauthErrorReply {
            service,
            pa_data,
            stime: _,
        }) = response
        else {
            unreachable!()
        };
        // The PA-ENC-TIMESTAMP method MUST be supported by
        // clients, but whether it is enabled by default MAY be determined on
        // a realm-by-realm basis.
        // If the method is not used in the initial request and the error
        // KDC_ERR_PREAUTH_REQUIRED is returned specifying PA-ENC-TIMESTAMP
        // as an acceptable method, the client SHOULD retry the initial
        // request using the PA-ENC-TIMESTAMP pre- authentication method.
        //
        // The ETYPE-INFO2 method MUST be supported; this method is used to
        // communicate the set of supported encryption types, and
        // corresponding salt and string to key parameters.

        // Assert returned preauth data contains PA-ENC-TIMESTAMP and PA-ETYPE-INFO2
        assert!(pa_data.enc_timestamp);

        // Assert returned preauth data contains PA-ETYPE-INFO2
        assert!(!pa_data.etype_info2.is_empty());

        // This gets the highest encryption strength item.
        let einfo2 = pa_data.etype_info2.last().unwrap();

        assert_eq!(service, Name::service_krbtgt("EXAMPLE.COM"));

        // Compute the pre-authentication.
        let base_key =
            DerivedKey::from_etype_info2(einfo2, "EXAMPLE.COM", "testuser_preauth", "password", 1)
                .expect("Failed to derive user key");

        let now = SystemTime::now();
        let seconds_since_epoch = now
            .duration_since(SystemTime::UNIX_EPOCH)
            .expect("Failed to convert value");

        let client_name = Name::principal("testuser_preauth", "EXAMPLE.COM");
        let as_req = KerberosRequest::as_builder(
            &client_name,
            Name::service_krbtgt("EXAMPLE.COM"),
            now + Duration::from_secs(3600),
        )
        .renew_until(Some(now + Duration::from_secs(86400 * 7)))
        .preauth_enc_ts(&pa_data, seconds_since_epoch, &base_key)
        .map(|b| b.build())
        .expect("Unable to build as req");

        /*
        let pre_auth = pa_rep
            .perform_enc_timestamp(
                password,
                "EXAMPLE.COM",
                "testuser_preauth",
                seconds_since_epoch,
            )
            .unwrap();

        let as_req = KerberosRequest::as_builder(
            Name::principal("testuser_preauth", "EXAMPLE.COM"),
            Name::service_krbtgt("EXAMPLE.COM"),
            None,
            now + Duration::from_secs(3600),
            Some(now + Duration::from_secs(86400 * 7)),
        )
        .add_preauthentication(pre_auth)
        .build();
        */

        // Now, because MIT KRB is *silly* we have to re-open the connection. Because apparently
        // the MIT KRB TCP transport is just "lets pretend to be UDP with with TCP" instead of
        // doing something sensible. I can only imagine that KKDCP also does similar ... sillyness.

        let stream = TcpStream::connect(kdc_addr)
            .await
            .expect("Unable to connect to kdc");

        let mut krb_stream = Framed::new(stream, KerberosTcpCodec::default());

        // Write a request
        krb_stream
            .send(as_req)
            .await
            .expect("Failed to transmit request");

        let response = krb_stream
            .next()
            .await
            .expect("failed to run response")
            .expect("failed to get response");

        trace!(?response);
        assert!(matches!(response, KerberosReply::AS(_)));
    }
}
