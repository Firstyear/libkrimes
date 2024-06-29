// #![deny(warnings)]

#![warn(unused_extern_crates)]
// Enable some groups of clippy lints.
#![deny(clippy::suspicious)]
#![deny(clippy::perf)]
// Specific lints to enforce.
#![deny(clippy::todo)]
#![deny(clippy::unimplemented)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::await_holding_lock)]
#![deny(clippy::needless_pass_by_value)]
#![deny(clippy::trivially_copy_pass_by_ref)]
#![deny(clippy::disallowed_types)]
#![deny(clippy::manual_let_else)]
#![allow(clippy::unreachable)]

mod asn1;
pub(crate) mod constants;
pub(crate) mod crypto;
pub mod error;
pub mod proto;

use bytes::Buf;
use bytes::BufMut;
use bytes::BytesMut;
use der::Decode;
use proto::KerberosResponse;
use std::io::{self};
use tokio_util::codec::{Decoder, Encoder};
use xdr_codec::record::XdrRecordReader;
use xdr_codec::record::XdrRecordWriter;
use xdr_codec::Write;

use crate::constants::DEFAULT_IO_MAX_SIZE;
use crate::proto::KerberosRequest;

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
    type Item = KerberosResponse;
    type Error = io::Error;

    fn decode(&mut self, buf: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        let reader = buf.reader();
        let mut xdr_reader = XdrRecordReader::new(reader);
        xdr_reader.set_implicit_eor(true);

        let record = xdr_reader.into_iter().next();

        let record: Vec<u8> = match record {
            None => {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "XDR reader returned EOF",
                ))
            }
            Some(rr) => match rr {
                Err(x) => return Err(x),
                Ok(buf) => buf,
            },
        };

        let rep = KerberosResponse::from_der(&record)
            .map_err(|x| io::Error::new(io::ErrorKind::InvalidData, x.to_string()))
            .expect("Failed to decode");

        // buf.clear();

        Ok(Some(rep))
    }
}

impl Encoder<KerberosRequest> for KerberosTcpCodec {
    type Error = io::Error;

    fn encode(&mut self, msg: KerberosRequest, buf: &mut BytesMut) -> io::Result<()> {
        debug_assert!(buf.is_empty());

        let der_bytes = msg
            .to_der()
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;

        debug_assert!(buf.len() <= self.max_size);

        /* RFC1831 section 10
        *
        * When RPC messages are passed on top of a byte stream transport
        * protocol (like TCP), it is necessary to delimit one message from
        * another in order to detect and possibly recover from protocol errors.
        * This is called record marking (RM).  One RPC message fits into one RM
        * record.

        * A record is composed of one or more record fragments.  A record
        * fragment is a four-byte header followed by 0 to (2**31) - 1 bytes of
        * fragment data.  The bytes encode an unsigned binary number; as with
        * XDR integers, the byte order is from highest to lowest.  The number
        * encodes two values -- a boolean which indicates whether the fragment
        * is the last fragment of the record (bit value 1 implies the fragment
        * is the last fragment) and a 31-bit unsigned binary value which is the
        * length in bytes of the fragment's data.  The boolean value is the
        * highest-order bit of the header; the length is the 31 low-order bits.
        * (Note that this record specification is NOT in XDR standard form!)
        */

        // Something is certainly wrong here with the xdr writer, as doing it by
        // hand works. given how simple xdr is, maybe we just take this approach?

        /*
        // buf.resize(der_bytes.len() + 4, 0);
        let mut w = XdrRecordWriter::new(buf.writer());
        w.set_implicit_eor(true);
        w.write_all(&der_bytes)
        */

        let d_len = der_bytes.len() as u32;
        let d_len_bytes = d_len.to_be_bytes();
        buf.clear();
        buf.extend_from_slice(&d_len_bytes);
        buf.extend_from_slice(&der_bytes);

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::KerberosResponse;
    use futures::SinkExt;
    use tokio::net::TcpStream;
    use tokio_util::codec::Framed;

    use std::time::{Duration, SystemTime};

    use super::KerberosTcpCodec;
    use crate::asn1::constants::errors::KrbErrorCode;
    use crate::asn1::constants::PaDataType;
    use crate::proto::KerberosRequest;
    use futures::StreamExt;
    use tracing::trace;

    #[tokio::test]
    async fn test_localhost_kdc_no_preauth() {
        let _ = tracing_subscriber::fmt::try_init();

        let stream = TcpStream::connect("127.0.0.1:55000")
            .await
            .expect("Unable to connect to localhost:55000");

        let mut krb_stream = Framed::new(stream, KerberosTcpCodec::default());

        let as_req = KerberosRequest::build_asreq(
            "testuser".to_string(),
            "krbtgt".to_string(),
            None,
            SystemTime::now() + Duration::from_secs(3600),
            None,
        )
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
        let asrep = match response {
            KerberosResponse::AsRep(asrep) => asrep,
            _ => unreachable!(),
        };

        let base_key = asrep
            .enc_part
            .derive_key(b"password", b"EXAMPLE.COM", b"testuser")
            .unwrap();

        // RFC 4120 The key usage value for encrypting this field is 3 in an AS-REP
        // message, using the client's long-term key or another key selected
        // via pre-authentication mechanisms.
        let cleartext = asrep.enc_part.decrypt_data(&base_key, 3).unwrap();
    }

    #[tokio::test]
    async fn test_localhost_kdc_preauth() {
        let _ = tracing_subscriber::fmt::try_init();

        let stream = TcpStream::connect("127.0.0.1:55000")
            .await
            .expect("Unable to connect to localhost:55000");

        let mut krb_stream = Framed::new(stream, KerberosTcpCodec::default());

        let now = SystemTime::now();

        let as_req = KerberosRequest::build_asreq(
            "testuser_preauth".to_string(),
            "krbtgt".to_string(),
            None,
            now + Duration::from_secs(3600),
            Some(now + Duration::from_secs(86400)),
        )
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
        let pa_rep = match response {
            KerberosResponse::PaRep(pa_rep) => pa_rep,
            _ => unreachable!(),
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
        assert!(pa_rep.enc_timestamp);

        // Assert returned preauth data contains PA-ETYPE-INFO2
        assert!(!pa_rep.etype_info2.is_empty());

        // Compute the pre-authentication.
        let now = SystemTime::now();
        let password = "password";
        let seconds_since_epoch = now.duration_since(SystemTime::UNIX_EPOCH).unwrap();

        let pre_auth = pa_rep
            .perform_enc_timestamp(
                password,
                "EXAMPLE.COM",
                "testuser_preauth",
                seconds_since_epoch,
            )
            .unwrap();

        let as_req = KerberosRequest::build_asreq(
            "testuser_preauth".to_string(),
            "krbtgt".to_string(),
            None,
            now + Duration::from_secs(3600),
            Some(now + Duration::from_secs(86400)),
        )
        .add_preauthentication(pre_auth)
        .build();

        // Write a request
        krb_stream
            .send(as_req)
            .await
            .expect("Failed to transmit request");

        let response = krb_stream.next().await;

        trace!(?response);
    }
}
