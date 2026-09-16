use crate::asn1::checksum::Checksum as Asn1Checksum;
use crate::asn1::OctetString;
use crate::error::KrbError;
use crate::proto::SessionKey;
use crypto_glue::{
    md5,
    der::{asn1::Any, Encode}
};

pub enum ChecksumBuilder {
    //Crc32,
    //RsaMd4,
    //RsaMd4Des,
    //DesMac,
    //DesMacK,
    //RsaMd4DesK,
    RsaMd5,
    //RsaMd5Des,
    HmacSha196Aes256(SessionKey),
}

impl ChecksumBuilder {
    fn value(&self) -> i32 {
        match self {
            //Self::Crc32 => 1,
            //Self::RsaMd4 => 2,
            //Self::RsaMd4Des => 3,
            //Self::DesMac => 4,
            //Self::DesMacK => 5,
            //Self::RsaMd4DesK => 6,
            Self::RsaMd5 => 7,
            //Self::RsaMd5Des => 8,
            Self::HmacSha196Aes256(_) => 16,
        }
    }

    pub(crate) fn compute_kdc_req_body(&self, req_body: &Any) -> Result<Asn1Checksum, KrbError> {
        let req_body = req_body
            .to_der()
            .map_err(|_| KrbError::DerEncodeKdcReqBody)?;

        let checksum = match self {
            Self::RsaMd5 => {
                let digest = md5::compute(req_body.as_slice());
                OctetString::new(digest.as_slice())
            }
            Self::HmacSha196Aes256(k) => {
                let checksum = k.checksum(req_body.as_slice(), 6)?;
                OctetString::new(checksum.as_slice())
            }
        }
        .map_err(|_| KrbError::DerEncodeOctetString)?;
        let checksum = Asn1Checksum {
            checksum_type: self.value(),
            checksum,
        };
        Ok(checksum)
    }
}

impl TryFrom<(i32, Option<SessionKey>)> for ChecksumBuilder {
    type Error = KrbError;

    fn try_from((value, k): (i32, Option<SessionKey>)) -> Result<Self, Self::Error> {
        match value {
            //1 => Err(KrbError::ApInappChecksum),
            //2 => Err(KrbError::ApInappChecksum),
            //3 => Err(KrbError::ApInappChecksum),
            //4 => Err(KrbError::ApInappChecksum),
            //5 => Err(KrbError::ApInappChecksum),
            //6 => Err(KrbError::ApInappChecksum),
            7 => Ok(ChecksumBuilder::RsaMd5),
            //8 => Err(KrbError::ApInappChecksum),
            16 => {
                if let Some(k) = k {
                    Ok(ChecksumBuilder::HmacSha196Aes256(k))
                } else {
                    Err(KrbError::UnsupportedChecksumType)
                }
            }
            _ => Err(KrbError::UnsupportedChecksumType),
        }
    }
}

impl From<SessionKey> for ChecksumBuilder {
    fn from(key: SessionKey) -> Self {
        match key {
            SessionKey::Aes256CtsHmacSha196 { k: _ } => ChecksumBuilder::HmacSha196Aes256(key),
        }
    }
}
