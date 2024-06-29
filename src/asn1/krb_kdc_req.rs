use super::kdc_req::KdcReq;
use der::{Tag, TagNumber, Writer};

/// ```text
/// AS-REQ          ::= [APPLICATION 10] KDC-REQ
/// TGS-REQ         ::= [APPLICATION 12] KDC-REQ
/// ```
#[derive(Debug, Eq, PartialEq)]
pub(crate) enum KrbKdcReq {
    AsReq(KdcReq),
    TgsReq(KdcReq),
}

impl<'a> ::der::Decode<'a> for KrbKdcReq {
    fn decode<R: der::Reader<'a>>(decoder: &mut R) -> der::Result<Self> {
        let tag: der::Tag = decoder.decode()?;
        let _len: der::Length = decoder.decode()?;

        match tag {
            Tag::Application {
                constructed: true,
                number: TagNumber::N10,
            } => {
                let kdc_req: KdcReq = decoder.decode()?;
                Ok(KrbKdcReq::AsReq(kdc_req))
            }
            Tag::Application {
                constructed: true,
                number: TagNumber::N12,
            } => {
                let kdc_req: KdcReq = decoder.decode()?;
                Ok(KrbKdcReq::TgsReq(kdc_req))
            }
            _ => Err(der::Error::from(der::ErrorKind::TagUnexpected {
                expected: None,
                actual: tag,
            })),
        }
    }
}

impl ::der::Encode for KrbKdcReq {
    fn encoded_len(&self) -> Result<der::Length, der::Error> {
        tracing::trace!(?self);
        let len: der::Length = match self {
            KrbKdcReq::AsReq(asreq) => {
                let tag_len = Tag::Application {
                    constructed: true,
                    number: TagNumber::N10,
                }
                .encoded_len()?;

                let as_req_len = asreq.encoded_len()?;
                let as_req_len_len = as_req_len.encoded_len()?;

                tracing::trace!(?tag_len, ?as_req_len, ?as_req_len_len);

                tag_len + as_req_len + as_req_len_len
            }
            KrbKdcReq::TgsReq(tgsreq) => {
                let tag_len = Tag::Application {
                    constructed: true,
                    number: TagNumber::N12,
                }
                .encoded_len()?;

                let tgs_req_len = tgsreq.encoded_len()?;
                let tgs_req_len_len = tgs_req_len.encoded_len()?;

                tracing::trace!(?tag_len, ?tgs_req_len, ?tgs_req_len_len);

                tag_len + tgs_req_len + tgs_req_len_len
            }
        }?;
        Ok(len)
    }

    fn encode(&self, writer: &mut impl Writer) -> der::Result<()> {
        match self {
            KrbKdcReq::AsReq(asreq) => {
                Tag::Application {
                    constructed: true,
                    number: TagNumber::N10,
                }
                .encode(writer)?;
                asreq.encoded_len()?.encode(writer)?;
                asreq.encode(writer)
            }
            KrbKdcReq::TgsReq(tgsreq) => {
                Tag::Application {
                    constructed: true,
                    number: TagNumber::N12,
                }
                .encode(writer)?;
                tgsreq.encoded_len()?.encode(writer)?;
                tgsreq.encode(writer)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::asn1::constants::{EncryptionType, KrbMessageType, PaDataType};
    use crate::asn1::kdc_req::KdcReq;
    use crate::asn1::kerberos_flags::KerberosFlags;
    use crate::asn1::kerberos_time::KerberosTime;
    use crate::asn1::krb_kdc_req::KrbKdcReq;
    use core::iter::zip;
    use der::asn1::OctetString;
    use der::flagset::FlagSet;
    use der::DateTime;
    use der::Decode;

    struct TestPaData {
        padata_type: u32,
        padata_value: Vec<u8>,
    }

    struct TestAsReq {
        blob: String,
        principal: String,
        realm: String,
        padata: Vec<TestPaData>,
        kdc_options: FlagSet<KerberosFlags>,
        from: Option<KerberosTime>,
        till: KerberosTime,
        rtime: Option<KerberosTime>,
        nonce: u32,
        etype: Vec<i32>,
        addresses: Option<Vec<(i32, OctetString)>>,
    }

    fn verify_as_req(asreq: &KdcReq, tasreq: &TestAsReq) {
        assert_eq!(asreq.pvno, 5);
        assert_eq!(asreq.msg_type, KrbMessageType::KrbAsReq.into());

        let pa = asreq.padata.as_ref().unwrap();
        assert_eq!(pa.len(), tasreq.padata.len());
        let iter = zip(pa, &tasreq.padata);
        for (pa, tpa) in iter {
            assert_eq!(pa.padata_type, tpa.padata_type);
            assert_eq!(pa.padata_value.as_bytes(), tpa.padata_value);
        }

        // let bits = asreq.req_body.kdc_options;
        // assert_eq!(bits, tasreq.kdc_options);
        // Temporarily commented out.
        assert!(false);

        let ref cname = &asreq.req_body.cname.as_ref().unwrap();
        assert_eq!(cname.name_type, 1);
        assert_eq!(cname.name_string[0].0.to_string(), tasreq.principal);

        assert_eq!(asreq.req_body.realm.0.to_string(), tasreq.realm);

        let ref sname = &asreq.req_body.sname.as_ref().unwrap();
        assert_eq!(sname.name_type, 2);
        assert_eq!(sname.name_string[0].0.to_string(), "krbtgt");
        assert_eq!(sname.name_string[1].0.to_string(), tasreq.realm);

        if let Some(trtime) = tasreq.rtime {
            let rtime = asreq.req_body.rtime.expect("rtime must be there");
            assert_eq!(rtime, trtime);
        } else {
            assert!(asreq.req_body.rtime.is_none());
        }

        assert_eq!(asreq.req_body.till, tasreq.till);

        if let Some(tfrom) = tasreq.from {
            let from = asreq.req_body.from.expect("from must be there");
            assert_eq!(from, tfrom);
        } else {
            assert!(asreq.req_body.from.is_none());
        }

        assert_eq!(asreq.req_body.nonce, tasreq.nonce);
        assert_eq!(asreq.req_body.etype, tasreq.etype);

        if let Some(taddrs) = &tasreq.addresses {
            let addrs = asreq
                .req_body
                .addresses
                .as_ref()
                .expect("addresses must be there");
            assert_eq!(addrs.len(), taddrs.len());

            let iter = zip(addrs, taddrs);
            for (addr, taddr) in iter {
                assert_eq!(addr.addr_type, taddr.0);
                assert_eq!(addr.address, taddr.1);
            }
        } else {
            assert!(asreq.req_body.addresses.is_none());
        }
    }

    #[test]
    fn krb_kdc_req_parse() {
        let samples: Vec<TestAsReq> = vec![
            TestAsReq {
                blob: "6a81b23081afa103020105a20302010aa31a3018300aa10402020096a2020400300aa10402020095a2020400a48186308183a00703050000000010a1143012a003020101a10b30091b0777696c6c69616da20b1b094b4b4443502e444556a31e301ca003020102a11530131b066b72627467741b094b4b4443502e444556a511180f32303234303431373034313534395aa70602047fbda7aea81a301802011202011102011402011302011002011702011902011a".to_string(),
                principal: "william".to_string(),
                realm: "KKDCP.DEV".to_string(),
                padata: vec![
                    TestPaData {
                        padata_type: PaDataType::PadataAsFreshness as u32,
                        padata_value: vec![],
                    },
                    TestPaData {
                        padata_type: PaDataType::EncpadataReqEncPaRep as u32,
                        padata_value: vec![],
                    }
                ],
                kdc_options: KerberosFlags::RenewableOk.into(),
                from: None,
                till: KerberosTime::from_date_time(DateTime::new(2024, 04, 17, 04, 15, 49).expect("Failed to build DateTime")),
                rtime: None,
                nonce: 2143135662,
                etype: vec![
                    EncryptionType::AES256_CTS_HMAC_SHA1_96 as i32,
                    EncryptionType::AES128_CTS_HMAC_SHA1_96 as i32,
                    EncryptionType::AES256_CTS_HMAC_SHA384_192 as i32,
                    EncryptionType::AES128_CTS_HMAC_SHA256_128 as i32,
                    EncryptionType::DES3_CBC_SHA1_KD as i32,
                    EncryptionType::RC4_HMAC as i32,
                    EncryptionType::CAMELLIA128_CTS_CMAC as i32,
                    EncryptionType::CAMELLIA256_CTS_CMAC as i32,
                ],
                addresses: None,
            },
            TestAsReq {
                blob: "6a81ff3081fca103020105a20302010aa32d302b300aa10402020096a2020400300aa10402020095a20204003011a10402020080a20904073005a0030101ffa481c03081bda00703050050010010a1123010a003020101a10930071b057573657231a20c1b0a41464f524553542e4144a31f301da003020102a11630141b066b72627467741b0a41464f524553542e4144a511180f32303234303631323134353130395aa7060204586155dda814301202011402011302011202011102011a020119a93e303c300da003020102a1060404c0a80164300da003020102a1060404ac110001300da003020102a1060404c0a86501300da003020102a10604040a95d65a".to_string(),
                principal: "user1".to_string(),
                realm: "AFOREST.AD".to_string(),
                padata: vec![
                    TestPaData {
                        padata_type: PaDataType::PadataAsFreshness as u32,
                        padata_value: vec![],
                    },
                    TestPaData {
                        padata_type: PaDataType::EncpadataReqEncPaRep as u32,
                        padata_value: vec![],
                    },
                    TestPaData {
                        padata_type: PaDataType::PaPacRequest as u32,
                        padata_value: vec![0x30, 0x05, 0xa0, 0x03, 0x01, 0x01, 0xff],
                    }
                ],
                kdc_options: KerberosFlags::RenewableOk | KerberosFlags::Forwardable | KerberosFlags::Canonicalize | KerberosFlags::Proxiable,
                from: None,
                till: KerberosTime::from_date_time(DateTime::new(2024, 06, 12, 14, 51, 09).expect("Failed to build DateTime")),
                rtime: None,
                nonce: 1482773981,
                etype: vec![
                    EncryptionType::AES256_CTS_HMAC_SHA384_192 as i32,
                    EncryptionType::AES128_CTS_HMAC_SHA256_128 as i32,
                    EncryptionType::AES256_CTS_HMAC_SHA1_96 as i32,
                    EncryptionType::AES128_CTS_HMAC_SHA1_96 as i32,
                    EncryptionType::CAMELLIA256_CTS_CMAC as i32,
                    EncryptionType::CAMELLIA128_CTS_CMAC as i32,
                ],
                addresses: Some(vec![
                    (2, OctetString::new(vec![0xc0, 0xa8, 0x01, 0x64]).expect("Failed to build octet string")),
                    (2, OctetString::new(vec![0xAC, 0x11, 0x00, 0x01]).expect("Failed to build octet string")),
                    (2, OctetString::new(vec![0xC0, 0xA8, 0x65, 0x01]).expect("Failed to build octet string")),
                    (2, OctetString::new(vec![0x0A, 0x95, 0xD6, 0x5A]).expect("Failed to build octet string"))
                ]),
            },
            TestAsReq {
                blob: "6a81ca3081c7a103020105a20302010aa31a3018300aa10402020096a2020400300aa10402020095a2020400a4819e30819ba00703050000800000a1153013a003020101a10c300a1b087465737475736572a20d1b0b4558414d504c452e434f4da320301ea003020102a11730151b066b72627467741b0b4558414d504c452e434f4da511180f32303234303631363035323730315aa611180f32303234303632323035323730315aa70602042e71de55a81a301802011202011102011402011302011002011702011902011a".to_string(),
                principal: "testuser".to_string(),
                realm: "EXAMPLE.COM".to_string(),
                padata: vec![
                    TestPaData {
                        padata_type: PaDataType::PadataAsFreshness as u32,
                        padata_value: vec![],
                    },
                    TestPaData {
                        padata_type: PaDataType::EncpadataReqEncPaRep as u32,
                        padata_value: vec![],
                    }
                ],
                kdc_options: KerberosFlags::Renewable.into(),
                from: None,
                till: KerberosTime::from_date_time(DateTime::new(2024, 06, 16, 05, 27, 01).expect("Failed to build DateTime")),
                rtime: Some(KerberosTime::from_date_time(DateTime::new(2024, 06, 22, 05, 27, 01).expect("Failed to build DateTime"))),
                nonce: 779214421,
                etype: vec![
                    EncryptionType::AES256_CTS_HMAC_SHA1_96 as i32,
                    EncryptionType::AES128_CTS_HMAC_SHA1_96 as i32,
                    EncryptionType::AES256_CTS_HMAC_SHA384_192 as i32,
                    EncryptionType::AES128_CTS_HMAC_SHA256_128 as i32,
                    EncryptionType::DES3_CBC_SHA1_KD as i32,
                    EncryptionType::RC4_HMAC as i32,
                    EncryptionType::CAMELLIA128_CTS_CMAC as i32,
                    EncryptionType::CAMELLIA256_CTS_CMAC as i32,
                ],
                addresses: None,
            }
        ];

        for sample in samples {
            let blob = hex::decode(&sample.blob).expect("Failed to decode sample");
            let message = KrbKdcReq::from_der(&blob).expect("Failed to decode");
            match message {
                KrbKdcReq::AsReq(asreq) => verify_as_req(&asreq, &sample),
                KrbKdcReq::TgsReq(_) => todo!(),
            }
        }
    }
}
