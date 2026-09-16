#![allow(unused_assignments)]
use crate::asn1::constants::encryption_types::EncryptionType;
use crate::asn1::constants::PrincipalNameType;
use crate::error::KrbError;
use crate::keytab::{Keytab, KeytabEntry};
use crate::proto::{DerivedKey, Name};
use binrw::helpers::until_eof;
use binrw::io::{SeekFrom, TakeSeekExt};
use binrw::BinReaderExt;
use binrw::{binread, binwrite, BinWrite};
use crypto_glue::aes256;
use std::fmt;
use std::fs::File;
use std::io::Read;
use tracing::error;

#[binwrite]
#[brw(big)]
#[binread]
#[derive(Debug, Clone, PartialEq, Eq)]
struct Data {
    #[br(temp)]
    #[bw(try_calc(u16::try_from(value.len())))]
    value_len: u16,
    #[br(count = value_len)]
    value: Vec<u8>,
}

#[binwrite]
#[brw(big)]
#[derive(Clone, PartialEq, Eq)]
#[binread]
#[br(import { version: u8 })]
struct Principal {
    #[br(temp)]
    #[bw(try_calc(u16::try_from(components.len())))]
    components_count: u16,
    realm: Data,
    // components includes the realm in version 1
    #[br(count = if version == 1 { components_count - 1 } else { components_count })]
    components: Vec<Data>,
    #[br(if(version > 1))]
    name_type: Option<u32>,
}

impl fmt::Debug for Principal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let c: Vec<_> = self
            .components
            .iter()
            .map(|x| String::from_utf8_lossy(x.value.as_slice()))
            .collect();
        let r = String::from_utf8_lossy(self.realm.value.as_slice());
        f.debug_struct("Principal")
            .field("components", &c)
            .field("realm", &r)
            .finish()
    }
}

impl From<Name> for Principal {
    fn from(value: Name) -> Self {
        match value {
            Name::Principal { name, realm } => Principal {
                realm: Data {
                    value: realm.as_bytes().to_vec(),
                },
                components: vec![Data {
                    value: name.as_bytes().to_vec(),
                }],
                name_type: Some(PrincipalNameType::NtPrincipal as u32),
            },
            Name::SrvPrincipal {
                service,
                host,
                realm,
            } => Principal {
                realm: Data {
                    value: realm.as_bytes().to_vec(),
                },
                components: vec![
                    Data {
                        value: service.as_bytes().to_vec(),
                    },
                    Data {
                        value: host.as_bytes().to_vec(),
                    },
                ],
                name_type: Some(PrincipalNameType::NtSrvInst as u32),
            },
            Name::SrvInst {
                service,
                instance,
                realm,
            } => {
                let mut c: Vec<Data> = vec![Data {
                    value: service.as_bytes().to_vec(),
                }];
                c.extend(instance.iter().map(|x| Data {
                    value: x.as_bytes().to_vec(),
                }));
                Principal {
                    realm: Data {
                        value: realm.as_bytes().to_vec(),
                    },
                    components: c,
                    name_type: Some(PrincipalNameType::NtSrvInst as u32),
                }
            }
            Name::SrvHst {
                service,
                host,
                realm,
            } => Principal {
                realm: Data {
                    value: realm.as_bytes().to_vec(),
                },
                components: vec![
                    Data {
                        value: service.as_bytes().to_vec(),
                    },
                    Data {
                        value: host.as_bytes().to_vec(),
                    },
                ],
                name_type: Some(PrincipalNameType::NtSrvHst as u32),
            },
        }
    }
}

impl TryFrom<&Principal> for Name {
    type Error = KrbError;

    fn try_from(value: &Principal) -> Result<Self, Self::Error> {
        match value.name_type {
            Some(1 /* PrincipalNameType::NtPrincipal */) => {
                let realm = String::from_utf8_lossy(&value.realm.value).to_string();
                let name = &value
                    .components
                    .first()
                    .ok_or(KrbError::PrincipalNameInvalidType)?
                    .value;
                let name = String::from_utf8_lossy(name).to_string();
                Ok(Name::Principal { name, realm })
            }
            Some(2 /* PrincipalNameType::NtSrvInst */) => {
                let realm = String::from_utf8_lossy(&value.realm.value).to_string();
                let service = &value
                    .components
                    .first()
                    .ok_or(KrbError::PrincipalNameInvalidType)?
                    .value;
                let service = String::from_utf8_lossy(service).to_string();

                let host = &value
                    .components
                    .get(1)
                    .ok_or(KrbError::PrincipalNameInvalidType)?
                    .value;
                let host = String::from_utf8_lossy(host).to_string();

                Ok(Name::SrvPrincipal {
                    service,
                    host,
                    realm,
                })
            }
            Some(3 /* PrincipalNameType::NtSrvHst */) => {
                let realm = String::from_utf8_lossy(&value.realm.value).to_string();
                let service = &value
                    .components
                    .first()
                    .ok_or(KrbError::PrincipalNameInvalidType)?
                    .value;
                let service = String::from_utf8_lossy(service).to_string();

                let host = &value
                    .components
                    .get(1)
                    .ok_or(KrbError::PrincipalNameInvalidType)?
                    .value;
                let host = String::from_utf8_lossy(host).to_string();

                Ok(Name::SrvHst {
                    service,
                    host,
                    realm,
                })
            }
            _ => Err(KrbError::PrincipalNameInvalidType),
        }
    }
}

#[binwrite]
#[brw(big)]
#[derive(Debug, Clone, PartialEq, Eq)]
#[binread]
#[br(import { version: u8, rlen: i32 })]
enum RecordData {
    #[br(pre_assert(rlen > 0))]
    Entry {
        #[br(args { version })]
        principal: Principal,
        timestamp: u32,
        key_version_u8: u8,
        enctype: u16,
        key: Data,
        // Only if 4 bytes remaining in the stream (field present from version 1.14)
        #[br(try)]
        key_version_u32: Option<u32>,
    },
    // A negative record length represents a "hole" in the file, it is, an entry that has
    // been invalidated. The length of the hole is the inverse of the record length.
    #[br(pre_assert(rlen <= 0))]
    Hole {
        #[br(count = rlen.abs())]
        pad: Vec<u8>,
    },
}

impl From<&KeytabEntry> for RecordData {
    fn from(value: &KeytabEntry) -> Self {
        let (kvno, enc_type) = match value.key {
            DerivedKey::Aes256CtsHmacSha196 {
                k: _,
                i: _,
                s: _,
                kvno,
            } => (kvno, EncryptionType::AES256_CTS_HMAC_SHA1_96),
        };

        RecordData::Entry {
            principal: value.principal.clone().into(),
            // I think this is NOT 2038 safe and requires a version change ...
            // indicates when the key was emitted to the keytab.
            timestamp: value.timestamp,
            // Needs to be 2, nfi why.
            key_version_u8: kvno as u8,
            enctype: enc_type as u16,
            key: Data {
                value: value.key.k(),
            },
            // Needs to be set?
            key_version_u32: Some(kvno),
        }
    }
}

impl TryFrom<&RecordData> for Option<KeytabEntry> {
    type Error = KrbError;

    fn try_from(value: &RecordData) -> Result<Self, Self::Error> {
        match value {
            RecordData::Hole { pad: _ } => Ok(None),
            RecordData::Entry {
                principal,
                timestamp,
                key_version_u8,
                enctype: _,
                key,
                key_version_u32,
            } => {
                let k = aes256::key_from_slice(key.value.as_slice())
                    .ok_or(KrbError::InvalidEncryptionKey)?;

                let e = KeytabEntry {
                    principal: principal.try_into()?,
                    timestamp: *timestamp,
                    key: DerivedKey::Aes256CtsHmacSha196 {
                        k,
                        i: 0,
                        s: String::new(),
                        kvno: match key_version_u32 {
                            Some(v) => *v,
                            None => (*key_version_u8) as u32,
                        },
                    },
                };
                Ok(Some(e))
            }
        }
    }
}

// Custom writer to seek back to fill the record length
#[binrw::writer(writer, endian)]
fn write_rdata(rdata: &RecordData) -> binrw::BinResult<()> {
    let start = writer.stream_position()?;
    rdata.write_options(writer, endian, ())?;
    let end = writer.stream_position()?;
    let rlen: i32 = end as i32 - start as i32;

    writer.seek(SeekFrom::Start(start - 4))?;
    rlen.write_options(writer, endian, ())?;
    writer.seek(SeekFrom::Start(end))?;
    Ok(())
}

#[binwrite]
#[brw(big)]
#[derive(Debug, Clone, PartialEq, Eq)]
#[binread]
#[br(import { version: u8 })]
struct Record {
    #[br(temp)]
    #[bw(if (matches!(rdata, RecordData::Entry { .. })), calc = 0)]
    // This field is always written as 0, the custom rdata writer will seek back to fill it
    rlen: i32,
    #[br(map_stream = |s| s.take_seek(rlen.unsigned_abs() as u64), args { version, rlen })]
    #[bw(if (matches!(rdata, RecordData::Entry { .. })), write_with = write_rdata)]
    rdata: RecordData,
}

#[binread]
#[binwrite]
#[brw(big)]
#[derive(Debug, Clone, PartialEq, Eq)]
struct FileKeytabV2 {
    #[br(parse_with = until_eof, args { version: 2 })]
    records: Vec<Record>,
}

#[binread]
#[binwrite]
#[brw(big, magic = 5u8)]
#[derive(Debug, Clone, PartialEq, Eq)]
enum FileKeytab {
    #[brw(magic = 2u8)]
    V2(FileKeytabV2),
}

impl From<&Keytab> for FileKeytab {
    fn from(value: &Keytab) -> Self {
        let records: Vec<Record> = value
            .iter()
            .map(|x| {
                let rdata: RecordData = x.into();
                Record { rdata }
            })
            .collect();
        let fk2: FileKeytabV2 = FileKeytabV2 { records };
        FileKeytab::V2(fk2)
    }
}

impl TryFrom<&FileKeytab> for Keytab {
    type Error = KrbError;

    fn try_from(value: &FileKeytab) -> Result<Self, Self::Error> {
        match value {
            FileKeytab::V2(v2) => {
                let mut entries: Vec<KeytabEntry> = Vec::with_capacity(0);
                for record in &v2.records {
                    let rdata = &record.rdata;
                    let entry: Option<KeytabEntry> = rdata.try_into()?;
                    if let Some(e) = entry {
                        entries.push(e);
                    }
                }
                Ok(entries)
            }
        }
    }
}

fn read(buffer: &Vec<u8>) -> Result<FileKeytab, KrbError> {
    let mut reader = binrw::io::Cursor::new(buffer);
    let keytab: FileKeytab = reader.read_type(binrw::Endian::Big).map_err(|err| {
        error!(?err, "Failed to unmarshall keytab buffer");
        KrbError::BinRWError
    })?;
    Ok(keytab)
}

pub fn store(kt_name: &str, kt: &Keytab) -> Result<(), KrbError> {
    let path = kt_name
        .strip_prefix("FILE:")
        .ok_or(KrbError::UnsupportedKeytabType)?;

    let mut f = File::create(path).map_err(|io_err| {
        error!(?io_err, "Unable to create file at {}", path);
        KrbError::IoError
    })?;

    let kt: FileKeytab = kt.into();
    kt.write(&mut f).map_err(|binrw_err| {
        error!(?binrw_err, "Unable to write binary data.");
        KrbError::BinRWError
    })?;

    Ok(())
}

pub fn load(kt_name: &str) -> Result<Keytab, KrbError> {
    let path = kt_name
        .strip_prefix("FILE:")
        .ok_or(KrbError::UnsupportedKeytabType)?;

    let mut f = File::open(path).map_err(|io_err| {
        error!(?io_err, "Unable to create file at {}", path);
        KrbError::IoError
    })?;

    let mut buffer = Vec::new();
    f.read_to_end(&mut buffer).map_err(|io_err| {
        error!(?io_err, "Unable to read file at {}", path);
        KrbError::IoError
    })?;

    let fk: FileKeytab = read(&buffer)?;
    let k: Keytab = (&fk).try_into()?;
    Ok(k)
}

#[cfg(test)]
mod tests {
    use super::*;
    use binrw::BinWrite;
    use std::fs;
    use std::process::{Command, Stdio};
    use tracing::warn;

    #[tokio::test]
    async fn test_keytab_read_write() {
        /*
         * This is a file ccache produced by MIT's kinit
         * including cache configuration entries
         */

        let mit_buf = "0502000000370001000a41464f524553542e41440006414e45544f240000000166ffb9ce0200110010cf8ea47a88cf230810f8ecbc9a1d4ea900000002000000470001000a41464f524553542e41440006414e45544f240000000166ffb9ce0200120020ed373e70378deac2b312e0ef95c5675091273661a2d7d001fb5dd28fb7ee007f000000020000003c0002000a41464f524553542e41440004686f73740005414e45544f0000000166ffb9ce0200110010cf8ea47a88cf230810f8ecbc9a1d4ea9000000020000004c0002000a41464f524553542e41440004686f73740005414e45544f0000000166ffb9ce0200120020ed373e70378deac2b312e0ef95c5675091273661a2d7d001fb5dd28fb7ee007f00000002000000490002000a41464f524553542e41440011526573747269637465644b7262486f73740005414e45544f0000000166ffb9ce0200110010cf8ea47a88cf230810f8ecbc9a1d4ea900000002000000590002000a41464f524553542e41440011526573747269637465644b7262486f73740005414e45544f0000000166ffb9ce0200120020ed373e70378deac2b312e0ef95c5675091273661a2d7d001fb5dd28fb7ee007f00000002";
        let mit_buf = hex::decode(mit_buf).expect("Failed to decode sample");
        let krime_keytab = super::read(&mit_buf).expect("Failed to read from buffer");

        let mut c = std::io::Cursor::new(Vec::new());
        krime_keytab.write(&mut c).expect("Failed to write");
        let krime_buf = c.into_inner();

        assert_eq!(krime_buf, mit_buf);
    }

    #[tokio::test]
    async fn test_keytab_read_write_with_holes() {
        let mit_buf = "0502000000370001000a41464f524553542e41440006414e45544f240000000166ffb9ce0200110010cf8ea47a88cf230810f8ecbc9a1d4ea900000002ffffffb90001000a41464f524553542e41440006414e45544f240000000166ffb9ce0200120020ed373e70378deac2b312e0ef95c5675091273661a2d7d001fb5dd28fb7ee007f000000020000003c0002000a41464f524553542e41440004686f73740005414e45544f0000000166ffb9ce0200110010cf8ea47a88cf230810f8ecbc9a1d4ea9000000020000004c0002000a41464f524553542e41440004686f73740005414e45544f0000000166ffb9ce0200120020ed373e70378deac2b312e0ef95c5675091273661a2d7d001fb5dd28fb7ee007f00000002ffffffb70002000a41464f524553542e41440011526573747269637465644b7262486f73740005414e45544f0000000166ffb9ce0200110010cf8ea47a88cf230810f8ecbc9a1d4ea900000002000000590002000a41464f524553542e41440011526573747269637465644b7262486f73740005414e45544f0000000166ffb9ce0200120020ed373e70378deac2b312e0ef95c5675091273661a2d7d001fb5dd28fb7ee007f00000002";
        let mit_buf = hex::decode(mit_buf).expect("Failed to decode sample");
        let krime_keytab = super::read(&mit_buf).expect("Failed to read from buffer");

        let FileKeytab::V2(k) = &krime_keytab;
        assert_eq!(k.records.len(), 6);
        assert!(matches!(k.records[0].rdata, RecordData::Entry { .. }));
        assert!(matches!(k.records[1].rdata, RecordData::Hole { .. }));
        assert!(matches!(k.records[2].rdata, RecordData::Entry { .. }));
        assert!(matches!(k.records[3].rdata, RecordData::Entry { .. }));
        assert!(matches!(k.records[4].rdata, RecordData::Hole { .. }));
        assert!(matches!(k.records[5].rdata, RecordData::Entry { .. }));

        let mut holes_len = 0;
        for r in &k.records {
            if let RecordData::Hole { pad } = &r.rdata {
                holes_len += pad.len() + 4
            }
        }

        let mut c = std::io::Cursor::new(Vec::new());
        let krime_keytab = super::read(&mit_buf).expect("Failed to read from buffer");
        krime_keytab.write(&mut c).expect("Failed to write");
        let krime_buf = c.into_inner();

        assert_eq!(mit_buf.len() - holes_len, krime_buf.len());

        let krime_keytab2 = super::read(&krime_buf).expect("Failed to read from buffer");
        let FileKeytab::V2(k2) = &krime_keytab2;
        assert_eq!(k2.records.len(), 4);

        assert_eq!(k.records[0], k2.records[0]);
        assert_eq!(k.records[2], k2.records[1]);
        assert_eq!(k.records[3], k2.records[2]);
        assert_eq!(k.records[5], k2.records[3]);
    }

    #[tokio::test]
    async fn test_keytab_read_pre_1_14() {
        let mit_buf = "0502000000460001000b4558414d504c452e4f524700087465737475736572000000016703af2e010012002012041af3423a7ec2002784c14dfd9c6df58b49498238a250249940b5f36f430b000000460001000b4558414d504c452e4f524700087465737475736572000000016703af2fff0012002012041af3423a7ec2002784c14dfd9c6df58b49498238a250249940b5f36f430b000000460001000b4558414d504c452e4f524700087465737475736572000000016703af2f000012002012041af3423a7ec2002784c14dfd9c6df58b49498238a250249940b5f36f430b000000460001000b4558414d504c452e4f524700087465737475736572000000016703af2fd20012002012041af3423a7ec2002784c14dfd9c6df58b49498238a250249940b5f36f430b";
        let mit_buf = hex::decode(mit_buf).expect("Failed to decode sample");
        let mit_keytab = super::read(&mit_buf).expect("Failed to read from buffer");
        let FileKeytab::V2(mit_keytab) = &mit_keytab;

        let kvs_wrap = [1, 255, 0, 250];
        assert_eq!(mit_keytab.records.len(), kvs_wrap.len());

        for (index, entry) in mit_keytab.records.iter().enumerate().take(3) {
            match entry.rdata {
                RecordData::Entry {
                    principal: _,
                    timestamp: _,
                    key_version_u8,
                    enctype: _,
                    key: _,
                    key_version_u32,
                } => {
                    assert_eq!(key_version_u8, kvs_wrap[index]);
                    assert!(key_version_u32.is_none());
                }
                _ => {
                    panic!("This should never happen");
                }
            }
        }

        let mit_buf = "05020000004a0001000b4558414d504c452e4f524700087465737475736572000000016703aeff010012002012041af3423a7ec2002784c14dfd9c6df58b49498238a250249940b5f36f430b000000010000004a0001000b4558414d504c452e4f524700087465737475736572000000016703aeffff0012002012041af3423a7ec2002784c14dfd9c6df58b49498238a250249940b5f36f430b000000ff0000004a0001000b4558414d504c452e4f524700087465737475736572000000016703aeff000012002012041af3423a7ec2002784c14dfd9c6df58b49498238a250249940b5f36f430b000001000000004a0001000b4558414d504c452e4f524700087465737475736572000000016703aeffd20012002012041af3423a7ec2002784c14dfd9c6df58b49498238a250249940b5f36f430b499602d2";
        let mit_buf = hex::decode(mit_buf).expect("Failed to decode sample");
        let mit_keytab = super::read(&mit_buf).expect("Failed to read from buffer");
        let FileKeytab::V2(mit_keytab) = &mit_keytab;

        let kvs: [u32; 4] = [1, 255, 256, 1234567890];
        assert_eq!(mit_keytab.records.len(), kvs.len());

        for i in 0..3 {
            let e = &mit_keytab.records[i];
            match e.rdata {
                RecordData::Entry {
                    principal: _,
                    timestamp: _,
                    key_version_u8,
                    enctype: _,
                    key: _,
                    key_version_u32,
                } => {
                    assert_eq!(key_version_u8, kvs_wrap[i]);
                    assert_eq!(key_version_u32.unwrap(), kvs[i]);
                }
                _ => {
                    panic!("This should never happen");
                }
            }
        }
    }

    #[tokio::test]
    async fn test_keytab_store_load() {
        let _ = tracing_subscriber::fmt::try_init();

        let path = tempfile::NamedTempFile::new()
            .expect("Failed to create temporary file")
            .into_temp_path()
            .to_string_lossy()
            .to_string();
        let ktname = "FILE:".to_owned() + path.as_str();

        let buf = "05020000004a0001000b4558414d504c452e4f524700087465737475736572000000016703aeff010012002012041af3423a7ec2002784c14dfd9c6df58b49498238a250249940b5f36f430b000000010000004a0001000b4558414d504c452e4f524700087465737475736572000000016703aeffff0012002012041af3423a7ec2002784c14dfd9c6df58b49498238a250249940b5f36f430b000000ff0000004a0001000b4558414d504c452e4f524700087465737475736572000000016703aeff000012002012041af3423a7ec2002784c14dfd9c6df58b49498238a250249940b5f36f430b000001000000004a0001000b4558414d504c452e4f524700087465737475736572000000016703aeffd20012002012041af3423a7ec2002784c14dfd9c6df58b49498238a250249940b5f36f430b499602d2";
        let buf = hex::decode(buf).expect("Failed to decode sample");
        let fk1 = super::read(&buf).expect("Failed to read from buffer");
        let k1: Keytab = (&fk1)
            .try_into()
            .expect("Failed to turn FileKeytab into Keytab");
        super::store(ktname.as_str(), &k1).expect("Failed to store keytab");

        if std::env::var("CI").is_ok() {
            // Skip klist check on CI

            if which::which("klist").is_err() {
                panic!("klist not found, can't continue test");
            }
        } else if which::which("klist").is_err() {
            warn!("Skipping klist check on CI as it's not installed");
            return;
        }

        let status = Command::new("klist")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .arg("-k")
            .arg(path.as_str())
            .status()
            .expect("Failed to klist");

        let k2: Keytab = super::load(ktname.as_str()).expect("Failed to load keytab file");
        let fk2: FileKeytab = (&k2).into();

        assert_eq!(fk1, fk2);
        assert_eq!(k1, k2);

        fs::remove_file(path).expect("Failed to rm keytab file");
        assert!(status.success());
    }
}
