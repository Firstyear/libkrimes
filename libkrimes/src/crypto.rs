use crate::constants::*;
use crate::error::KrbError;

use crypto_glue::{
    aes256::{Aes256Block, Aes256BlockSize, Aes256Key},
    aes256cbc::{Aes256CbcEnc, BlockModeEncrypt},
    aes256cts::{Aes256CtsDec, Aes256CtsEnc, Aes256CtsIv, CtsDecrypt, CtsEncrypt, KeyIvInit},
    hmac_s1::HmacSha1,
    pbkdf2::pbkdf2_hmac,
    rand::{rng, RngExt},
    sha1::Sha1,
    traits::{FixedOutput, KeyInit, Mac},
};

/// Given the users passphrase, the kerberos realm, the client name and the iteration
/// count then the users base key is derived. The iteration count is an optional value
/// which defaults to the RFC3962 value of 0x1000 (4096). This *default value* is
/// INSECURE and should not be used. This will become a hard error in the future!
pub(crate) fn derive_key_aes256_cts_hmac_sha1_96(
    passphrase: &[u8],
    salt: &[u8],
    iter_count: u32,
) -> Result<Aes256Key, KrbError> {
    // Salt is the concatenation of realm + cname.
    // NOTE: Salt may come in AS-REP padata ETYPE-INFO2
    let mut buf = Aes256Key::default();
    pbkdf2_hmac::<Sha1>(passphrase, salt, iter_count, &mut buf);

    // It's unclear what this achieves cryptographically ...
    let mut dk_buf = Aes256Key::default();
    dk_aes_256(&mut dk_buf, &buf);

    Ok(dk_buf)
}

fn dk_aes_256(out_buf: &mut Aes256Key, buf: &Aes256Key) {
    let (lower, upper) = out_buf.split_ref_mut::<Aes256BlockSize>();
    debug_assert!(lower.len() == AES_BLOCK_SIZE);
    debug_assert!(upper.len() == AES_BLOCK_SIZE);
    dk_encrypt_aes_256_cbc(buf, &N_FOLD_KERBEROS_16.into(), lower);
    dk_encrypt_aes_256_cbc(buf, lower, upper);
}

fn dk_encrypt_aes_256_cbc(key: &Aes256Key, plaintext: &Aes256Block, out_buf: &mut Aes256Block) {
    Aes256CbcEnc::new(key, &IV_ZERO.into()).encrypt_block_b2b(plaintext, out_buf)
}

/// Given the [base key](derive_key_aes256_cts_hmac_sha1_96) and the key_usage value
/// decrypt and authenticate the provided ciphertext.
pub(crate) fn decrypt_aes256_cts_hmac_sha1_96(
    key: &Aes256Key,
    ciphertext: &[u8],
    key_usage: i32,
) -> Result<Vec<u8>, KrbError> {
    // Split to get the mac.
    if let Some((ciphertext, msg_hmac)) = ciphertext.split_last_chunk::<SHA1_HMAC_LEN>() {
        // Check the ciphertext length.
        assert!(!ciphertext.is_empty());
        if ciphertext.is_empty() {
            return Err(KrbError::MessageEmpty);
        };

        // More key derivation ...
        let (ki, ke) = dk_ki_ke_aes_256(key, key_usage);

        let mut plaintext = ciphertext.to_vec();

        let zero_iv = Aes256CtsIv::default();
        let aes_256_cts_dec = Aes256CtsDec::new(&ke, &zero_iv);

        aes_256_cts_dec
            .decrypt_inout(plaintext.as_mut_slice().into())
            .map_err(|_err| KrbError::InsufficientData)?;

        // let mut mac = HmacSha1::new(&ki.into());
        let mut mac = HmacSha1::new_from_slice(&ki).map_err(|_| KrbError::InvalidHmacSha1Key)?;
        mac.update(&plaintext);

        let mut buf = [0u8; 20];
        mac.finalize_into((&mut buf).into());

        // Truncate to 96 bits.
        let my_hmac = &buf[0..SHA1_HMAC_LEN];

        // The first block is a "confounder" or a random block that exists to setup
        // the IV for the next block. Ignore it.
        let plaintext = plaintext.split_off(AES_BLOCK_SIZE);

        if my_hmac == msg_hmac {
            Ok(plaintext)
        } else {
            Err(KrbError::MessageAuthenticationFailed)
        }
    } else {
        // Not enough data
        Err(KrbError::InsufficientData)
    }
}

/// Given the [base key](derive_key_aes256_cts_hmac_sha1_96) and the key_usage value
/// encrypt and authenticate the provided plaintext.
pub(crate) fn encrypt_aes256_cts_hmac_sha1_96(
    key: &Aes256Key,
    plaintext: &[u8],
    key_usage: i32,
) -> Result<Vec<u8>, KrbError> {
    if plaintext.is_empty() {
        return Err(KrbError::PlaintextEmpty);
    };
    let (ki, ke) = dk_ki_ke_aes_256(key, key_usage);

    let mut buf = vec![0; AES_BLOCK_SIZE + plaintext.len() + SHA1_HMAC_LEN];

    {
        let (confuzzler, buf_rem) = buf.split_at_mut(AES_BLOCK_SIZE);
        rng().fill(confuzzler);

        let (ciphertext, hmac) = buf_rem.split_at_mut(plaintext.len());
        ciphertext.copy_from_slice(plaintext);

        let mut mac = HmacSha1::new_from_slice(&ki).map_err(|_| KrbError::InvalidHmacSha1Key)?;

        mac.update(confuzzler);
        mac.update(ciphertext);

        let mut buf = [0u8; 20];
        mac.finalize_into((&mut buf).into());

        // Truncate to 96 bits.
        let my_hmac = &buf[0..SHA1_HMAC_LEN];
        hmac.copy_from_slice(my_hmac);
    }

    let (cipher, _hmac) = buf.split_at_mut(AES_BLOCK_SIZE + plaintext.len());

    let zero_iv = Aes256CtsIv::default();
    let aes_256_cts_enc = Aes256CtsEnc::new(&ke, &zero_iv);

    aes_256_cts_enc
        .encrypt_inout(cipher.into())
        .map_err(|_err| KrbError::InsufficientData)?;

    Ok(buf)
}

fn dk_kc_aes_256(buf: &Aes256Key, key_usage: i32) -> Aes256Key {
    let kc_const = match key_usage {
        0 => &N_FOLD_KEY_USAGE_KC_00,
        1 => &N_FOLD_KEY_USAGE_KC_01,
        2 => &N_FOLD_KEY_USAGE_KC_02,
        3 => &N_FOLD_KEY_USAGE_KC_03,
        4 => &N_FOLD_KEY_USAGE_KC_04,
        5 => &N_FOLD_KEY_USAGE_KC_05,
        6 => &N_FOLD_KEY_USAGE_KC_06,
        7 => &N_FOLD_KEY_USAGE_KC_07,
        8 => &N_FOLD_KEY_USAGE_KC_08,
        9 => &N_FOLD_KEY_USAGE_KC_09,
        10 => &N_FOLD_KEY_USAGE_KC_10,
        11 => &N_FOLD_KEY_USAGE_KC_11,
        12 => &N_FOLD_KEY_USAGE_KC_12,
        13 => &N_FOLD_KEY_USAGE_KC_13,
        14 => &N_FOLD_KEY_USAGE_KC_14,
        15 => &N_FOLD_KEY_USAGE_KC_15,
        16 => &N_FOLD_KEY_USAGE_KC_16,
        17 => &N_FOLD_KEY_USAGE_KC_17,
        18 => &N_FOLD_KEY_USAGE_KC_18,
        19 => &N_FOLD_KEY_USAGE_KC_19,
        20 => &N_FOLD_KEY_USAGE_KC_20,
        21 => &N_FOLD_KEY_USAGE_KC_21,
        22 => &N_FOLD_KEY_USAGE_KC_22,
        23 => &N_FOLD_KEY_USAGE_KC_23,
        24 => &N_FOLD_KEY_USAGE_KC_24,
        25 => &N_FOLD_KEY_USAGE_KC_25,
        26 => &N_FOLD_KEY_USAGE_KC_26,
        27 => &N_FOLD_KEY_USAGE_KC_27,
        28 => &N_FOLD_KEY_USAGE_KC_28,
        29 => &N_FOLD_KEY_USAGE_KC_29,
        30 => &N_FOLD_KEY_USAGE_KC_30,
        31 => &N_FOLD_KEY_USAGE_KC_31,
        _ => unreachable!(),
    };

    let mut kc = Aes256Key::default();

    let (lower, upper) = kc.split_ref_mut::<Aes256BlockSize>();
    debug_assert!(lower.len() == AES_BLOCK_SIZE);
    debug_assert!(upper.len() == AES_BLOCK_SIZE);
    dk_encrypt_aes_256_cbc(buf, kc_const.into(), lower);
    dk_encrypt_aes_256_cbc(buf, lower, upper);

    kc
}

fn dk_ki_ke_aes_256(buf: &Aes256Key, key_usage: i32) -> (Aes256Key, Aes256Key) {
    let (ki_const, ke_const) = match key_usage {
        0 => (&N_FOLD_KEY_USAGE_KI_00, &N_FOLD_KEY_USAGE_KE_00),
        1 => (&N_FOLD_KEY_USAGE_KI_01, &N_FOLD_KEY_USAGE_KE_01),
        2 => (&N_FOLD_KEY_USAGE_KI_02, &N_FOLD_KEY_USAGE_KE_02),
        3 => (&N_FOLD_KEY_USAGE_KI_03, &N_FOLD_KEY_USAGE_KE_03),
        4 => (&N_FOLD_KEY_USAGE_KI_04, &N_FOLD_KEY_USAGE_KE_04),
        5 => (&N_FOLD_KEY_USAGE_KI_05, &N_FOLD_KEY_USAGE_KE_05),
        6 => (&N_FOLD_KEY_USAGE_KI_06, &N_FOLD_KEY_USAGE_KE_06),
        7 => (&N_FOLD_KEY_USAGE_KI_07, &N_FOLD_KEY_USAGE_KE_07),
        8 => (&N_FOLD_KEY_USAGE_KI_08, &N_FOLD_KEY_USAGE_KE_08),
        9 => (&N_FOLD_KEY_USAGE_KI_09, &N_FOLD_KEY_USAGE_KE_09),
        10 => (&N_FOLD_KEY_USAGE_KI_10, &N_FOLD_KEY_USAGE_KE_10),
        11 => (&N_FOLD_KEY_USAGE_KI_11, &N_FOLD_KEY_USAGE_KE_11),
        12 => (&N_FOLD_KEY_USAGE_KI_12, &N_FOLD_KEY_USAGE_KE_12),
        13 => (&N_FOLD_KEY_USAGE_KI_13, &N_FOLD_KEY_USAGE_KE_13),
        14 => (&N_FOLD_KEY_USAGE_KI_14, &N_FOLD_KEY_USAGE_KE_14),
        15 => (&N_FOLD_KEY_USAGE_KI_15, &N_FOLD_KEY_USAGE_KE_15),
        16 => (&N_FOLD_KEY_USAGE_KI_16, &N_FOLD_KEY_USAGE_KE_16),
        17 => (&N_FOLD_KEY_USAGE_KI_17, &N_FOLD_KEY_USAGE_KE_17),
        18 => (&N_FOLD_KEY_USAGE_KI_18, &N_FOLD_KEY_USAGE_KE_18),
        19 => (&N_FOLD_KEY_USAGE_KI_19, &N_FOLD_KEY_USAGE_KE_19),
        20 => (&N_FOLD_KEY_USAGE_KI_20, &N_FOLD_KEY_USAGE_KE_20),
        21 => (&N_FOLD_KEY_USAGE_KI_21, &N_FOLD_KEY_USAGE_KE_21),
        22 => (&N_FOLD_KEY_USAGE_KI_22, &N_FOLD_KEY_USAGE_KE_22),
        23 => (&N_FOLD_KEY_USAGE_KI_23, &N_FOLD_KEY_USAGE_KE_23),
        24 => (&N_FOLD_KEY_USAGE_KI_24, &N_FOLD_KEY_USAGE_KE_24),
        25 => (&N_FOLD_KEY_USAGE_KI_25, &N_FOLD_KEY_USAGE_KE_25),
        26 => (&N_FOLD_KEY_USAGE_KI_26, &N_FOLD_KEY_USAGE_KE_26),
        27 => (&N_FOLD_KEY_USAGE_KI_27, &N_FOLD_KEY_USAGE_KE_27),
        28 => (&N_FOLD_KEY_USAGE_KI_28, &N_FOLD_KEY_USAGE_KE_28),
        29 => (&N_FOLD_KEY_USAGE_KI_29, &N_FOLD_KEY_USAGE_KE_29),
        30 => (&N_FOLD_KEY_USAGE_KI_30, &N_FOLD_KEY_USAGE_KE_30),
        31 => (&N_FOLD_KEY_USAGE_KI_31, &N_FOLD_KEY_USAGE_KE_31),
        _ => unreachable!(),
    };

    let mut ki = Aes256Key::default();

    let (lower, upper) = ki.split_ref_mut::<Aes256BlockSize>();
    debug_assert!(lower.len() == AES_BLOCK_SIZE);
    debug_assert!(upper.len() == AES_BLOCK_SIZE);
    dk_encrypt_aes_256_cbc(buf, ki_const.into(), lower);
    dk_encrypt_aes_256_cbc(buf, lower, upper);

    let mut ke = Aes256Key::default();
    let (lower, upper) = ke.split_ref_mut::<Aes256BlockSize>();
    debug_assert!(lower.len() == AES_BLOCK_SIZE);
    debug_assert!(upper.len() == AES_BLOCK_SIZE);
    dk_encrypt_aes_256_cbc(buf, ke_const.into(), lower);
    dk_encrypt_aes_256_cbc(buf, lower, upper);

    (ki, ke)
}

pub(crate) fn checksum_hmac_sha1_96_aes256(
    plaintext: &[u8],
    key: &Aes256Key,
    key_usage: i32,
) -> Result<Vec<u8>, KrbError> {
    if plaintext.is_empty() {
        return Err(KrbError::PlaintextEmpty);
    };

    let kc = dk_kc_aes_256(key, key_usage);
    let mut mac = HmacSha1::new_from_slice(&kc).map_err(|_| KrbError::InvalidHmacSha1Key)?;
    mac.update(plaintext);

    let mut buf = [0u8; 20];
    mac.finalize_into((&mut buf).into());

    // Truncate to 96 bits.
    let my_hmac = &buf[0..SHA1_HMAC_LEN];
    Ok(my_hmac.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::asn1::pa_enc_ts_enc::PaEncTsEnc;
    use crate::constants::RFC_PBKDF2_SHA1_ITER;
    use assert_hex::assert_eq_hex;
    use crypto_glue::der::Decode;

    #[test]
    fn test_hmac_sha1_96_kerbeiros() {
        let out_key = derive_key_aes256_cts_hmac_sha1_96(
            "Minnie1234".as_bytes(),
            "KINGDOM.HEARTSmickey".as_bytes(),
            RFC_PBKDF2_SHA1_ITER,
        )
        .expect("Failed to derive key for test_hmac_sha1_96_kerbeiros");

        assert_eq!(
            [
                0xd3, 0x30, 0x1f, 0x0f, 0x25, 0x39, 0xcc, 0x40, 0x26, 0xa5, 0x69, 0xf8, 0xb7, 0xc3,
                0x67, 0x15, 0xc8, 0xda, 0xef, 0x10, 0x9f, 0xa3, 0xd8, 0xb2, 0xe1, 0x46, 0x16, 0xaa,
                0xca, 0xb5, 0x49, 0xfd
            ],
            out_key.as_slice(),
        )
    }

    // https://www.rfc-editor.org/rfc/rfc3962#appendix-B

    #[test]
    fn test_hmac_sha1_96_rfc3962_vector_1() {
        let out_key = derive_key_aes256_cts_hmac_sha1_96(
            "password".as_bytes(),
            "ATHENA.MIT.EDUraeburn".as_bytes(),
            1,
        )
        .unwrap();

        assert_eq!(
            [
                0xfe, 0x69, 0x7b, 0x52, 0xbc, 0x0d, 0x3c, 0xe1, 0x44, 0x32, 0xba, 0x03, 0x6a, 0x92,
                0xe6, 0x5b, 0xbb, 0x52, 0x28, 0x09, 0x90, 0xa2, 0xfa, 0x27, 0x88, 0x39, 0x98, 0xd7,
                0x2a, 0xf3, 0x01, 0x61
            ],
            out_key.as_slice(),
        )
    }

    #[test]
    fn test_hmac_sha1_96_rfc3962_vector_2() {
        let out_key = derive_key_aes256_cts_hmac_sha1_96(
            "password".as_bytes(),
            "ATHENA.MIT.EDUraeburn".as_bytes(),
            1200,
        )
        .unwrap();

        assert_eq!(
            [
                0x55, 0xa6, 0xac, 0x74, 0x0a, 0xd1, 0x7b, 0x48, 0x46, 0x94, 0x10, 0x51, 0xe1, 0xe8,
                0xb0, 0xa7, 0x54, 0x8d, 0x93, 0xb0, 0xab, 0x30, 0xa8, 0xbc, 0x3f, 0xf1, 0x62, 0x80,
                0x38, 0x2b, 0x8c, 0x2a
            ],
            out_key.as_slice(),
        )
    }

    #[test]
    fn test_aes256_cts_hmac_sha1_96_decrypt_1() {
        let out_key = derive_key_aes256_cts_hmac_sha1_96(
            "admin".as_bytes(),
            "admin1234".as_bytes(),
            RFC_PBKDF2_SHA1_ITER,
        )
        .unwrap();

        let input_data = [
            0x29, 0x73, 0x7f, 0x3d, 0xb6, 0xbc, 0xdf, 0xe9, 0x99, 0x0f, 0xb2, 0x13, 0x6d, 0x3e,
            0xfe, 0x6f, 0x21, 0x00, 0xe6, 0xc4, 0xac, 0x75, 0x82, 0x42, 0x99, 0xd8, 0xd3, 0x70,
            0x2f, 0x5a, 0x2e, 0x31, 0xc7, 0xa3, 0x36, 0x74, 0x7d, 0xfd, 0x73, 0x4a, 0x1e, 0xa0,
            0x16, 0x5e, 0xbb, 0x27, 0xc0, 0xd7, 0xce, 0x9b, 0x5a, 0xec, 0x7a,
        ];

        let key_usage = 1;

        let data = decrypt_aes256_cts_hmac_sha1_96(&out_key, &input_data, key_usage).unwrap();

        assert_eq!(
            vec![
                0x33, 0x61, 0x68, 0x77, 0x7a, 0x74, 0x39, 0x4d, 0x47, 0x39, 0x57, 0x56, 0x45, 0x75,
                0x42, 0x56, 0x43, 0x35, 0x6a, 0x30, 0x6f, 0x69, 0x36, 0x73, 0x49
            ],
            data
        );
    }

    #[test]
    fn test_aes256_cts_hmac_sha1_96_decrypt_2() {
        let out_key = derive_key_aes256_cts_hmac_sha1_96(
            "test".as_bytes(),
            "test1234".as_bytes(),
            RFC_PBKDF2_SHA1_ITER,
        )
        .unwrap();

        let input_data = [
            0x3d, 0x29, 0x1c, 0x68, 0x54, 0x89, 0xe7, 0xb7, 0x5d, 0xab, 0xdc, 0x6e, 0x01, 0x0a,
            0xd0, 0x01, 0x9d, 0xb1, 0x64, 0x81, 0xb1, 0x2c, 0xb8, 0xbf, 0xa5, 0x13, 0x61, 0x92,
            0x42, 0x76, 0x1f, 0x99, 0x0d, 0xe2, 0xc0, 0x27, 0x66, 0x1c, 0x98, 0x33, 0xbc, 0xce,
            0xd3,
        ];

        let key_usage = 2;

        let data = decrypt_aes256_cts_hmac_sha1_96(&out_key, &input_data, key_usage).unwrap();

        assert_eq!(
            vec![
                0x6c, 0x4a, 0x33, 0x66, 0x74, 0x66, 0x77, 0x78, 0x6a, 0x73, 0x52, 0x35, 0x32, 0x32,
                0x4f
            ],
            data
        );
    }

    #[test]
    fn test_aes256_cts_hmac_sha1_96_reflexive_1() {
        let out_key = derive_key_aes256_cts_hmac_sha1_96(
            "test".as_bytes(),
            "test1234".as_bytes(),
            RFC_PBKDF2_SHA1_ITER,
        )
        .unwrap();

        let input_data = [0xffu8; 32];

        let key_usage = 2;

        let enc_data = encrypt_aes256_cts_hmac_sha1_96(&out_key, &input_data, key_usage).unwrap();

        let data = decrypt_aes256_cts_hmac_sha1_96(&out_key, &enc_data, key_usage).unwrap();

        assert_eq!(data, input_data);
    }

    #[test]
    fn test_aes256_cts_hmac_sha1_96_reflexive_2() {
        let out_key = derive_key_aes256_cts_hmac_sha1_96(
            "test".as_bytes(),
            "test1234".as_bytes(),
            RFC_PBKDF2_SHA1_ITER,
        )
        .unwrap();

        // Half an aes block size
        let input_data = [0xaau8; 8];

        let key_usage = 3;

        let enc_data = encrypt_aes256_cts_hmac_sha1_96(&out_key, &input_data, key_usage).unwrap();

        let data = decrypt_aes256_cts_hmac_sha1_96(&out_key, &enc_data, key_usage).unwrap();

        assert_eq!(data, input_data);
    }

    #[test]
    fn test_aes256_cts_hmac_sha1_96_reflexive_3() {
        let out_key = derive_key_aes256_cts_hmac_sha1_96(
            "test".as_bytes(),
            "test1234".as_bytes(),
            RFC_PBKDF2_SHA1_ITER,
        )
        .unwrap();

        // Exactly one block size
        let input_data = [0x55u8; 16];

        let key_usage = 4;

        let enc_data = encrypt_aes256_cts_hmac_sha1_96(&out_key, &input_data, key_usage).unwrap();

        let data = decrypt_aes256_cts_hmac_sha1_96(&out_key, &enc_data, key_usage).unwrap();

        assert_eq!(data, input_data);
    }

    #[test]
    fn test_aes256_cts_hmac_sha1_96_reflexive_4() {
        let out_key = derive_key_aes256_cts_hmac_sha1_96(
            "test".as_bytes(),
            "test1234".as_bytes(),
            RFC_PBKDF2_SHA1_ITER,
        )
        .unwrap();

        // Multiple blocks, not aligned
        let input_data = [0xbbu8; 49];

        let key_usage = 5;

        let enc_data = encrypt_aes256_cts_hmac_sha1_96(&out_key, &input_data, key_usage).unwrap();

        let data = decrypt_aes256_cts_hmac_sha1_96(&out_key, &enc_data, key_usage).unwrap();

        assert_eq!(data, input_data);
    }

    #[test]
    fn test_aes256_cts_hmac_sha1_pa_enc_timestamp_decrypt() {
        let enc_data = hex::decode("b736f4dba847718b9f634b7ac94d5d691663164d877a0d875b94f786222ae9dca8cf68a972cfe6b5bec1c29682ec3c507307e7c32eedc032")
            .unwrap();

        let out_key = derive_key_aes256_cts_hmac_sha1_96(
            "password".as_bytes(),
            "EXAMPLE.COMtestuser_preauth".as_bytes(),
            RFC_PBKDF2_SHA1_ITER,
        )
        .unwrap();

        let key_usage = 1;

        let data = decrypt_aes256_cts_hmac_sha1_96(&out_key, &enc_data, key_usage).unwrap();

        eprintln!("{data:?}");

        let pa_enc_ts_enc = PaEncTsEnc::from_der(&data).unwrap();

        eprintln!("{pa_enc_ts_enc:?}");
    }

    #[test]
    fn test_checksum_hmac_sha1_96() {
        let input = "3067a00703050000810000a20d1b0b4558414d504c452e434f4da3253023a003020103a11c301a1b04686f73741b127065707065722e6578616d706c652e636f6da511180f32303234313031303230333832335aa7060204769220c1a80b3009020112020113020114";

        let input = hex::decode(input).unwrap();
        let derived_key = "14AD9322E8134937815FB995067F8C1859A8237C599E450F2BC1E99330C94232";
        let derived_key = hex::decode(derived_key).unwrap();
        let checksum = "351E56F9FA207CDCA62A0BDC";
        let checksum = hex::decode(checksum).unwrap();

        let mut mac = HmacSha1::new_from_slice(&derived_key).unwrap();
        mac.update(&input);

        let mut buf = [0u8; 20];
        mac.finalize_into((&mut buf).into());

        // Truncate to 96 bits.
        let my_hmac = &buf[0..SHA1_HMAC_LEN];
        assert_eq_hex!(my_hmac, checksum);
    }

    #[test]
    fn test_checksum_dk_hmac_sha1_96() {
        let input = "3067a00703050000810000a20d1b0b4558414d504c452e434f4da3253023a003020103a11c301a1b04686f73741b127065707065722e6578616d706c652e636f6da511180f32303234313031303230333832335aa7060204769220c1a80b3009020112020113020114";

        let input = hex::decode(input).unwrap();
        let base_key = "3C4EEFA91060DC4000582C17885AA63A58CD5A57C5CD3E7601A0587E7E05F9D0";
        let base_key = hex::decode(base_key).unwrap();
        let derived_key = "14AD9322E8134937815FB995067F8C1859A8237C599E450F2BC1E99330C94232";
        let derived_key = hex::decode(derived_key).unwrap();
        let checksum = "351E56F9FA207CDCA62A0BDC";
        let checksum = hex::decode(checksum).unwrap();

        let mut b = Aes256Key::default();
        b.clone_from_slice(base_key.as_slice());

        let kc = dk_kc_aes_256(&b, 6);

        assert_eq_hex!(kc.as_slice(), derived_key.as_slice());

        let mut mac = HmacSha1::new_from_slice(&derived_key).unwrap();
        mac.update(&input);

        let mut buf = [0u8; 20];
        mac.finalize_into((&mut buf).into());

        // Truncate to 96 bits.
        let my_hmac = &buf[0..SHA1_HMAC_LEN];
        assert_eq_hex!(my_hmac, checksum);
    }
}
