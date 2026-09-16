use crate::constants::*;
use crate::error::KrbError;

use crypto_glue::{

/*
 aes::cipher::generic_array::GenericArray;
 aes::cipher::{BlockDecryptMut, BlockEncryptMut};
 aes::Aes256;
 hmac::{digest::FixedOutput, Hmac, Mac};
 */

    traits::{Mac,
    KeyInit,
    KeyIvInit
    },
        sha1::Sha1,
        aes256::{self, Aes256Key, Aes256Block},
        aes256cts::{self, KeyIvInit},

    pbkdf2::pbkdf2_hmac,
    rand::{rng, Rng},
    hmac_s1::{
        HmacSha1
    },
};


// type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;
// type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;
// 
// type Aes256Block = GenericArray<u8, <aes::Aes256 as aes::cipher::BlockSizeUser>::BlockSize>;
// type Aes256Key = GenericArray<u8, <aes::Aes256 as aes::cipher::KeySizeUser>::KeySize>;


/// Given the users passphrase, the kerberos realm, the client name and the iteration
/// count then the users base key is derived. The iteration count is an optional value
/// which defaults to the RFC3962 value of 0x1000 (4096). This *default value* is
/// INSECURE and should not be used. This will become a hard error in the future!
pub(crate) fn derive_key_aes256_cts_hmac_sha1_96(
    passphrase: &[u8],
    salt: &[u8],
    iter_count: u32,
) -> Result<[u8; AES_256_KEY_LEN], KrbError> {
    // Salt is the concatenation of realm + cname.
    // NOTE: Salt may come in AS-REP padata ETYPE-INFO2
    let mut buf = [0u8; AES_256_KEY_LEN];
    pbkdf2_hmac::<Sha1>(passphrase, salt, iter_count, &mut buf);

    // It's unclear what this achieves cryptographically ...
    let mut dk_buf = [0u8; AES_256_KEY_LEN];
    dk_aes_256(&mut dk_buf, &buf);

    Ok(dk_buf)
}

fn dk_aes_256(out_buf: &mut [u8; AES_256_KEY_LEN], buf: &[u8; AES_256_KEY_LEN]) {
    let (lower, upper) = out_buf.split_at_mut(AES_BLOCK_SIZE);
    debug_assert!(lower.len() == AES_BLOCK_SIZE);
    debug_assert!(upper.len() == AES_BLOCK_SIZE);
    dk_encrypt_aes_256_cbc(buf.into(), &N_FOLD_KERBEROS_16.into(), lower.into());
    dk_encrypt_aes_256_cbc(buf.into(), (&*lower).into(), upper.into());
}

fn dk_encrypt_aes_256_cbc(key: &Aes256Key, plaintext: &Aes256Block, out_buf: &mut Aes256Block) {
    Aes256CbcEnc::new(key, &IV_ZERO.into()).encrypt_block_b2b_mut(plaintext, out_buf)
}

/// Given the [base key](derive_key_aes256_cts_hmac_sha1_96) and the key_usage value
/// decrypt and authenticate the provided ciphertext.
pub(crate) fn decrypt_aes256_cts_hmac_sha1_96(
    key: &[u8; AES_256_KEY_LEN],
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

        let mut plaintext = decrypt_aes256_cts(&ke, ciphertext)?;

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
    key: &[u8; AES_256_KEY_LEN],
    plaintext: &[u8],
    key_usage: i32,
) -> Result<Vec<u8>, KrbError> {
    if plaintext.is_empty() {
        return Err(KrbError::PlaintextEmpty);
    };
    let (ki, ke) = dk_ki_ke_aes_256(key, key_usage);

    let mut confuzzler = [0u8; AES_BLOCK_SIZE];
    rng().fill(&mut confuzzler);

    // let mut mac = HmacSha1::new(ki.into());
    let mut mac = HmacSha1::new_from_slice(&ki).map_err(|_| KrbError::InvalidHmacSha1Key)?;

    mac.update(&confuzzler);
    mac.update(plaintext);

    let mut buf = [0u8; 20];
    mac.finalize_into((&mut buf).into());

    // Truncate to 96 bits.
    let my_hmac = &buf[0..SHA1_HMAC_LEN];

    let mut ciphertext = vec![0; AES_BLOCK_SIZE + plaintext.len() + SHA1_HMAC_LEN];
    let (cipher, hmac) = ciphertext.split_at_mut(AES_BLOCK_SIZE + plaintext.len());

    encrypt_aes256_cts(&ke, &confuzzler, plaintext, cipher)?;
    hmac.copy_from_slice(my_hmac);

    Ok(ciphertext)
}

fn dk_kc_aes_256(buf: &[u8; AES_256_KEY_LEN], key_usage: i32) -> [u8; AES_256_KEY_LEN] {
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

    let mut kc = [0u8; AES_256_KEY_LEN];

    let (lower, upper) = kc.split_at_mut(AES_BLOCK_SIZE);
    debug_assert!(lower.len() == AES_BLOCK_SIZE);
    debug_assert!(upper.len() == AES_BLOCK_SIZE);
    dk_encrypt_aes_256_cbc(buf.into(), kc_const.into(), lower.into());
    dk_encrypt_aes_256_cbc(buf.into(), (&*lower).into(), upper.into());

    kc
}

fn dk_ki_ke_aes_256(
    buf: &[u8; AES_256_KEY_LEN],
    key_usage: i32,
) -> ([u8; AES_256_KEY_LEN], [u8; AES_256_KEY_LEN]) {
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

    let mut ki = [0u8; AES_256_KEY_LEN];

    let (lower, upper) = ki.split_at_mut(AES_BLOCK_SIZE);
    debug_assert!(lower.len() == AES_BLOCK_SIZE);
    debug_assert!(upper.len() == AES_BLOCK_SIZE);
    dk_encrypt_aes_256_cbc(buf.into(), ki_const.into(), lower.into());
    dk_encrypt_aes_256_cbc(buf.into(), (&*lower).into(), upper.into());

    let mut ke = [0u8; AES_256_KEY_LEN];
    let (lower, upper) = ke.split_at_mut(AES_BLOCK_SIZE);
    debug_assert!(lower.len() == AES_BLOCK_SIZE);
    debug_assert!(upper.len() == AES_BLOCK_SIZE);
    dk_encrypt_aes_256_cbc(buf.into(), ke_const.into(), lower.into());
    dk_encrypt_aes_256_cbc(buf.into(), (&*lower).into(), upper.into());

    (ki, ke)
}

fn encrypt_aes256_cts(
    key: &[u8; AES_256_KEY_LEN],
    confuzzler: &[u8],
    plaintext: &[u8],
    ciphertext: &mut [u8],
) -> Result<(), KrbError> {

    // Need at lesat one block for the confuzzler.
    debug_assert!(ciphertext.len() == plaintext.len() + AES_BLOCK_SIZE);

    let plaintext_chunks = plaintext.chunks(AES_BLOCK_SIZE);
    let mut ciphertext_chunks = ciphertext.chunks_mut(AES_BLOCK_SIZE);

    // There will be one more ciphertext_chunk than plaintext.
    debug_assert!(plaintext_chunks.len() + 1 == ciphertext_chunks.len());

    // Now there are some chunks here that are special.
    // The first ciphertext chunk is a confuzzler. We take this as a "last_chunk"
    // variable because we need to operate on this as we proceed.
    let mut previous_chunk = ciphertext_chunks
        .next()
        // Should be impossible
        .ok_or(KrbError::InsufficientData)?;
    // The last "chunk" of both needs to be operated on for CTS mode.

    // Zip the iters now, we positioned ciphertext to match.
    let mut chunks = std::iter::zip(ciphertext_chunks, plaintext_chunks);
    // Get the last chunk, this is the only one that may not be block_size
    // and needs special handling.
    let (c_n_chunk, p_n_star_chunk) = chunks
        .next_back()
        // Should be impossible
        .ok_or(KrbError::InsufficientData)?;

    // All remaining chunks are to be directly encrypted.

    // Setup the CBC encipher.
    let mut cipher = Aes256CbcEnc::new(key.into(), &IV_ZERO.into());

    // Setup the initial block that contains the confuzzler
    let mut previous_block = [0u8; AES_BLOCK_SIZE];
    previous_block.copy_from_slice(confuzzler);

    // Initially encipher the confuzzler
    cipher.encrypt_block_mut((&mut previous_block).into());
    previous_chunk.copy_from_slice(&previous_block);

    // Now for each chunk, encrypt.
    for (cipher_chunk, plain_chunk) in chunks {
        previous_block.copy_from_slice(plain_chunk);
        cipher.encrypt_block_mut((&mut previous_block).into());
        cipher_chunk.copy_from_slice(&previous_block);
        previous_chunk = cipher_chunk;
    }

    // Now we are positioned. previous_chunk + previous_block both have Cn-1.

    // We have c_n and p_n already positioned from the start.

    let c_n1_chunk = previous_chunk;
    let c_n1_block = previous_block;

    let p_n_star_len = p_n_star_chunk.len();

    debug_assert!(*c_n1_chunk == c_n1_block);

    let mut c_n_block: Aes256Block = [0u8; AES_BLOCK_SIZE].into();

    let (p_n_star, c_n_star_2) = c_n_block.split_at_mut(p_n_star_len);
    p_n_star.copy_from_slice(p_n_star_chunk);

    let (c_n1_star, c_n1_star_2) = c_n1_block.split_at(p_n_star_len);
    c_n_star_2.copy_from_slice(c_n1_star_2);

    for i in 0..p_n_star_len {
        p_n_star[i] ^= c_n1_star[i];
    }

    let mut raw_cipher = Aes256::new(key.into());
    raw_cipher.encrypt_block_mut(&mut c_n_block);

    // We now have c_n_block and c_n1_star. This is where we apply the CS3 / CTS
    // swap.
    c_n1_chunk.copy_from_slice(&c_n_block);
    c_n_chunk.copy_from_slice(c_n1_star);

    Ok(())
}

fn decrypt_aes256_cts(key: &[u8; AES_256_KEY_LEN], ciphertext: &[u8]) -> Result<Vec<u8>, KrbError> {
    // Should not be possible
    debug_assert!(!ciphertext.is_empty());

    let ctxt_len = ciphertext.len();

    let num_blocks = ctxt_len / AES_BLOCK_SIZE;
    let mut cipher = Aes256CbcDec::new(key.into(), &IV_ZERO.into());

    if num_blocks == 0 {
        // Impossible in krb because the first block is always the confounder.
        return Err(KrbError::CtsCiphertextInvalid);
    }

    // Fill with zeros
    let mut plaintext = vec![0; ctxt_len];

    let plaintext_chunks = plaintext.chunks_mut(AES_BLOCK_SIZE);
    let ciphertext_chunks = ciphertext.chunks(AES_BLOCK_SIZE);

    let mut chunks = std::iter::zip(ciphertext_chunks, plaintext_chunks);

    // Remove the last two blocks from the right. These are "special" in CTS.
    let (c_n1_chunk, p_n_chunk) = chunks.next_back().ok_or(KrbError::InsufficientData)?;
    // Penultimate chunk
    let (c_n_chunk, p_n1_chunk) = chunks.next_back().ok_or(KrbError::InsufficientData)?;

    // Now process the other chunks as normal. CTS aka CS3 is just CBC with
    // bad vibes at the end.
    // .encrypt_block_b2b_mut(plaintext, out_buf)

    for (cipher_chunk, plain_chunk) in chunks {
        cipher.decrypt_block_b2b_mut(cipher_chunk.into(), plain_chunk.into())
    }

    // Now we have to process the last two blocks. To understand why we need
    // to look at the encryption process.
    // CTS or CS3 from nist SP800-38A defines our chunks in the cipher text as:
    //
    // C1 || C2 || ... || Cn-2 || Cn-1 || Cn
    //
    // Similar plaintext is
    //
    // P1 || P2 || ... || Pn-2 || Pn-1 || Pn
    //
    // The spec will denote Cn-1* as the MSB of Cn-1 and Cn-1** as the LSB to
    // some length d.
    //
    // In the encryption of CS1 when Pn doesn't make a full block, then Pn is
    // padded with 0 and XORed with Cn-1 (per cbc). But before the cipher is
    // applied then Pn is XORed with Cn-1* and has Cn-2** appended.This is then
    // put through the cipher.
    //
    // CS3 is an alteration of CS1 where Cn-1 and Cn are always
    // swapped so we know what blocks are what.
    //
    // C1 || C2 || ... || Cn-2 || Cn || Cn-1
    //
    // So to decrypt we do CBC up to Cn-2.
    // At that point we need to decrypt Cn with AES ECB. This gives us Z* and
    // Z**.
    //
    // We can then XOR Z* with Cn-1* to get Pn*. Finally we can perform
    // The last decryption with Cn-1* concat Z** via CBC mode to finish the
    // decryption.
    //
    // This weird dance ends up that if we are block aligned it's just CBC with
    // the last two blocks swapped basicly.

    // We need a scratch block.
    let mut z: Aes256Block = [0u8; AES_BLOCK_SIZE].into();
    let mut raw_cipher = Aes256::new(key.into());

    let z_star_len = c_n1_chunk.len();

    // Decrypt Cn
    raw_cipher.decrypt_block_b2b_mut(c_n_chunk.into(), &mut z);

    // Block is now Z.
    let (z_star, z_star_2) = z.split_at(z_star_len);

    debug_assert!(z_star_2.len() + c_n1_chunk.len() == AES_BLOCK_SIZE);

    debug_assert!(z_star.len() == p_n_chunk.len());

    for i in 0..z_star.len() {
        p_n_chunk[i] = c_n1_chunk[i] ^ z_star[i];
    }

    // Pn is complete.
    let mut cn1_block: Aes256Block = [0u8; AES_BLOCK_SIZE].into();

    // We concat the two slices here.
    let (cn1_block_star, cn1_block_star_2) = cn1_block.split_at_mut(c_n1_chunk.len());
    cn1_block_star.copy_from_slice(c_n1_chunk);
    cn1_block_star_2.copy_from_slice(z_star_2);

    // We can re-use the existing cbc cipher as it has the correct state
    // of the cbc mode.
    cipher.decrypt_block_b2b_mut(&cn1_block, p_n1_chunk.into());

    Ok(plaintext)
}

pub(crate) fn checksum_hmac_sha1_96_aes256(
    plaintext: &[u8],
    key: &[u8; AES_256_KEY_LEN],
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
    use crate::constants::{AES_256_KEY_LEN, RFC_PBKDF2_SHA1_ITER};
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
            out_key,
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
            out_key,
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
            out_key,
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

        let mut b: [u8; AES_256_KEY_LEN] = [0; AES_256_KEY_LEN];
        b.clone_from_slice(base_key.as_slice());

        let kc = dk_kc_aes_256(&b, 6);

        assert_eq_hex!(kc, derived_key.as_slice());

        let mut mac = HmacSha1::new_from_slice(&derived_key).unwrap();
        mac.update(&input);

        let mut buf = [0u8; 20];
        mac.finalize_into((&mut buf).into());

        // Truncate to 96 bits.
        let my_hmac = &buf[0..SHA1_HMAC_LEN];
        assert_eq_hex!(my_hmac, checksum);
    }
}
