//! Cryptographic helpers for Proton Drive.
//!
//! Proton Drive uses OpenPGP (via rpgp) for:
//! - Encrypting the share-key passphrase with the address key.
//! - Encrypting each node-key passphrase with the parent node key.
//! - Encrypting file/folder names with the parent node key.
//!
//! File content blocks use **AES-256-CBC** with a session key obtained by
//! decrypting the link's `content_key_packet` (a base64-encoded OpenPGP
//! PKESK packet) with the node's unlocked private key.

use std::io::Cursor;

use aes::cipher::{
    block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyIvInit,
};
use base64::{Engine, engine::general_purpose::STANDARD};
use pgp::composed::cleartext::CleartextSignedMessage;
use pgp::composed::KeyType;
use pgp::crypto::hash::HashAlgorithm;
use pgp::crypto::sym::SymmetricKeyAlgorithm;
use pgp::types::{PublicKeyTrait, SecretKeyTrait};
use pgp::{ArmorOptions, Deserializable, Message, SignedPublicKey, SignedSecretKey};
use rand::rngs::OsRng;

use crate::{Error, Result};

type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;
type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;

/// Decrypt a PGP-armored message using the supplied key.
///
/// # Arguments
/// - `armored_msg`  — PGP-armored ciphertext (the message to decrypt).
/// - `armored_key`  — PGP-armored secret key that the message is encrypted to.
/// - `key_passphrase` — Passphrase that unlocks `armored_key`.
///                      Pass an empty slice if the key has no passphrase.
///
/// # Returns
/// The raw plaintext bytes of the decrypted message.
pub fn pgp_decrypt(
    armored_msg: &str,
    armored_key: &str,
    key_passphrase: &[u8],
) -> Result<Vec<u8>> {
    let (key, _) = SignedSecretKey::from_armor_single(Cursor::new(armored_key.as_bytes()))
        .map_err(|e| Error::Crypto(format!("key parse: {e}")))?;

    let (msg, _) = Message::from_armor_single(Cursor::new(armored_msg.as_bytes()))
        .map_err(|e| Error::Crypto(format!("message parse: {e}")))?;

    let pw = String::from_utf8_lossy(key_passphrase).into_owned();
    let (decrypted, _) = msg
        .decrypt(|| pw.clone(), &[&key])
        .map_err(|e| Error::Crypto(format!("decrypt: {e}")))?;

    decrypted
        .get_content()
        .map_err(|e| Error::Crypto(format!("get content: {e}")))?
        .ok_or_else(|| Error::Crypto("decrypted message has no literal content".into()))
}

/// Decrypt a `content_key_packet` (base64-encoded PKESK) using a node's
/// private key, returning the 32-byte session key.
///
/// # Arguments
/// - `b64_key_packet`   — Base64-encoded OpenPGP PKESK packet.
/// - `node_armored_key` — PGP-armored node private key.
/// - `node_passphrase`  — Passphrase that unlocks `node_armored_key`.
pub fn decrypt_session_key(
    b64_key_packet: &str,
    node_armored_key: &str,
    node_passphrase: &[u8],
) -> Result<Vec<u8>> {
    let packet_bytes = STANDARD
        .decode(b64_key_packet)
        .map_err(|e| Error::Crypto(format!("decode key packet: {e}")))?;

    let (key, _) = SignedSecretKey::from_armor_single(Cursor::new(node_armored_key.as_bytes()))
        .map_err(|e| Error::Crypto(format!("node key parse: {e}")))?;

    let msg = Message::from_bytes(Cursor::new(&packet_bytes))
        .map_err(|e| Error::Crypto(format!("parse key packet: {e}")))?;

    let pw = String::from_utf8_lossy(node_passphrase).into_owned();
    let (decrypted, _) = msg
        .decrypt(|| pw.clone(), &[&key])
        .map_err(|e| Error::Crypto(format!("decrypt key packet: {e}")))?;

    decrypted
        .get_content()
        .map_err(|e| Error::Crypto(format!("get content: {e}")))?
        .ok_or_else(|| Error::Crypto("key packet has no content".into()))
}

/// Decrypt a single block of file data using the session key.
///
/// Blocks are encrypted with **AES-256-CBC** using the content key.
/// The IV is derived as `SHA-256(content_key ‖ decimal(block_index))[:16]`.
///
/// # Arguments
/// - `encrypted`   — Raw encrypted block bytes from the pre-signed URL.
/// - `session_key` — 32-byte content key from [`decrypt_session_key`].
/// - `block_index` — Index of the block (0-based), used for IV derivation.
pub fn decrypt_block(encrypted: &[u8], session_key: &[u8], block_index: u32) -> Result<Vec<u8>> {
    use sha2::{Digest, Sha256};

    let iv = {
        let mut hasher = Sha256::new();
        hasher.update(session_key);
        hasher.update(block_index.to_string().as_bytes());
        let hash = hasher.finalize();
        hash[..16].to_vec()
    };

    let mut buf = encrypted.to_vec();
    let pt = Aes256CbcDec::new_from_slices(session_key, &iv)
        .map_err(|e| Error::Crypto(format!("init cipher: {e}")))?
        .decrypt_padded_mut::<Pkcs7>(&mut buf)
        .map_err(|e| Error::Crypto(format!("block decrypt: {e}")))?;

    Ok(pt.to_vec())
}

/// PGP-encrypt plaintext bytes to an armored (public or secret) key.
///
/// Tries parsing the key as a [`SignedPublicKey`] first, falling back to
/// [`SignedSecretKey`] — the latter is needed because [`DriveKeyring`] stores
/// private keys and [`SignedSecretKey`] implements [`PublicKeyTrait`].
pub fn pgp_encrypt(plaintext: &[u8], armored_key: &str) -> Result<String> {
    use rand::rngs::OsRng;

    let msg = Message::new_literal_bytes("", plaintext);

    // Try as public key first, then as secret key.
    if let Ok((pk, _)) = SignedPublicKey::from_armor_single(Cursor::new(armored_key.as_bytes())) {
        let encrypted = msg
            .encrypt_to_keys_seipdv1(OsRng, SymmetricKeyAlgorithm::AES256, &[&pk])
            .map_err(|e| Error::Crypto(format!("encrypt: {e}")))?;
        return encrypted
            .to_armored_string(ArmorOptions::default())
            .map_err(|e| Error::Crypto(format!("armor: {e}")));
    }

    let (sk, _) = SignedSecretKey::from_armor_single(Cursor::new(armored_key.as_bytes()))
        .map_err(|e| Error::Crypto(format!("secret key parse: {e}")))?;
    let encrypted = msg
        .encrypt_to_keys_seipdv1(OsRng, SymmetricKeyAlgorithm::AES256, &[&sk])
        .map_err(|e| Error::Crypto(format!("encrypt: {e}")))?;
    encrypted
        .to_armored_string(ArmorOptions::default())
        .map_err(|e| Error::Crypto(format!("armor: {e}")))
}

/// PGP-encrypt plaintext using an already-parsed secret key (from the keyring).
pub fn pgp_encrypt_to_key(plaintext: &[u8], key: &SignedSecretKey) -> Result<String> {
    use rand::rngs::OsRng;

    let msg = Message::new_literal_bytes("", plaintext);
    let encrypted = msg
        .encrypt_to_keys_seipdv1(OsRng, SymmetricKeyAlgorithm::AES256, &[key])
        .map_err(|e| Error::Crypto(format!("encrypt: {e}")))?;
    encrypted
        .to_armored_string(ArmorOptions::default())
        .map_err(|e| Error::Crypto(format!("armor: {e}")))
}

/// Encrypt a single block of file data with AES-256-CBC.
///
/// IV is derived as `SHA-256(session_key ‖ decimal(block_index))[:16]`.
/// PKCS7 padding is applied automatically.
pub fn encrypt_block(plaintext: &[u8], session_key: &[u8], block_index: u32) -> Result<Vec<u8>> {
    use sha2::{Digest, Sha256};

    let iv = {
        let mut hasher = Sha256::new();
        hasher.update(session_key);
        hasher.update(block_index.to_string().as_bytes());
        let hash = hasher.finalize();
        hash[..16].to_vec()
    };

    let pt_len = plaintext.len();
    // Allocate buffer with extra space for PKCS7 padding (max 16 bytes).
    let block_size = 16usize;
    let pad_max = block_size;
    let mut buf = plaintext.to_vec();
    buf.resize(pt_len + pad_max, 0);

    let ct = Aes256CbcEnc::new_from_slices(session_key, &iv)
        .map_err(|e| Error::Crypto(format!("init cipher: {e}")))?
        .encrypt_padded_mut::<Pkcs7>(&mut buf, pt_len)
        .map_err(|_| Error::Crypto("block encrypt: padding error".into()))?;

    Ok(ct.to_vec())
}

/// Generate a random 32-byte AES session key.
pub fn generate_session_key() -> Vec<u8> {
    use rand::Rng;
    rand::rngs::OsRng.gen::<[u8; 32]>().to_vec()
}

/// Create a base64-encoded content key packet by PGP-encrypting the session
/// key with the node's key (public or private, armored).
pub fn create_content_key_packet(
    session_key: &[u8],
    armored_node_key: &str,
) -> Result<String> {
    use rand::rngs::OsRng;

    // Try as public key first, then as secret key.
    let encrypted = if let Ok((pk, _)) =
        SignedPublicKey::from_armor_single(Cursor::new(armored_node_key.as_bytes()))
    {
        let msg = Message::new_literal_bytes("", session_key);
        msg.encrypt_to_keys_seipdv1(OsRng, SymmetricKeyAlgorithm::AES256, &[&pk])
            .map_err(|e| Error::Crypto(format!("encrypt session key: {e}")))?
    } else {
        let (sk, _) = SignedSecretKey::from_armor_single(Cursor::new(armored_node_key.as_bytes()))
            .map_err(|e| Error::Crypto(format!("secret key parse: {e}")))?;
        let msg = Message::new_literal_bytes("", session_key);
        msg.encrypt_to_keys_seipdv1(OsRng, SymmetricKeyAlgorithm::AES256, &[&sk])
            .map_err(|e| Error::Crypto(format!("encrypt session key: {e}")))?
    };

    let mut buf = Vec::new();
    use pgp::ser::Serialize as PgpSerialize;
    encrypted
        .to_writer(&mut buf)
        .map_err(|e| Error::Crypto(format!("serialize: {e}")))?;

    Ok(STANDARD.encode(&buf))
}

/// Generate a PGP key pair for a new drive node (file or folder).
///
/// Returns `(armored_private_key, passphrase)` where the private key is
/// passphrase-protected and exported in PGP-armored format.
pub fn generate_node_keypair() -> Result<(String, Vec<u8>)> {
    use pgp::composed::SecretKeyParamsBuilder;
    use rand::Rng;
    use smallvec::smallvec;

    let passphrase: Vec<u8> = OsRng.gen::<[u8; 32]>().to_vec();
    let pass_str = hex::encode(&passphrase);

    let mut params = SecretKeyParamsBuilder::default();
    params
        .key_type(KeyType::Rsa(2048))
        .can_certify(false)
        .can_sign(true)
        .primary_user_id("drive-node@proton.local".into())
        .passphrase(Some(pass_str.clone()))
        .preferred_symmetric_algorithms(smallvec![SymmetricKeyAlgorithm::AES256])
        .preferred_hash_algorithms(smallvec![HashAlgorithm::SHA2_256])
        .preferred_compression_algorithms(smallvec![]);

    let built = params
        .build()
        .map_err(|e| Error::Crypto(format!("key params build: {e}")))?;
    let secret_key = built
        .generate(OsRng)
        .map_err(|e| Error::Crypto(format!("key generate: {e}")))?;

    let pass_fn = || pass_str.clone();
    let signed = secret_key
        .sign(OsRng, pass_fn)
        .map_err(|e| Error::Crypto(format!("key sign: {e}")))?;

    // Export as armored private key block.
    let mut buf = Vec::new();
    pgp::armor::write(
        &signed,
        pgp::armor::BlockType::PrivateKey,
        &mut buf,
        None,
        true,
    )
    .map_err(|e| Error::Crypto(format!("armor write: {e}")))?;

    let armored = String::from_utf8(buf)
        .map_err(|e| Error::Crypto(format!("armor utf8: {e}")))?;

    Ok((armored, passphrase))
}

/// PGP-sign data with an armored key, returning an armored signature string.
///
/// `armored_key` must be a passphrase-protected PGP private key.
/// The passphrase is supplied as raw bytes (e.g. the 32-byte key passphrase).
pub fn pgp_sign(data: &[u8], armored_key: &str, passphrase: &[u8]) -> Result<String> {
    use pgp::composed::StandaloneSignature;
    use pgp::packet::Signature;
    use pgp::packet::SignatureType;
    use pgp::types::Version;

    let (key, _) = SignedSecretKey::from_armor_single(Cursor::new(armored_key.as_bytes()))
        .map_err(|e| Error::Crypto(format!("key parse: {e}")))?;

    let pass_str = String::from_utf8_lossy(passphrase).into_owned();
    let sig_bytes = key
        .create_signature(|| pass_str, HashAlgorithm::SHA2_256, data)
        .map_err(|e| Error::Crypto(format!("sign: {e}")))?;

    // Try to extract the hash algorithm and other metadata from the key's own signature packet.
    // We build a minimal v4 signature packet wrapping the raw bytes.
    // The `signed_hash_value` and subpackets are best-effort for now.
    let hashed_subpackets = vec![];
    let unhashed_subpackets = vec![];
    let signed_hash_value = [0u8; 2];

    let sig_packet = Signature::v4(
        Version::New,
        SignatureType::Binary,
        key.algorithm(),
        HashAlgorithm::SHA2_256,
        signed_hash_value,
        sig_bytes,
        hashed_subpackets,
        unhashed_subpackets,
    );

    let standalone = StandaloneSignature::new(sig_packet);
    standalone
        .to_armored_string(None.into())
        .map_err(|e| Error::Crypto(format!("armor signature: {e}")))
}

/// Generate a random 32-byte hash key for name collision detection.
///
/// Each folder has a hash key that is used to compute HMAC-SHA256 of
/// its children's plain-text names.  The key is PGP-encrypted with
/// the folder's node key.
pub fn generate_hash_key() -> Vec<u8> {
    use rand::Rng;
    rand::rngs::OsRng.gen::<[u8; 32]>().to_vec()
}

/// Compute the name hash for collision detection.
///
/// Given a parent folder's decrypted `hash_key` (32 bytes) and a child's
/// `plaintext_name`, returns the hex-encoded HMAC-SHA256.
pub fn compute_name_hash(hash_key: &[u8], plaintext_name: &str) -> String {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    let mut mac = Hmac::<Sha256>::new_from_slice(hash_key)
        .expect("HMAC accepts 32-byte key");
    mac.update(plaintext_name.as_bytes());
    let result = mac.finalize();
    let code = result.into_bytes();
    hex::encode(code)
}

/// Proton's published PGP public key for verifying the SRP modulus signature.
///
/// Fingerprint: `248097092b458509c508dac0350585c4e9518f26`
/// Source: https://github.com/ProtonMail/proton-python-client (constants.py)
const PROTON_SRP_MODULUS_KEY: &str = "-----BEGIN PGP PUBLIC KEY BLOCK-----

xjMEXAHLgxYJKwYBBAHaRw8BAQdAFurWXXwjTemqjD7CXjXVyKf0of7n9Ctm
L8v9enkzggHNEnByb3RvbkBzcnAubW9kdWx1c8J3BBAWCgApBQJcAcuDBgsJ
BwgDAgkQNQWFxOlRjyYEFQgKAgMWAgECGQECGwMCHgEAAPGRAP9sauJsW12U
MnTQUZpsbJb53d0Wv55mZIIiJL2XulpWPQD/V6NglBd96lZKBmInSXX/kXat
Sv+y0io+LR8i2+jV+AbOOARcAcuDEgorBgEEAZdVAQUBAQdAeJHUz1c9+KfE
kSIgcBRE3WuXC4oj5a2/U3oASExGDW4DAQgHwmEEGBYIABMFAlwBy4MJEDUF
hcTpUY8mAhsMAAD/XQD8DxNI6E78meodQI+wLsrKLeHn32iLvUqJbVDhfWSU
WO4BAMcm1u02t4VKw++ttECPt+HUgPUq5pqQWe5Q2cW4TMsE
=Y4Mw
-----END PGP PUBLIC KEY BLOCK-----";

/// Verify the PGP signature on the SRP modulus and return the raw modulus bytes.
///
/// Takes the full PGP-signed message (as returned by `POST /auth/v4/info`),
/// verifies it against Proton's embedded public key, and returns the decoded
/// 256-byte modulus (big-endian).
pub fn verify_modulus_signature(pgp_signed_modulus: &str) -> Result<Vec<u8>> {
    let (signed_msg, _) = CleartextSignedMessage::from_string(pgp_signed_modulus)
        .map_err(|e| Error::Crypto(format!("failed to parse PGP signed message: {e}")))?;

    let (pub_key, _) = SignedPublicKey::from_string(PROTON_SRP_MODULUS_KEY)
        .map_err(|e| Error::Crypto(format!("failed to parse Proton public key: {e}")))?;

    signed_msg
        .verify(&pub_key)
        .map_err(|e| Error::Crypto(format!("modulus signature verification failed: {e}")))?;

    // Extract base64 modulus from the cleartext body.
    // Strip any whitespace since base64::STANDARD is strict.
    let b64: String = signed_msg.text().chars().filter(|c| !c.is_whitespace()).collect();

    STANDARD
        .decode(&b64)
        .map_err(|e| Error::Crypto(format!("modulus base64 decode failed: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verify_modulus_signature_rejects_plain_base64() {
        let err = verify_modulus_signature("aGVsbG8=").unwrap_err();
        assert!(
            err.to_string().contains("failed to parse"),
            "expected parse error, got: {err}"
        );
    }

    #[test]
    fn verify_modulus_signature_rejects_empty_input() {
        let err = verify_modulus_signature("").unwrap_err();
        assert!(
            err.to_string().contains("failed to parse"),
            "expected parse error, got: {err}"
        );
    }
}
