//! Node key derivation from lightningd's `hsm_secret`.
//!
//! CLN derives its node key from `hsm_secret` using HKDF-SHA256
//! (salt = little-endian u32 counter, ikm = first 32 bytes of the extracted HSM
//! secret material, info = "nodeid", length = 32).
//! We replicate this to sign hosted-channel state with the node key,
//! which is what clients verify against (the node's public key).

use bip39::Mnemonic;
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use secp256k1::{PublicKey, SecretKey};
use sha2::{Digest, Sha256};
use std::path::Path;
use thiserror::Error;
use zeroize::Zeroize;

const LEGACY_PLAIN_LEN: usize = 32;
const LEGACY_ENCRYPTED_LEN: usize = 73;
const PASSPHRASE_HASH_LEN: usize = 32;
const NODE_KEY_IKM_LEN: usize = 32;
const LEGACY_ENCRYPTED_HEADER_LEN: usize = 24;
const LEGACY_ENCRYPTED_CIPHERTEXT_LEN: usize = 49;
const CLN_ARGON2ID_SALT: [u8; 16] = [
    b'c', b'-', b'l', b'i', b'g', b'h', b't', b'n', b'i', b'n', b'g', 0, 0, 0, 0, 0,
];

#[derive(Debug, Error)]
pub enum KeyError {
    #[error("cannot read hsm_secret at {0}: {1}")]
    Read(String, std::io::Error),
    #[error("hsm_secret at {0} has invalid format (got {1} bytes)")]
    InvalidFormat(String, usize),
    #[error("hsm_secret at {0} requires a passphrase")]
    PassphraseRequired(String),
    #[error("hsm_secret at {0} does not use a passphrase")]
    PassphraseNotNeeded(String),
    #[error("wrong hsm_secret passphrase for {0}")]
    WrongPassphrase(String),
    #[error("invalid hsm_secret mnemonic at {0}: {1}")]
    InvalidMnemonic(String, String),
    #[error("cannot decrypt hsm_secret at {0}: {1}")]
    Decrypt(String, String),
    #[error("invalid node secret key: {0}")]
    InvalidKey(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HsmSecretKind {
    LegacyPlain,
    LegacyEncrypted,
    MnemonicNoPassphrase,
    MnemonicWithPassphrase,
    Invalid,
}

pub fn detect_hsm_secret_kind(data: &[u8]) -> HsmSecretKind {
    if data.len() < LEGACY_PLAIN_LEN {
        HsmSecretKind::Invalid
    } else if data.len() == LEGACY_PLAIN_LEN {
        HsmSecretKind::LegacyPlain
    } else if data.len() == LEGACY_ENCRYPTED_LEN {
        HsmSecretKind::LegacyEncrypted
    } else if data[..PASSPHRASE_HASH_LEN].iter().all(|b| *b == 0) {
        HsmSecretKind::MnemonicNoPassphrase
    } else {
        HsmSecretKind::MnemonicWithPassphrase
    }
}

/// The node's signing keypair, derived from hsm_secret.
///
/// The secret key is zeroized on drop.
pub struct NodeKeys {
    pub secret: SecretKey,
    pub public: PublicKey,
}

impl Drop for NodeKeys {
    fn drop(&mut self) {
        // SecretKey内部のバイトをゼロ化
        let bytes = self.secret.secret_bytes();
        let mut bytes = bytes;
        bytes.zeroize();
    }
}

impl NodeKeys {
    /// Derive from a raw 32-byte hsm_secret.
    pub fn from_hsm_secret(hsm_secret: &[u8]) -> Result<Self, KeyError> {
        if hsm_secret.len() != NODE_KEY_IKM_LEN {
            return Err(KeyError::InvalidFormat(
                "<memory>".to_string(),
                hsm_secret.len(),
            ));
        }
        Self::from_secret_material(hsm_secret)
    }

    fn from_secret_material(secret_material: &[u8]) -> Result<Self, KeyError> {
        if secret_material.len() < NODE_KEY_IKM_LEN {
            return Err(KeyError::InvalidFormat(
                "<memory>".to_string(),
                secret_material.len(),
            ));
        }

        let mut okm = [0u8; 32];
        let mut salt_counter = 0u32;
        let secret = loop {
            let salt = salt_counter.to_ne_bytes();
            let hk = Hkdf::<Sha256>::new(Some(&salt), &secret_material[..NODE_KEY_IKM_LEN]);
            hk.expand(b"nodeid", &mut okm)
                .map_err(|e| KeyError::InvalidKey(e.to_string()))?;
            match SecretKey::from_slice(&okm) {
                Ok(secret) => break secret,
                Err(_) => {
                    salt_counter = salt_counter
                        .checked_add(1)
                        .ok_or_else(|| KeyError::InvalidKey("salt counter overflow".into()))?;
                }
            }
        };

        okm.zeroize();

        let secp = secp256k1::Secp256k1::new();
        let public = secp256k1::PublicKey::from_secret_key(&secp, &secret);

        Ok(NodeKeys { secret, public })
    }

    pub fn from_hsm_secret_bytes(data: &[u8], passphrase: Option<&str>) -> Result<Self, KeyError> {
        let mut material = extract_hsm_secret_material("<memory>", data, passphrase)?;
        let result = Self::from_secret_material(&material);
        material.zeroize();
        result
    }

    /// Read the hsm_secret file and derive the node keys.
    pub fn from_file(path: impl AsRef<Path>) -> Result<Self, KeyError> {
        Self::from_file_with_passphrase(path, None)
    }

    pub fn from_file_with_passphrase(
        path: impl AsRef<Path>,
        passphrase: Option<&str>,
    ) -> Result<Self, KeyError> {
        let path = path.as_ref();
        let path_str = path.to_string_lossy().to_string();
        let mut data = std::fs::read(path).map_err(|e| KeyError::Read(path_str.clone(), e))?;
        let result =
            Self::from_hsm_secret_bytes(&data, passphrase).map_err(|e| e.with_path(path_str));
        data.zeroize();
        result
    }
}

impl KeyError {
    fn with_path(self, path: String) -> Self {
        match self {
            KeyError::InvalidFormat(_, len) => KeyError::InvalidFormat(path, len),
            KeyError::PassphraseRequired(_) => KeyError::PassphraseRequired(path),
            KeyError::PassphraseNotNeeded(_) => KeyError::PassphraseNotNeeded(path),
            KeyError::WrongPassphrase(_) => KeyError::WrongPassphrase(path),
            KeyError::InvalidMnemonic(_, reason) => KeyError::InvalidMnemonic(path, reason),
            KeyError::Decrypt(_, reason) => KeyError::Decrypt(path, reason),
            other => other,
        }
    }
}

fn extract_hsm_secret_material(
    path: &str,
    data: &[u8],
    passphrase: Option<&str>,
) -> Result<Vec<u8>, KeyError> {
    match detect_hsm_secret_kind(data) {
        HsmSecretKind::LegacyPlain => {
            if passphrase.is_some() {
                return Err(KeyError::PassphraseNotNeeded(path.to_string()));
            }
            Ok(data.to_vec())
        }
        HsmSecretKind::LegacyEncrypted => decrypt_legacy_hsm_secret(path, data, passphrase),
        HsmSecretKind::MnemonicNoPassphrase => extract_mnemonic_secret(path, data, passphrase),
        HsmSecretKind::MnemonicWithPassphrase => extract_mnemonic_secret(path, data, passphrase),
        HsmSecretKind::Invalid => Err(KeyError::InvalidFormat(path.to_string(), data.len())),
    }
}

fn decrypt_legacy_hsm_secret(
    path: &str,
    data: &[u8],
    passphrase: Option<&str>,
) -> Result<Vec<u8>, KeyError> {
    let passphrase = passphrase.ok_or_else(|| KeyError::PassphraseRequired(path.to_string()))?;
    let mut key_bytes = [0u8; 32];
    let params = argon2::Params::new(268_435_456, 3, 1, Some(key_bytes.len()))
        .map_err(|e| KeyError::Decrypt(path.to_string(), e.to_string()))?;
    let argon2 = argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
    argon2
        .hash_password_into(passphrase.as_bytes(), &CLN_ARGON2ID_SALT, &mut key_bytes)
        .map_err(|_| KeyError::WrongPassphrase(path.to_string()))?;

    let cipher = XChaCha20Poly1305::new(Key::from_slice(&key_bytes));
    let nonce = XNonce::from_slice(&data[..LEGACY_ENCRYPTED_HEADER_LEN]);
    let plaintext = cipher
        .decrypt(nonce, &data[LEGACY_ENCRYPTED_HEADER_LEN..])
        .map_err(|_| KeyError::WrongPassphrase(path.to_string()))?;
    key_bytes.zeroize();

    if plaintext.len() != LEGACY_PLAIN_LEN {
        return Err(KeyError::Decrypt(
            path.to_string(),
            format!("decrypted secret is {} bytes", plaintext.len()),
        ));
    }
    debug_assert_eq!(
        data.len() - LEGACY_ENCRYPTED_HEADER_LEN,
        LEGACY_ENCRYPTED_CIPHERTEXT_LEN
    );
    Ok(plaintext)
}

fn extract_mnemonic_secret(
    path: &str,
    data: &[u8],
    passphrase: Option<&str>,
) -> Result<Vec<u8>, KeyError> {
    let kind = detect_hsm_secret_kind(data);
    let mnemonic = std::str::from_utf8(&data[PASSPHRASE_HASH_LEN..])
        .map_err(|e| KeyError::InvalidMnemonic(path.to_string(), e.to_string()))?;
    let mnemonic = Mnemonic::parse_normalized(mnemonic)
        .map_err(|e| KeyError::InvalidMnemonic(path.to_string(), e.to_string()))?;
    let passphrase = match (kind, passphrase) {
        (HsmSecretKind::MnemonicNoPassphrase, None) => "",
        (HsmSecretKind::MnemonicNoPassphrase, Some(_)) => {
            return Err(KeyError::PassphraseNotNeeded(path.to_string()))
        }
        (HsmSecretKind::MnemonicWithPassphrase, Some(passphrase)) => passphrase,
        (HsmSecretKind::MnemonicWithPassphrase, None) => {
            return Err(KeyError::PassphraseRequired(path.to_string()))
        }
        _ => unreachable!("only mnemonic kinds call extract_mnemonic_secret"),
    };
    let seed = mnemonic.to_seed(passphrase);
    if kind == HsmSecretKind::MnemonicWithPassphrase {
        let hash = Sha256::digest(seed);
        if hash.as_slice() != &data[..PASSPHRASE_HASH_LEN] {
            return Err(KeyError::WrongPassphrase(path.to_string()));
        }
    }
    Ok(seed.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derive_from_known_hsm_secret() {
        let hsm = [0x42u8; 32];
        let keys = NodeKeys::from_hsm_secret(&hsm).unwrap();
        // The public key should be valid and deterministic
        let keys2 = NodeKeys::from_hsm_secret(&hsm).unwrap();
        assert_eq!(keys.public, keys2.public);
    }

    #[test]
    fn wrong_size_hsm_secret() {
        let hsm = [0u8; 31];
        assert!(NodeKeys::from_hsm_secret(&hsm).is_err());
    }

    #[test]
    fn different_hsm_gives_different_keys() {
        let keys1 = NodeKeys::from_hsm_secret(&[0x01u8; 32]).unwrap();
        let keys2 = NodeKeys::from_hsm_secret(&[0x02u8; 32]).unwrap();
        assert_ne!(keys1.public, keys2.public);
    }

    #[test]
    fn from_file_roundtrip() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let hsm = [0xAAu8; 32];
        std::fs::write(tmp.path(), hsm).unwrap();
        let keys = NodeKeys::from_file(tmp.path()).unwrap();
        let keys2 = NodeKeys::from_hsm_secret(&hsm).unwrap();
        assert_eq!(keys.public, keys2.public);
    }

    #[test]
    fn detects_hsm_secret_kinds() {
        assert_eq!(detect_hsm_secret_kind(&[0u8; 31]), HsmSecretKind::Invalid);
        assert_eq!(
            detect_hsm_secret_kind(&[0u8; 32]),
            HsmSecretKind::LegacyPlain
        );
        assert_eq!(
            detect_hsm_secret_kind(&[0u8; 73]),
            HsmSecretKind::LegacyEncrypted
        );

        let mut mnemonic = vec![0u8; 32];
        mnemonic.extend_from_slice(b"abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about");
        assert_eq!(
            detect_hsm_secret_kind(&mnemonic),
            HsmSecretKind::MnemonicNoPassphrase
        );
        mnemonic[0] = 1;
        assert_eq!(
            detect_hsm_secret_kind(&mnemonic),
            HsmSecretKind::MnemonicWithPassphrase
        );
    }

    #[test]
    fn mnemonic_without_passphrase_derives_key() {
        let phrase = b"abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let mut data = vec![0u8; 32];
        data.extend_from_slice(phrase);

        let keys = NodeKeys::from_hsm_secret_bytes(&data, None).unwrap();
        let keys2 = NodeKeys::from_hsm_secret_bytes(&data, None).unwrap();
        assert_eq!(keys.public, keys2.public);
        assert!(matches!(
            NodeKeys::from_hsm_secret_bytes(&data, Some("unused")),
            Err(KeyError::PassphraseNotNeeded(_))
        ));
    }

    #[test]
    fn mnemonic_with_passphrase_checks_hash() {
        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let passphrase = "correct horse battery staple";
        let mnemonic = Mnemonic::parse_normalized(phrase).unwrap();
        let seed = mnemonic.to_seed(passphrase);
        let hash = Sha256::digest(seed);

        let mut data = hash.to_vec();
        data.extend_from_slice(phrase.as_bytes());
        let keys = NodeKeys::from_hsm_secret_bytes(&data, Some(passphrase)).unwrap();
        let keys2 = NodeKeys::from_hsm_secret_bytes(&data, Some(passphrase)).unwrap();
        assert_eq!(keys.public, keys2.public);
        assert!(matches!(
            NodeKeys::from_hsm_secret_bytes(&data, None),
            Err(KeyError::PassphraseRequired(_))
        ));
        assert!(matches!(
            NodeKeys::from_hsm_secret_bytes(&data, Some("wrong")),
            Err(KeyError::WrongPassphrase(_))
        ));
    }
}
