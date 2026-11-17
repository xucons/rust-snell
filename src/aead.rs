use std::fmt;

use aes_gcm::aead::Aead as AeadTrait;
use aes_gcm::{Aes128Gcm, KeyInit, Nonce};
use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::ChaCha20Poly1305;

const ARGON2_OUTPUT_LEN: usize = 32;

pub const PAYLOAD_SIZE_MASK: usize = 0x3FFF;
pub const SALT_SIZE: usize = 16;

/// AEAD 加解密失败。失败原因对调用方没有更多可用的细节，因此只区分方向。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AeadError {
    Encrypt,
    Decrypt,
}

impl fmt::Display for AeadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Encrypt => f.write_str("AEAD encryption failed"),
            Self::Decrypt => f.write_str("AEAD decryption failed"),
        }
    }
}

impl std::error::Error for AeadError {}

/// 与参考实现一致的 Argon2id 派生：t=3, m=8 KiB, p=1，统一派生 32 字节后截断。
fn snell_kdf(psk: &[u8], salt: &[u8], key_size: usize) -> Vec<u8> {
    let params =
        Params::new(8, 3, 1, Some(ARGON2_OUTPUT_LEN)).expect("fixed Argon2 parameters are valid");
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut output = vec![0u8; ARGON2_OUTPUT_LEN];
    argon2
        .hash_password_into(psk, salt, &mut output)
        .expect("Argon2id with fixed parameters cannot fail");
    output[..key_size].to_vec()
}

/// Snell 使用的 AEAD 密码套件。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CipherKind {
    Aes128Gcm,
    ChaCha20Poly1305,
}

/// 保存 PSK 的密码套件工厂。`Debug` 输出会隐藏 PSK。
#[derive(Clone)]
pub struct Cipher {
    kind: CipherKind,
    psk: Vec<u8>,
}

impl fmt::Debug for Cipher {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Cipher")
            .field("kind", &self.kind)
            .field("psk", &"***")
            .finish()
    }
}

impl Cipher {
    pub fn new(kind: CipherKind, psk: &[u8]) -> Self {
        Self {
            kind,
            psk: psk.to_vec(),
        }
    }

    /// 用给定 salt 派生本方向的 AEAD 实例。
    pub fn aead(&self, salt: &[u8]) -> AeadCipher {
        match self.kind {
            CipherKind::Aes128Gcm => {
                let key = snell_kdf(&self.psk, salt, 16);
                AeadCipher::Aes128Gcm(Box::new(
                    Aes128Gcm::new_from_slice(&key).expect("AES-128 key is 16 bytes"),
                ))
            }
            CipherKind::ChaCha20Poly1305 => {
                let key = snell_kdf(&self.psk, salt, 32);
                AeadCipher::ChaCha20Poly1305(Box::new(
                    ChaCha20Poly1305::new_from_slice(&key).expect("ChaCha20 key is 32 bytes"),
                ))
            }
        }
    }
}

/// 一个方向的 AEAD 实例。
pub enum AeadCipher {
    Aes128Gcm(Box<Aes128Gcm>),
    ChaCha20Poly1305(Box<ChaCha20Poly1305>),
}

impl fmt::Debug for AeadCipher {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Aes128Gcm(_) => f.write_str("AeadCipher::Aes128Gcm"),
            Self::ChaCha20Poly1305(_) => f.write_str("AeadCipher::ChaCha20Poly1305"),
        }
    }
}

impl AeadCipher {
    pub const NONCE_SIZE: usize = 12;
    pub const TAG_SIZE: usize = 16;

    pub fn encrypt(&self, nonce: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, AeadError> {
        match self {
            Self::Aes128Gcm(cipher) => cipher
                .encrypt(Nonce::from_slice(nonce), plaintext)
                .map_err(|_| AeadError::Encrypt),
            Self::ChaCha20Poly1305(cipher) => cipher
                .encrypt(chacha20poly1305::Nonce::from_slice(nonce), plaintext)
                .map_err(|_| AeadError::Encrypt),
        }
    }

    pub fn decrypt(&self, nonce: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, AeadError> {
        match self {
            Self::Aes128Gcm(cipher) => cipher
                .decrypt(Nonce::from_slice(nonce), ciphertext)
                .map_err(|_| AeadError::Decrypt),
            Self::ChaCha20Poly1305(cipher) => cipher
                .decrypt(chacha20poly1305::Nonce::from_slice(nonce), ciphertext)
                .map_err(|_| AeadError::Decrypt),
        }
    }
}

/// Snell 的 nonce 是 12 字节小端计数器：先递增第一个字节，溢出时向后续字节进位。
pub fn increment_nonce(nonce: &mut [u8]) {
    for b in nonce.iter_mut() {
        *b = b.wrapping_add(1);
        if *b != 0 {
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SALT: &[u8] = b"0123456789abcdef";

    #[test]
    fn nonce_increments_little_endian_with_carry() {
        let mut nonce = [0u8; 12];
        increment_nonce(&mut nonce);
        assert_eq!(nonce[0], 1);

        nonce[0] = 0xFF;
        nonce[1] = 0x01;
        increment_nonce(&mut nonce);
        assert_eq!(nonce[0], 0);
        assert_eq!(nonce[1], 2);

        let mut all_ones = [0xFFu8; 12];
        increment_nonce(&mut all_ones);
        assert_eq!(all_ones, [0u8; 12]);
    }

    #[test]
    fn kdf_is_deterministic_and_matches_requested_length() {
        let a = snell_kdf(b"test-psk", SALT, 16);
        let b = snell_kdf(b"test-psk", SALT, 16);
        assert_eq!(a, b);
        assert_eq!(a.len(), 16);
        assert_eq!(snell_kdf(b"test-psk", SALT, 32).len(), 32);
        assert_ne!(
            snell_kdf(b"test-psk", SALT, 16),
            snell_kdf(b"test-psk", b"fedcba9876543210", 16)
        );
    }

    #[test]
    fn aes_gcm_roundtrip() {
        let cipher = Cipher::new(CipherKind::Aes128Gcm, b"test-psk");
        let aead = cipher.aead(SALT);
        let nonce = [0u8; 12];
        let encrypted = aead.encrypt(&nonce, b"hello").unwrap();
        assert_eq!(aead.decrypt(&nonce, &encrypted).unwrap(), b"hello");
    }

    #[test]
    fn chacha20_roundtrip() {
        let cipher = Cipher::new(CipherKind::ChaCha20Poly1305, b"test-psk");
        let aead = cipher.aead(SALT);
        let nonce = [0u8; 12];
        let encrypted = aead.encrypt(&nonce, b"hello").unwrap();
        assert_eq!(aead.decrypt(&nonce, &encrypted).unwrap(), b"hello");
    }

    #[test]
    fn rejects_tampered_ciphertext() {
        let cipher = Cipher::new(CipherKind::Aes128Gcm, b"test-psk");
        let aead = cipher.aead(SALT);
        let nonce = [0u8; 12];
        let mut encrypted = aead.encrypt(&nonce, b"hello").unwrap();
        encrypted[0] ^= 0xFF;
        assert_eq!(aead.decrypt(&nonce, &encrypted), Err(AeadError::Decrypt));
    }

    #[test]
    fn cipher_debug_hides_psk() {
        let cipher = Cipher::new(CipherKind::Aes128Gcm, b"super-secret");
        let text = format!("{cipher:?}");
        assert!(!text.contains("super-secret"));
        assert!(text.contains("***"));
    }
}
