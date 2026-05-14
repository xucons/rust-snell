use aes_gcm::{Aes128Gcm, KeyInit, Nonce};
use aes_gcm::aead::Aead as AeadTrait;
use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::ChaCha20Poly1305;

const ARGON2_OUTPUT_LEN: usize = 32;

pub const PAYLOAD_SIZE_MASK: usize = 0x3FFF;
pub const SALT_SIZE: usize = 16;

fn snell_kdf(psk: &[u8], salt: &[u8], key_size: usize) -> Vec<u8> {
    let params = Params::new(8, 3, 1, Some(ARGON2_OUTPUT_LEN)).unwrap();
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut output = vec![0u8; ARGON2_OUTPUT_LEN];
    argon2.hash_password_into(psk, salt, &mut output).unwrap();
    output[..key_size].to_vec()
}

#[allow(dead_code)]
pub trait Cipher: Send + Sync {
    fn key_size(&self) -> usize;
    fn encrypter(&self, salt: &[u8]) -> Box<dyn AeadCipher>;
    fn decrypter(&self, salt: &[u8]) -> Box<dyn AeadCipher>;
}

pub trait AeadCipher: Send + Sync {
    fn encrypt(&self, nonce: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, String>;
    fn decrypt(&self, nonce: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, String>;
    fn nonce_size(&self) -> usize;
    fn tag_size(&self) -> usize;
}

struct Aes128GcmCipher { psk: Vec<u8> }

impl Cipher for Aes128GcmCipher {
    fn key_size(&self) -> usize { 16 }
    fn encrypter(&self, salt: &[u8]) -> Box<dyn AeadCipher> {
        let key = snell_kdf(&self.psk, salt, 16);
        Box::new(Aes128GcmAead { cipher: Aes128Gcm::new_from_slice(&key).unwrap() })
    }
    fn decrypter(&self, salt: &[u8]) -> Box<dyn AeadCipher> {
        let key = snell_kdf(&self.psk, salt, 16);
        Box::new(Aes128GcmAead { cipher: Aes128Gcm::new_from_slice(&key).unwrap() })
    }
}

struct Aes128GcmAead { cipher: Aes128Gcm }

impl AeadCipher for Aes128GcmAead {
    fn encrypt(&self, nonce: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, String> {
        let n = Nonce::from_slice(nonce);
        self.cipher.encrypt(n, plaintext).map_err(|e| e.to_string())
    }
    fn decrypt(&self, nonce: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, String> {
        let n = Nonce::from_slice(nonce);
        self.cipher.decrypt(n, ciphertext).map_err(|e| e.to_string())
    }
    fn nonce_size(&self) -> usize { 12 }
    fn tag_size(&self) -> usize { 16 }
}

struct ChaCha20Poly1305Cipher { psk: Vec<u8> }

impl Cipher for ChaCha20Poly1305Cipher {
    fn key_size(&self) -> usize { 32 }
    fn encrypter(&self, salt: &[u8]) -> Box<dyn AeadCipher> {
        let key = snell_kdf(&self.psk, salt, 32);
        Box::new(ChaCha20Aead { cipher: ChaCha20Poly1305::new_from_slice(&key).unwrap() })
    }
    fn decrypter(&self, salt: &[u8]) -> Box<dyn AeadCipher> {
        let key = snell_kdf(&self.psk, salt, 32);
        Box::new(ChaCha20Aead { cipher: ChaCha20Poly1305::new_from_slice(&key).unwrap() })
    }
}

struct ChaCha20Aead { cipher: ChaCha20Poly1305 }

impl AeadCipher for ChaCha20Aead {
    fn encrypt(&self, nonce: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, String> {
        let n = chacha20poly1305::Nonce::from_slice(nonce);
        self.cipher.encrypt(n, plaintext).map_err(|e| e.to_string())
    }
    fn decrypt(&self, nonce: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, String> {
        let n = chacha20poly1305::Nonce::from_slice(nonce);
        self.cipher.decrypt(n, ciphertext).map_err(|e| e.to_string())
    }
    fn nonce_size(&self) -> usize { 12 }
    fn tag_size(&self) -> usize { 16 }
}

pub fn new_aes128_gcm(psk: &[u8]) -> Box<dyn Cipher> {
    Box::new(Aes128GcmCipher { psk: psk.to_vec() })
}

pub fn new_chacha20_poly1305(psk: &[u8]) -> Box<dyn Cipher> {
    Box::new(ChaCha20Poly1305Cipher { psk: psk.to_vec() })
}

pub fn increment_nonce(nonce: &mut [u8]) {
    for b in nonce.iter_mut() {
        *b = b.wrapping_add(1);
        if *b != 0 {
            return;
        }
    }
}
