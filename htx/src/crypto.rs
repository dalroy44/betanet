//! Cryptographic primitives for the Betanet HTX protocol.
//!
//! This module provides a high-level API for the cryptographic operations
//! required by the specification, wrapping well-vetted Rust crypto libraries.

use chacha20poly1305::{AeadInPlace, ChaCha20Poly1305, KeyInit, Nonce};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use hkdf::Hkdf;
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};

// Constants from the specification
pub const KEY_SIZE: usize = 32;
pub const NONCE_SIZE: usize = 12;
pub const TAG_SIZE: usize = 16;
pub const SIGNATURE_SIZE: usize = 64;

/// A symmetric encryption key.
#[derive(Clone)]
pub struct SymmetricKey([u8; KEY_SIZE]);

/// A Diffie-Hellman secret key.
pub struct DhSecretKey(StaticSecret);

/// A Diffie-Hellman public key.
pub struct DhPublicKey(PublicKey);

/// An Ed25519 signing key.
pub struct SignSecretKey(SigningKey);

/// An Ed25519 verifying key (public key).
pub struct SignPublicKey(VerifyingKey);


#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("aead decryption failed")]
    DecryptionFailed,
    #[error("hkdf output length is invalid")]
    HkdfInvalidLength,
    #[error("signature verification failed")]
    SignatureVerificationFailed,
}

impl SymmetricKey {
    /// Creates a new symmetric key from a byte array.
    pub fn new(key_bytes: [u8; KEY_SIZE]) -> Self {
        Self(key_bytes)
    }

    /// Encrypts the given plaintext with the given nonce and associated data.
    ///
    /// Returns a Vec<u8> containing the ciphertext and the authentication tag.
    pub fn encrypt(&self, plaintext: &[u8], nonce: &[u8; NONCE_SIZE], aad: &[u8]) -> Vec<u8> {
        let cipher = ChaCha20Poly1305::new_from_slice(&self.0).unwrap();
        let nonce = Nonce::from_slice(nonce);

        let mut buffer = Vec::with_capacity(plaintext.len() + TAG_SIZE);
        buffer.extend_from_slice(plaintext);

        let tag = cipher.encrypt_in_place_detached(nonce, aad, &mut buffer).unwrap();
        buffer.extend_from_slice(&tag);

        buffer
    }

    /// Decrypts the given ciphertext with the given nonce and associated data.
    ///
    /// The ciphertext slice is expected to contain the actual ciphertext followed by the
    /// 16-byte authentication tag.
    ///
    /// Returns a Vec<u8> containing the plaintext if decryption is successful.
    pub fn decrypt(&self, ciphertext_with_tag: &[u8], nonce: &[u8; NONCE_SIZE], aad: &[u8]) -> Result<Vec<u8>, Error> {
        if ciphertext_with_tag.len() < TAG_SIZE {
            return Err(Error::DecryptionFailed);
        }

        let (ciphertext, tag) = ciphertext_with_tag.split_at(ciphertext_with_tag.len() - TAG_SIZE);

        let cipher = ChaCha20Poly1305::new_from_slice(&self.0).unwrap();
        let nonce = Nonce::from_slice(nonce);

        let mut buffer = Vec::with_capacity(ciphertext.len());
        buffer.extend_from_slice(ciphertext);

        cipher.decrypt_in_place_detached(nonce, aad, &mut buffer, tag.into())
            .map_err(|_| Error::DecryptionFailed)?;

        Ok(buffer)
    }
}


/// Derives keying material using HKDF-SHA256.
pub fn hkdf_sha256(salt: Option<&[u8]>, ikm: &[u8], info: Option<&[u8]>, okm: &mut [u8]) -> Result<(), Error> {
    let hk = Hkdf::<Sha256>::new(salt, ikm);
    hk.expand(info.unwrap_or(&[]), okm)
        .map_err(|_| Error::HkdfInvalidLength)
}

/// A Diffie-Hellman shared secret.
pub struct SharedSecret([u8; 32]);

impl DhSecretKey {
    /// Generates a new random Diffie-Hellman secret key.
    pub fn new() -> Self {
        let mut rng = rand::thread_rng();
        Self(StaticSecret::random_from_rng(&mut rng))
    }

    /// Returns the public key corresponding to this secret key.
    pub fn public_key(&self) -> DhPublicKey {
        DhPublicKey(PublicKey::from(&self.0))
    }

    /// Computes the shared secret with a peer's public key.
    pub fn diffie_hellman(&self, public_key: &DhPublicKey) -> SharedSecret {
        SharedSecret(self.0.diffie_hellman(&public_key.0).to_bytes())
    }
}

/// An Ed25519 signature.
pub struct Ed25519Signature(Signature);

impl SignSecretKey {
    /// Generates a new random Ed25519 signing key.
    pub fn new() -> Self {
        let mut rng = rand::thread_rng();
        Self(SigningKey::generate(&mut rng))
    }

    /// Returns the public key corresponding to this secret key.
    pub fn public_key(&self) -> SignPublicKey {
        SignPublicKey(self.0.verifying_key())
    }

    /// Signs a message with this secret key.
    pub fn sign(&self, msg: &[u8]) -> Ed25519Signature {
        Ed25519Signature(self.0.sign(msg))
    }
}

impl SignPublicKey {
    /// Verifies a signature on a message with this public key.
    pub fn verify(&self, msg: &[u8], signature: &Ed25519Signature) -> Result<(), Error> {
        self.0.verify_strict(msg, &signature.0)
            .map_err(|_| Error::SignatureVerificationFailed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aead_roundtrip() {
        let key_bytes = [42u8; KEY_SIZE];
        let key = SymmetricKey::new(key_bytes);
        let nonce = [1u8; NONCE_SIZE];
        let aad = b"additional data";
        let plaintext = b"hello world";

        let ciphertext = key.encrypt(plaintext, &nonce, aad);
        let decrypted = key.decrypt(&ciphertext, &nonce, aad).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn aead_tampered_ciphertext() {
        let key_bytes = [42u8; KEY_SIZE];
        let key = SymmetricKey::new(key_bytes);
        let nonce = [1u8; NONCE_SIZE];
        let aad = b"additional data";
        let plaintext = b"hello world";

        let mut ciphertext = key.encrypt(plaintext, &nonce, aad);
        ciphertext[0] ^= 0xff; // Flip a bit

        let result = key.decrypt(&ciphertext, &nonce, aad);
        assert!(matches!(result, Err(Error::DecryptionFailed)));
    }

    #[test]
    fn hkdf_works() {
        let ikm = &[0x0b; 22];
        let salt = hex::decode("000102030405060708090a0b0c").unwrap();
        let info = hex::decode("f0f1f2f3f4f5f6f7f8f9").unwrap();

        let expected_okm = hex::decode("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865").unwrap();

        let mut okm = vec![0u8; 42];
        hkdf_sha256(Some(&salt), ikm, Some(&info), &mut okm).unwrap();

        assert_eq!(okm, expected_okm);
    }

    #[test]
    fn dh_roundtrip() {
        let alice_sk = DhSecretKey::new();
        let alice_pk = alice_sk.public_key();

        let bob_sk = DhSecretKey::new();
        let bob_pk = bob_sk.public_key();

        let shared_secret_alice = alice_sk.diffie_hellman(&bob_pk);
        let shared_secret_bob = bob_sk.diffie_hellman(&alice_pk);

        assert_eq!(shared_secret_alice.0, shared_secret_bob.0);
    }

    #[test]
    fn signature_roundtrip() {
        let sk = SignSecretKey::new();
        let pk = sk.public_key();
        let msg = b"test message";

        let signature = sk.sign(msg);
        assert!(pk.verify(msg, &signature).is_ok());
    }

    #[test]
    fn signature_fails_wrong_key() {
        let sk1 = SignSecretKey::new();
        let sk2 = SignSecretKey::new();
        let pk2 = sk2.public_key();
        let msg = b"test message";

        let signature = sk1.sign(msg);
        assert!(pk2.verify(msg, &signature).is_err());
    }
}
