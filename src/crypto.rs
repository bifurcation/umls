use crate::common::*;
use crate::io::*;
use crate::syntax::*;
use crate::{mls_newtype_opaque, mls_newtype_primitive};

use core::marker::PhantomData;
use core::ops::{Deref, DerefMut};
use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use heapless::Vec;
use rand_core::CryptoRngCore;
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey, StaticSecret};

pub mod consts {
    use super::CipherSuite;

    pub const CIPHER_SUITE: CipherSuite = CipherSuite(0x0001);

    pub const HASH_OUTPUT_SIZE: usize = 32;

    pub const HPKE_PRIVATE_KEY_SIZE: usize = 32;
    pub const HPKE_PUBLIC_KEY_SIZE: usize = 32;
    pub const HPKE_KEM_OUTPUT_SIZE: usize = HPKE_PUBLIC_KEY_SIZE;
    pub const HPKE_KEM_SECRET_SIZE: usize = HASH_OUTPUT_SIZE;

    pub const SIGNATURE_PRIVATE_KEY_SIZE: usize = 64;
    pub const SIGNATURE_PUBLIC_KEY_SIZE: usize = 32;
    pub const SIGNATURE_SIZE: usize = 64;

    pub const AEAD_OVERHEAD: usize = 16;
    pub const AEAD_KEY_SIZE: usize = 16;
    pub const AEAD_NONCE_SIZE: usize = 12;
}

mls_newtype_primitive! { CipherSuite + CipherSuiteView => u16 }

pub use consts::AEAD_OVERHEAD;
pub use consts::CIPHER_SUITE;

mls_newtype_opaque! {
    HashOutput + HashOutputView,
    consts::HASH_OUTPUT_SIZE
}

mls_newtype_opaque! {
    HpkePrivateKey + HpkePrivateKeyView,
    consts::HPKE_PRIVATE_KEY_SIZE
}

mls_newtype_opaque! {
    HpkePublicKey + HpkePublicKeyView,
    consts::HPKE_PUBLIC_KEY_SIZE
}

mls_newtype_opaque! {
    HpkeKemOutput + HpkeKemOutputView,
    consts::HPKE_KEM_OUTPUT_SIZE
}

mls_newtype_opaque! {
    HpkeKemSecret + HpkeKemSecretView,
    consts::HPKE_KEM_SECRET_SIZE
}

mls_newtype_opaque! {
    SignaturePrivateKey + SignaturePrivateKeyView,
    consts::SIGNATURE_PRIVATE_KEY_SIZE
}

mls_newtype_opaque! {
    SignaturePublicKey + SignaturePublicKeyView,
    consts::SIGNATURE_PUBLIC_KEY_SIZE
}

mls_newtype_opaque! {
    Signature + SignatureView,
    consts::SIGNATURE_SIZE
}

mls_newtype_opaque! {
    AeadKey + AeadKeyView,
    consts::SIGNATURE_SIZE
}

mls_newtype_opaque! {
    AeadNonce + AeadNonceView,
    consts::SIGNATURE_SIZE
}

pub struct Hash {
    hash: Sha256,
}

impl Hash {
    pub fn new() -> Self {
        Self {
            hash: Sha256::new(),
        }
    }

    pub fn finalize(self) -> HashOutput {
        let digest = self.hash.finalize();
        HashOutput::try_from(digest.as_slice()).unwrap()
    }
}

impl Write for Hash {
    fn write(&mut self, data: &[u8]) -> Result<()> {
        self.hash.update(data);
        Ok(())
    }
}

pub fn generate_sig(
    rng: &mut impl CryptoRngCore,
) -> Result<(SignaturePrivateKey, SignaturePublicKey)> {
    let raw_priv = SigningKey::generate(rng);
    let raw_pub = raw_priv.verifying_key();

    let priv_bytes = raw_priv.to_keypair_bytes();
    let pub_bytes = raw_pub.to_bytes();

    let signature_priv = SignaturePrivateKey::try_from(priv_bytes.as_slice()).unwrap();
    let signature_key = SignaturePublicKey::try_from(pub_bytes.as_slice()).unwrap();

    Ok((signature_priv, signature_key))
}

/*
struct {
    opaque label<V>;
    opaque content<V>;
} SignContent;
*/
fn signature_digest(message: &[u8], label: &[u8]) -> Result<HashOutput> {
    let mut h = Hash::new();

    Varint(label.len()).serialize(&mut h)?;
    h.write(label)?;

    Varint(message.len()).serialize(&mut h)?;
    h.write(message)?;

    Ok(h.finalize())
}

pub fn sign_with_label(
    message: &[u8],
    label: &[u8],
    signature_priv: SignaturePrivateKeyView,
) -> Result<Signature> {
    let priv_bytes = signature_priv.as_ref().try_into().unwrap();
    let raw_priv = SigningKey::from_keypair_bytes(priv_bytes).unwrap();

    let digest = signature_digest(message, label)?;
    let raw_sig = raw_priv.sign(digest.as_ref());
    let signature = Signature::try_from(raw_sig.to_bytes().as_slice()).unwrap();

    Ok(signature)
}

pub fn verify_with_label(
    message: &[u8],
    label: &[u8],
    signature_key: SignaturePublicKeyView,
    signature: SignatureView,
) -> Result<bool> {
    let key_bytes = signature_key.as_ref().try_into().unwrap();
    let sig_bytes = signature.as_ref();

    let raw_key = VerifyingKey::from_bytes(key_bytes).unwrap();
    let raw_sig = ed25519_dalek::Signature::try_from(sig_bytes).unwrap();

    let digest = signature_digest(message, label)?;
    let ver = raw_key.verify(digest.as_ref(), &raw_sig).is_ok();
    Ok(ver)
}

pub fn generate_hpke(rng: &mut impl CryptoRngCore) -> Result<(HpkePrivateKey, HpkePublicKey)> {
    let raw_priv = StaticSecret::random_from_rng(rng);
    let raw_pub = PublicKey::from(&raw_priv);

    let priv_bytes = raw_priv.to_bytes();
    let pub_bytes = raw_pub.to_bytes();

    let hpke_priv = HpkePrivateKey::try_from(priv_bytes.as_slice()).unwrap();
    let hpke_key = HpkePublicKey::try_from(pub_bytes.as_slice()).unwrap();

    Ok((hpke_priv, hpke_key))
}

pub fn hpke_encap(encryption_key: HpkePublicKeyView) -> (HpkeKemOutput, HpkeKemSecret) {
    todo!();
}

pub fn hpke_decap(
    encryption_priv: HpkePrivateKeyView,
    kem_output: HpkeKemOutputView,
) -> HpkeKemSecret {
    todo!();
}

pub fn hpke_key_nonce(secret: HpkeKemSecret) -> (AeadKey, AeadNonce) {
    todo!();
}

pub fn aead_seal(ct: &mut [u8], pt: &[u8], key: AeadKey, nonce: AeadNonce, aad: &[u8]) -> usize {
    todo!();
}

pub fn aead_open(
    pt: &mut [u8],
    ct: &[u8],
    key: AeadKey,
    nonce: AeadNonce,
    aad: &[u8],
) -> Result<usize> {
    todo!();
}
