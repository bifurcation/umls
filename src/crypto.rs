use crate::common::*;
use crate::io::*;
use crate::syntax::*;
use crate::{mls_newtype, mls_newtype_opaque};

use core::ops::Deref;
use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use heapless::Vec;
use rand_core::CryptoRngCore;
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey, StaticSecret};

pub mod consts {
    pub const CIPHER_SUITE: u16 = 0x0001;

    pub const HASH_OUTPUT_SIZE: usize = 32;

    pub const HPKE_PRIVATE_KEY_SIZE: usize = 32;
    pub const HPKE_PUBLIC_KEY_SIZE: usize = 32;

    pub const SIGNATURE_PRIVATE_KEY_SIZE: usize = 64;
    pub const SIGNATURE_PUBLIC_KEY_SIZE: usize = 32;
    pub const SIGNATURE_SIZE: usize = 64;
}

pub use consts::CIPHER_SUITE;

mls_newtype_opaque! {
    HashOutput + HashOutputView,
    HashOutputData + HashOutputViewData,
    consts::HASH_OUTPUT_SIZE
}

mls_newtype_opaque! {
    HpkePrivateKey + HpkePrivateKeyView,
    HpkePrivateKeyData + HpkePrivateKeyViewData,
    consts::HPKE_PRIVATE_KEY_SIZE
}

mls_newtype_opaque! {
    HpkePublicKey + HpkePublicKeyView,
    HpkePublicKeyData + HpkePublicKeyViewData,
    consts::HPKE_PUBLIC_KEY_SIZE
}

mls_newtype_opaque! {
    SignaturePrivateKey + SignaturePrivateKeyView,
    SignaturePrivateKeyData + SignaturePrivateKeyViewData,
    consts::SIGNATURE_PRIVATE_KEY_SIZE
}

mls_newtype_opaque! {
    SignaturePublicKey + SignaturePublicKeyView,
    SignaturePublicKeyData + SignaturePublicKeyViewData,
    consts::SIGNATURE_PUBLIC_KEY_SIZE
}

mls_newtype_opaque! {
    Signature + SignatureView,
    SignatureData + SignatureViewData,
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

// TODO(RLB) SignWithLabel
pub fn sign(message: &[u8], signature_priv: SignaturePrivateKeyView) -> Result<Signature> {
    let priv_bytes = signature_priv.as_ref().try_into().unwrap();
    let raw_priv = SigningKey::from_keypair_bytes(priv_bytes).unwrap();

    let raw_sig = raw_priv.sign(message.as_ref());
    let signature = Signature::try_from(raw_sig.to_bytes().as_slice()).unwrap();

    Ok(signature)
}

// TODO(RLB) VerifyWithLabel
pub fn verify(
    message: &[u8],
    signature_key: SignaturePublicKeyView,
    signature: SignatureView,
) -> Result<bool> {
    let key_bytes = signature_key.as_ref().try_into().unwrap();
    let sig_bytes = signature.as_ref();

    let raw_key = VerifyingKey::from_bytes(key_bytes).unwrap();
    let raw_sig = ed25519_dalek::Signature::try_from(sig_bytes).unwrap();

    let ver = raw_key.verify(message, &raw_sig).is_ok();
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
