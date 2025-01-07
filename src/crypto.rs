use crate::common::*;
use crate::io::*;
use crate::syntax::*;
use crate::{mls_newtype_opaque, mls_newtype_primitive};

use aes_gcm::{AeadCore, AeadInPlace, Aes128Gcm, KeyInit};
use core::marker::PhantomData;
use core::ops::{Deref, DerefMut};
use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use heapless::Vec;
use hmac::{digest::FixedOutput, Mac, SimpleHmac};
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

pub trait Zero {
    fn zero() -> Self;
}

impl Zero for HashOutput {
    fn zero() -> Self {
        let mut hash_output = Self::default();
        let vec = &mut hash_output.0 .0;
        vec.resize_default(consts::HASH_OUTPUT_SIZE).unwrap();
        hash_output
    }
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

pub struct Hmac {
    mac: SimpleHmac<Sha256>,
}

impl Hmac {
    pub fn new(key: &[u8]) -> Self {
        let key = key.try_into().unwrap();
        Self {
            mac: <SimpleHmac<Sha256> as KeyInit>::new(key),
        }
    }

    pub fn finalize(self) -> HashOutput {
        let digest = self.mac.finalize_fixed();
        HashOutput::try_from(digest.as_slice()).unwrap()
    }
}

impl Write for Hmac {
    fn write(&mut self, data: &[u8]) -> Result<()> {
        self.mac.update(data);
        Ok(())
    }
}

pub fn hmac(key: &[u8], data: &[u8]) -> HashOutput {
    let mut hmac = Hmac::new(key);
    hmac.write(data).unwrap();
    hmac.finalize()
}

/*
struct {
  opaque label<V>;
  opaque value<V>;
} RefHashInput;
*/
pub fn hash_ref(label: &'static [u8], value: &impl Serialize) -> Result<HashOutput> {
    let mut h = Hash::new();

    Varint(label.len()).serialize(&mut h)?;
    h.write(label)?;

    let mut count = CountWriter::default();
    value.serialize(&mut count)?;

    Varint(count.len()).serialize(&mut h)?;
    value.serialize(&mut h)?;

    Ok(h.finalize())
}

pub fn extract(salt: HashOutputView, ikm: HashOutputView) -> HashOutput {
    hmac(salt.as_ref(), ikm.as_ref())
}

fn expand_with_label_full(
    prk: HashOutputView,
    label: &'static [u8],
    context: &[u8],
    len: u16,
) -> HashOutput {
    // We never need more than one block of output
    //   T(0) = empty string (zero length)
    //   T(1) = HMAC-Hash(PRK, T(0) | info | 0x01)
    let mut h = Hmac::new(prk.as_ref());

    // struct {
    //   uint16 length;
    //   opaque label<V>;
    //   opaque context<V>;
    // } KDFLabel;
    len.serialize(&mut h).unwrap();

    Varint(label.len()).serialize(&mut h).unwrap();
    h.write(label).unwrap();

    Varint(context.len()).serialize(&mut h).unwrap();
    h.write(context).unwrap();

    h.write(&[0x01]).unwrap();

    let mut out = h.finalize();
    out.0 .0.resize_default(len as usize).unwrap();
    out
}

pub fn expand_with_label(
    secret: HashOutputView,
    label: &'static [u8],
    context: &[u8],
) -> HashOutput {
    expand_with_label_full(secret, label, context, consts::HASH_OUTPUT_SIZE as u16)
}

pub fn derive_secret(secret: HashOutputView, label: &'static [u8]) -> HashOutput {
    expand_with_label(secret, label, &[])
}

pub fn tree_key_nonce(secret: HashOutputView, generation: u32) -> (AeadKey, AeadNonce) {
    let generation = generation.to_be_bytes();
    let key_data = expand_with_label_full(
        secret,
        b"key",
        generation.as_ref(),
        consts::AEAD_KEY_SIZE as u16,
    );
    let nonce_data = expand_with_label_full(
        secret,
        b"nonce",
        generation.as_ref(),
        consts::AEAD_NONCE_SIZE as u16,
    );

    let key = AeadKey(Opaque(key_data.as_ref().try_into().unwrap()));
    let nonce = AeadNonce(Opaque(nonce_data.as_ref().try_into().unwrap()));

    (key, nonce)
}

pub fn welcome_key_nonce(secret: HashOutputView) -> (AeadKey, AeadNonce) {
    let key_data = expand_with_label_full(secret, b"key", &[], consts::AEAD_KEY_SIZE as u16);
    let nonce_data = expand_with_label_full(secret, b"nonce", &[], consts::AEAD_NONCE_SIZE as u16);

    let key = AeadKey(Opaque(key_data.as_ref().try_into().unwrap()));
    let nonce = AeadNonce(Opaque(nonce_data.as_ref().try_into().unwrap()));

    (key, nonce)
}

pub fn sender_data_key_nonce(secret: HashOutputView, ciphertext: &[u8]) -> (AeadKey, AeadNonce) {
    let ciphertext_sample = &ciphertext[..consts::HASH_OUTPUT_SIZE];

    let key_data = expand_with_label_full(
        secret,
        b"key",
        ciphertext_sample,
        consts::AEAD_KEY_SIZE as u16,
    );
    let nonce_data = expand_with_label_full(
        secret,
        b"nonce",
        ciphertext_sample,
        consts::AEAD_NONCE_SIZE as u16,
    );

    let key = AeadKey(Opaque(key_data.as_ref().try_into().unwrap()));
    let nonce = AeadNonce(Opaque(nonce_data.as_ref().try_into().unwrap()));

    (key, nonce)
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
) -> Result<()> {
    let key_bytes = signature_key.as_ref().try_into().unwrap();
    let sig_bytes = signature.as_ref();

    let raw_key = VerifyingKey::from_bytes(key_bytes).unwrap();
    let raw_sig = ed25519_dalek::Signature::try_from(sig_bytes).unwrap();

    let digest = signature_digest(message, label)?;
    let ver = raw_key.verify(digest.as_ref(), &raw_sig).is_ok();
    ver.then_some(()).ok_or(Error("Invalid signature"))
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

pub fn aead_seal<const N: usize>(
    ct: &mut Vec<u8, N>,
    pt: &[u8],
    key: AeadKey,
    nonce: AeadNonce,
    aad: &[u8],
) {
    type Key = aes_gcm::Key<Aes128Gcm>;
    type Nonce = aes_gcm::Nonce<<Aes128Gcm as AeadCore>::NonceSize>;

    let key: &Key = key.as_ref().into();
    let nonce: &Nonce = nonce.as_ref().into();

    // AES-GCM crate requires a different version of heapless
    let mut inner_ct = aes_gcm::aead::heapless::Vec::<u8, N>::new();
    inner_ct.extend_from_slice(pt).unwrap();

    let aead = Aes128Gcm::new(key);
    aead.encrypt_in_place(nonce, aad, &mut inner_ct).unwrap();

    ct.clear();
    ct.extend_from_slice(&inner_ct).unwrap()
}

pub fn aead_open<const N: usize>(
    pt: &mut Vec<u8, N>,
    ct: &[u8],
    key: AeadKey,
    nonce: AeadNonce,
    aad: &[u8],
) -> Result<()> {
    type Key = aes_gcm::Key<Aes128Gcm>;
    type Nonce = aes_gcm::Nonce<<Aes128Gcm as AeadCore>::NonceSize>;

    let key: &Key = key.as_ref().into();
    let nonce: &Nonce = nonce.as_ref().into();

    // AES-GCM crate requires a different version of heapless
    let mut inner_pt = aes_gcm::aead::heapless::Vec::<u8, N>::new();

    let (ct, tag) = ct.split_at(ct.len() - consts::AEAD_OVERHEAD);
    inner_pt.extend_from_slice(ct).unwrap();

    let aead = Aes128Gcm::new(key);
    aead.decrypt_in_place_detached(nonce, aad, &mut inner_pt, tag.into())
        .map_err(|_| Error("AEAD error"))?;

    pt.clear();
    pt.extend_from_slice(&inner_pt).unwrap();
    Ok(())
}
