use crate::common::*;
use crate::io::*;
use crate::stack::*;
use crate::syntax::*;
use crate::{mls_newtype_opaque, mls_newtype_primitive, stack_ptr, tick};

use aes_gcm::{aead::Buffer, AeadCore, AeadInPlace, Aes128Gcm, KeyInit};
use core::ops::{Deref, DerefMut};
use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use heapless::Vec;
use hmac::{digest::FixedOutput, Mac, SimpleHmac};
use rand::{Fill, Rng};
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

mls_newtype_primitive! { CipherSuite => u16 }

pub use consts::AEAD_OVERHEAD;

mls_newtype_opaque! {
    HashOutput,
    consts::HASH_OUTPUT_SIZE
}

mls_newtype_opaque! {
    HpkePrivateKey,
    consts::HPKE_PRIVATE_KEY_SIZE
}

mls_newtype_opaque! {
    HpkePublicKey,
    consts::HPKE_PUBLIC_KEY_SIZE
}

mls_newtype_opaque! {
    HpkeKemOutput,
    consts::HPKE_KEM_OUTPUT_SIZE
}

mls_newtype_opaque! {
    HpkeKemSecret,
    consts::HPKE_KEM_SECRET_SIZE
}

mls_newtype_opaque! {
    SignaturePrivateKey,
    consts::SIGNATURE_PRIVATE_KEY_SIZE
}

mls_newtype_opaque! {
    SignaturePublicKey,
    consts::SIGNATURE_PUBLIC_KEY_SIZE
}

mls_newtype_opaque! {
    Signature,
    consts::SIGNATURE_SIZE
}

mls_newtype_opaque! {
    AeadKey,
    consts::SIGNATURE_SIZE
}

mls_newtype_opaque! {
    AeadNonce,
    consts::SIGNATURE_SIZE
}

pub trait Constructors {
    fn zero() -> Self;
    fn random(rng: &mut (impl CryptoRngCore + Rng)) -> Self;
}

impl<const N: usize> Constructors for Opaque<N> {
    fn zero() -> Self {
        let mut opaque = Self::default();
        let vec = &mut opaque.0;
        vec.resize_default(consts::HASH_OUTPUT_SIZE).unwrap();
        opaque
    }

    fn random(rng: &mut (impl CryptoRngCore + Rng)) -> Self {
        let mut opaque = Self::zero();
        opaque.as_mut().try_fill(rng).unwrap();
        opaque
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
        Self {
            mac: <SimpleHmac<Sha256> as KeyInit>::new_from_slice(key).unwrap(),
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

pub fn extract(salt: &HashOutput, ikm: &HashOutput) -> HashOutput {
    hmac(salt.as_ref(), ikm.as_ref())
}

fn expand_with_label_full(
    prk: &HashOutput,
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

pub fn expand_with_label(secret: &HashOutput, label: &'static [u8], context: &[u8]) -> HashOutput {
    expand_with_label_full(secret, label, context, consts::HASH_OUTPUT_SIZE as u16)
}

pub fn derive_secret(secret: &HashOutput, label: &'static [u8]) -> HashOutput {
    expand_with_label(secret, label, &[])
}

pub fn tree_key_nonce(secret: &HashOutput, generation: u32) -> (AeadKey, AeadNonce) {
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

pub fn welcome_key_nonce(secret: &HashOutput) -> (AeadKey, AeadNonce) {
    let key_data = expand_with_label_full(secret, b"key", &[], consts::AEAD_KEY_SIZE as u16);
    let nonce_data = expand_with_label_full(secret, b"nonce", &[], consts::AEAD_NONCE_SIZE as u16);

    let key = AeadKey(Opaque(key_data.as_ref().try_into().unwrap()));
    let nonce = AeadNonce(Opaque(nonce_data.as_ref().try_into().unwrap()));

    (key, nonce)
}

pub fn sender_data_key_nonce(secret: &HashOutput, ciphertext: &[u8]) -> (AeadKey, AeadNonce) {
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
    signature_priv: &SignaturePrivateKey,
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
    signature_key: &SignaturePublicKey,
    signature: &Signature,
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

    let hpke_priv = HpkePrivateKey::try_from(raw_priv.as_bytes().as_ref()).unwrap();
    let hpke_key = HpkePublicKey::try_from(raw_pub.as_bytes().as_ref()).unwrap();

    Ok((hpke_priv, hpke_key))
}

pub fn derive_hpke(seed: &HashOutput) -> Result<(HpkePrivateKey, HpkePublicKey)> {
    let priv_bytes: &[u8; 32] = seed
        .as_ref()
        .try_into()
        .map_err(|_| Error("Invalid key data"))?;

    let raw_priv = StaticSecret::from(*priv_bytes);
    let raw_pub = PublicKey::from(&raw_priv);

    let hpke_priv = HpkePrivateKey::try_from(raw_priv.as_bytes().as_ref()).unwrap();
    let hpke_key = HpkePublicKey::try_from(raw_pub.as_bytes().as_ref()).unwrap();

    Ok((hpke_priv, hpke_key))
}

pub fn hpke_priv_to_pub(hpke_priv: &HpkePrivateKey) -> HpkePublicKey {
    let priv_bytes: [u8; 32] = hpke_priv.as_ref().try_into().unwrap();

    let raw_priv = StaticSecret::from(priv_bytes);
    let raw_pub = PublicKey::from(&raw_priv);

    HpkePublicKey::try_from(raw_pub.as_bytes().as_ref()).unwrap()
}

mod hpke {
    use super::*;

    // 0x0020 = DHKEM(X25519, HKDF-SHA256)
    const KEM_SUITE_ID: &[u8] = b"KEM\x00\x20";

    // suite_id = concat("HPKE", kem_id, kdf_id, aead_id)
    // kem_id  = 0x0020 = DHKEM(X25519, HKDF-SHA256)
    // kdf_id  = 0x0001 = HKDF-SHA256
    // aead_id = 0x0001 = AES-128-GCM
    const FULL_SUITE_ID: &[u8] = b"HPKE\x00\x20\x00\x01\x00\x01";

    fn labeled_extract(
        suite_id: &'static [u8],
        salt: &[u8],
        label: &[u8],
        ikm: &[u8],
    ) -> HashOutput {
        let mut h = Hmac::new(salt);

        h.write(b"HPKE-v1").unwrap();
        h.write(suite_id).unwrap();
        h.write(label).unwrap();
        h.write(ikm).unwrap();

        h.finalize()
    }

    fn labeled_expand(
        suite_id: &'static [u8],
        prk: &[u8],
        label: &[u8],
        info: &[u8],
        len: usize,
    ) -> HashOutput {
        let mut h = Hmac::new(prk);

        h.write(&len.to_be_bytes()).unwrap();
        h.write(b"HPKE-v1").unwrap();
        h.write(suite_id).unwrap();
        h.write(label).unwrap();
        h.write(info).unwrap();

        let mut out = h.finalize();
        out.0 .0.resize_default(len as usize).unwrap();
        out
    }

    pub fn extract_and_expand(dh: &[u8], kem_context: &[u8]) -> HashOutput {
        let eae_prk = labeled_extract(KEM_SUITE_ID, b"", b"eae_prk", dh);
        labeled_expand(
            KEM_SUITE_ID,
            eae_prk.as_ref(),
            b"shared_secret",
            kem_context,
            consts::HASH_OUTPUT_SIZE,
        )
    }

    pub fn key_schedule(secret: &[u8]) -> (AeadKey, AeadNonce) {
        const MODE_BASE: u8 = 0x00;

        let psk_id_hash = labeled_extract(FULL_SUITE_ID, b"", b"psk_id_hash", &[]);
        let info_hash = labeled_extract(FULL_SUITE_ID, b"", b"info_hash", &[]);

        let mut key_schedule_context: Vec<u8, 65> = Vec::new();
        key_schedule_context.push(MODE_BASE).unwrap();
        key_schedule_context
            .extend_from_slice(psk_id_hash.as_ref())
            .unwrap();
        key_schedule_context
            .extend_from_slice(info_hash.as_ref())
            .unwrap();

        let key_data = labeled_expand(
            FULL_SUITE_ID,
            secret,
            b"key",
            &key_schedule_context,
            consts::AEAD_KEY_SIZE,
        );
        let nonce_data = labeled_expand(
            FULL_SUITE_ID,
            secret,
            b"key",
            &key_schedule_context,
            consts::AEAD_NONCE_SIZE,
        );

        let key = AeadKey(Opaque(key_data.as_ref().try_into().unwrap()));
        let nonce = AeadNonce(Opaque(nonce_data.as_ref().try_into().unwrap()));

        (key, nonce)
    }
}

pub fn hpke_encap(
    rng: &mut impl CryptoRngCore,
    encryption_key: &HpkePublicKey,
) -> (HpkeKemOutput, HpkeKemSecret) {
    let pk_r_m: [u8; 32] = encryption_key.as_ref().try_into().unwrap();
    let pk_r = PublicKey::from(pk_r_m);

    let sk_e = StaticSecret::random_from_rng(rng);
    let enc = PublicKey::from(&sk_e);

    let dh = sk_e.diffie_hellman(&pk_r);

    let mut kem_context: Vec<u8, 64> = Vec::new();
    kem_context.extend_from_slice(enc.as_bytes()).unwrap();
    kem_context.extend_from_slice(&pk_r_m).unwrap();

    let shared_secret = hpke::extract_and_expand(dh.as_bytes(), kem_context.as_ref());

    let enc = HpkeKemOutput::try_from(enc.as_bytes().as_ref()).unwrap();
    let shared_secret = HpkeKemSecret::try_from(shared_secret.as_ref()).unwrap();
    (enc, shared_secret)
}

pub fn hpke_decap(encryption_priv: &HpkePrivateKey, kem_output: &HpkeKemOutput) -> HpkeKemSecret {
    let sk_r_m: [u8; 32] = encryption_priv.as_ref().try_into().unwrap();
    let sk_r = StaticSecret::from(sk_r_m);
    let pk_r = PublicKey::from(&sk_r);
    let pk_r_m = pk_r.as_bytes().as_ref();

    let pk_e_m: [u8; 32] = kem_output.as_ref().try_into().unwrap();
    let pk_e = PublicKey::from(pk_e_m);

    let dh = sk_r.diffie_hellman(&pk_e);

    let mut kem_context: Vec<u8, 64> = Vec::new();
    kem_context.extend_from_slice(kem_output.as_ref()).unwrap();
    kem_context.extend_from_slice(&pk_r_m).unwrap();

    let shared_secret = hpke::extract_and_expand(dh.as_bytes(), kem_context.as_ref());
    HpkeKemSecret::try_from(shared_secret.as_ref()).unwrap()
}

pub fn hpke_key_nonce(secret: HpkeKemSecret) -> (AeadKey, AeadNonce) {
    hpke::key_schedule(secret.as_ref())
}

struct VecAsBuffer<'a, const N: usize>(&'a mut Vec<u8, N>);

impl<'a, const N: usize> AsRef<[u8]> for VecAsBuffer<'a, N> {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl<'a, const N: usize> AsMut<[u8]> for VecAsBuffer<'a, N> {
    fn as_mut(&mut self) -> &mut [u8] {
        self.0.as_mut()
    }
}

impl<'a, const N: usize> Buffer for VecAsBuffer<'a, N> {
    fn extend_from_slice(&mut self, other: &[u8]) -> aead::Result<()> {
        self.0.extend_from_slice(other).map_err(|_| aead::Error)
    }

    fn truncate(&mut self, len: usize) {
        self.0.truncate(len);
    }
}

pub fn aead_seal<const N: usize>(ct: &mut Vec<u8, N>, key: AeadKey, nonce: AeadNonce, aad: &[u8]) {
    type Key = aes_gcm::Key<Aes128Gcm>;
    type Nonce = aes_gcm::Nonce<<Aes128Gcm as AeadCore>::NonceSize>;

    let key: &Key = key.as_ref().into();
    let nonce: &Nonce = nonce.as_ref().into();

    let aead = Aes128Gcm::new(key);
    aead.encrypt_in_place(nonce, aad, &mut VecAsBuffer(ct))
        .unwrap();
}

pub fn aead_open(
    pt: &mut [u8],
    tag: &[u8],
    key: AeadKey,
    nonce: AeadNonce,
    aad: &[u8],
) -> Result<()> {
    type Key = aes_gcm::Key<Aes128Gcm>;
    type Nonce = aes_gcm::Nonce<<Aes128Gcm as AeadCore>::NonceSize>;

    let key: &Key = key.as_ref().into();
    let nonce: &Nonce = nonce.as_ref().into();

    let aead = Aes128Gcm::new(key);
    aead.decrypt_in_place_detached(nonce, aad, pt, tag.into())
        .map_err(|_| Error("AEAD error"))?;

    Ok(())
}
