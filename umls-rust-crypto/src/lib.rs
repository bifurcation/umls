use umls_core::{
    common::{Error, Result},
    crypto::{self, Crypto, DependentSizes},
    io::{Read, Write},
    protocol::{CipherSuite, X25519_AES128GCM_SHA256_ED25519},
    protocol::{GroupInfo, GroupSecrets, PathSecret, PrivateMessageContent, SenderData},
    syntax::{Deserialize, Opaque, Raw, Serialize},
    treekem::RatchetTree,
};

use aes_gcm::{aead::Buffer, AeadCore, AeadInPlace, Aes128Gcm, KeyInit};
use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use heapless::Vec;
use hmac::{digest::FixedOutput, Mac, SimpleHmac};
use rand_core::CryptoRngCore;
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey, StaticSecret};

const HASH_OUTPUT_SIZE: usize = 32;
const HPKE_PRIVATE_KEY_SIZE: usize = 32;
const HPKE_PUBLIC_KEY_SIZE: usize = 32;
const HPKE_KEM_OUTPUT_SIZE: usize = HPKE_PUBLIC_KEY_SIZE;
const HPKE_KEM_SECRET_SIZE: usize = HASH_OUTPUT_SIZE;
const SIGNATURE_PRIVATE_KEY_SIZE: usize = 64;
const SIGNATURE_PUBLIC_KEY_SIZE: usize = 32;
const SIGNATURE_SIZE: usize = 64;
const AEAD_OVERHEAD: usize = 16;
const AEAD_KEY_SIZE: usize = 16;
const AEAD_NONCE_SIZE: usize = 12;

type HashOutput = Opaque<{ HASH_OUTPUT_SIZE }>;
type AeadKey = Opaque<{ AEAD_KEY_SIZE }>;
type AeadNonce = Opaque<{ AEAD_NONCE_SIZE }>;

pub struct Hash {
    hash: Sha256,
}

impl Default for Hash {
    fn default() -> Self {
        Self {
            hash: Sha256::new(),
        }
    }
}

impl crypto::Hash for Hash {
    type Output = HashOutput;

    fn finalize(self) -> HashOutput {
        let digest = self.hash.finalize();
        Opaque(Vec::try_from(digest.as_slice()).unwrap())
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

impl crypto::Hmac for Hmac {
    type Output = HashOutput;

    fn new(key: &[u8]) -> Self {
        Self {
            mac: <SimpleHmac<Sha256> as KeyInit>::new_from_slice(key).unwrap(),
        }
    }

    fn finalize(self) -> HashOutput {
        let digest = self.mac.finalize_fixed();
        Opaque(Vec::try_from(digest.as_slice()).unwrap())
    }
}

impl Write for Hmac {
    fn write(&mut self, data: &[u8]) -> Result<()> {
        self.mac.update(data);
        Ok(())
    }
}

#[derive(Clone, Default, Debug, Serialize, Deserialize)]
pub struct BufferVec<const N: usize>(pub Vec<u8, N>);

impl<const N: usize> AsRef<[u8]> for BufferVec<N> {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl<const N: usize> AsMut<[u8]> for BufferVec<N> {
    fn as_mut(&mut self) -> &mut [u8] {
        self.0.as_mut()
    }
}

impl<const N: usize> Write for BufferVec<N> {
    fn write(&mut self, data: &[u8]) -> Result<()> {
        self.0.write(data)
    }
}

impl<const N: usize> Buffer for BufferVec<N> {
    fn extend_from_slice(&mut self, other: &[u8]) -> aead::Result<()> {
        self.0.extend_from_slice(other).map_err(|_| aead::Error)
    }

    fn truncate(&mut self, len: usize) {
        self.0.truncate(len);
    }
}

mod hpke {
    use super::{
        AeadKey, AeadNonce, HashOutput, Hmac, Opaque, Vec, AEAD_KEY_SIZE, AEAD_NONCE_SIZE,
        HASH_OUTPUT_SIZE,
    };
    use umls_core::crypto::Hmac as _;
    use umls_core::io::Write as _;

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
        out.0.resize_default(len as usize).unwrap();
        out
    }

    pub fn extract_and_expand(dh: &[u8], kem_context: &[u8]) -> HashOutput {
        let eae_prk = labeled_extract(KEM_SUITE_ID, b"", b"eae_prk", dh);
        labeled_expand(
            KEM_SUITE_ID,
            eae_prk.as_ref(),
            b"shared_secret",
            kem_context,
            HASH_OUTPUT_SIZE,
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
            AEAD_KEY_SIZE,
        );
        let nonce_data = labeled_expand(
            FULL_SUITE_ID,
            secret,
            b"key",
            &key_schedule_context,
            AEAD_NONCE_SIZE,
        );

        let key = Opaque(key_data.as_ref().try_into().unwrap());
        let nonce = Opaque(nonce_data.as_ref().try_into().unwrap());

        (key, nonce)
    }
}

#[derive(Clone, PartialEq, Default, Debug)]
pub struct RustCryptoX25519;

impl Crypto for RustCryptoX25519 {
    const CIPHER_SUITE: CipherSuite = X25519_AES128GCM_SHA256_ED25519;

    type Hash = Hash;
    type Hmac = Hmac;

    const HASH_OUTPUT_SIZE: usize = HASH_OUTPUT_SIZE;
    const AEAD_KEY_SIZE: usize = AEAD_KEY_SIZE;
    const AEAD_NONCE_SIZE: usize = AEAD_NONCE_SIZE;

    type RawHashOutput = Raw<{ HASH_OUTPUT_SIZE }>;
    type HashOutput = HashOutput;

    type HpkePrivateKey = Opaque<{ HPKE_PRIVATE_KEY_SIZE }>;
    type HpkePublicKey = Opaque<{ HPKE_PUBLIC_KEY_SIZE }>;
    type HpkeKemOutput = Opaque<{ HPKE_KEM_OUTPUT_SIZE }>;
    type HpkeKemSecret = Opaque<{ HPKE_KEM_SECRET_SIZE }>;

    fn hpke_generate(
        rng: &mut impl CryptoRngCore,
    ) -> Result<(Self::HpkePrivateKey, Self::HpkePublicKey)> {
        let raw_priv = StaticSecret::random_from_rng(rng);
        let raw_pub = PublicKey::from(&raw_priv);

        let hpke_priv = Self::HpkePrivateKey::try_from(raw_priv.as_bytes().as_ref()).unwrap();
        let hpke_key = Self::HpkePublicKey::try_from(raw_pub.as_bytes().as_ref()).unwrap();

        Ok((hpke_priv, hpke_key))
    }

    fn hpke_derive(seed: &Self::HashOutput) -> Result<(Self::HpkePrivateKey, Self::HpkePublicKey)> {
        let priv_bytes: &[u8; 32] = seed
            .as_ref()
            .try_into()
            .map_err(|_| Error("Invalid key data"))?;

        let raw_priv = StaticSecret::from(*priv_bytes);
        let raw_pub = PublicKey::from(&raw_priv);

        let hpke_priv = Self::HpkePrivateKey::try_from(raw_priv.as_bytes().as_ref()).unwrap();
        let hpke_key = Self::HpkePublicKey::try_from(raw_pub.as_bytes().as_ref()).unwrap();

        Ok((hpke_priv, hpke_key))
    }

    fn hpke_priv_to_pub(encryption_priv: &Self::HpkePrivateKey) -> Self::HpkePublicKey {
        let priv_bytes: [u8; 32] = encryption_priv.as_ref().try_into().unwrap();

        let raw_priv = StaticSecret::from(priv_bytes);
        let raw_pub = PublicKey::from(&raw_priv);

        Self::HpkePublicKey::try_from(raw_pub.as_bytes().as_ref()).unwrap()
    }

    fn hpke_encap(
        rng: &mut impl CryptoRngCore,
        encryption_key: &Self::HpkePublicKey,
    ) -> (Self::HpkeKemOutput, Self::HpkeKemSecret) {
        let pk_r_m: [u8; 32] = encryption_key.as_ref().try_into().unwrap();
        let pk_r = PublicKey::from(pk_r_m);

        let sk_e = StaticSecret::random_from_rng(rng);
        let enc = PublicKey::from(&sk_e);

        let dh = sk_e.diffie_hellman(&pk_r);

        let mut kem_context: Vec<u8, 64> = Vec::new();
        kem_context.extend_from_slice(enc.as_bytes()).unwrap();
        kem_context.extend_from_slice(&pk_r_m).unwrap();

        let shared_secret = hpke::extract_and_expand(dh.as_bytes(), kem_context.as_ref());

        let enc = Self::HpkeKemOutput::try_from(enc.as_bytes().as_ref()).unwrap();
        let shared_secret = Self::HpkeKemSecret::try_from(shared_secret.as_ref()).unwrap();
        (enc, shared_secret)
    }

    fn hpke_decap(
        encryption_priv: &Self::HpkePrivateKey,
        kem_output: &Self::HpkeKemOutput,
    ) -> Self::HpkeKemSecret {
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
        Self::HpkeKemSecret::try_from(shared_secret.as_ref()).unwrap()
    }

    fn hpke_key_nonce(secret: Self::HpkeKemSecret) -> (Self::AeadKey, Self::AeadNonce) {
        hpke::key_schedule(secret.as_ref())
    }

    type SignaturePrivateKey = Opaque<{ SIGNATURE_PRIVATE_KEY_SIZE }>;
    type SignaturePublicKey = Opaque<{ SIGNATURE_PUBLIC_KEY_SIZE }>;
    type Signature = Opaque<{ SIGNATURE_SIZE }>;

    fn sig_generate(
        rng: &mut impl CryptoRngCore,
    ) -> Result<(Self::SignaturePrivateKey, Self::SignaturePublicKey)> {
        let raw_priv = SigningKey::generate(rng);
        let raw_pub = raw_priv.verifying_key();

        let priv_bytes = raw_priv.to_keypair_bytes();
        let pub_bytes = raw_pub.to_bytes();

        let signature_priv = Self::SignaturePrivateKey::try_from(priv_bytes.as_slice()).unwrap();
        let signature_key = Self::SignaturePublicKey::try_from(pub_bytes.as_slice()).unwrap();

        Ok((signature_priv, signature_key))
    }

    // TODO(RLB) Use pre-hashed variant
    fn sign(digest: &[u8], signature_priv: &Self::SignaturePrivateKey) -> Result<Self::Signature> {
        let priv_bytes = signature_priv.as_ref().try_into().unwrap();
        let raw_priv = SigningKey::from_keypair_bytes(priv_bytes).unwrap();

        let raw_sig = raw_priv.sign(digest);
        Ok(Self::Signature::try_from(raw_sig.to_bytes().as_slice()).unwrap())
    }

    // TODO(RLB) Use pre-hashed variant
    fn verify(
        digest: &[u8],
        signature: &Self::Signature,
        signature_key: &Self::SignaturePublicKey,
    ) -> Result<()> {
        let key_bytes = signature_key.as_ref().try_into().unwrap();
        let sig_bytes = signature.as_ref();

        let raw_key = VerifyingKey::from_bytes(key_bytes).unwrap();
        let raw_sig = ed25519_dalek::Signature::try_from(sig_bytes).unwrap();

        let ver = raw_key.verify(digest, &raw_sig).is_ok();
        ver.then_some(()).ok_or(Error("Invalid signature"))
    }

    type AeadKey = AeadKey;
    type AeadNonce = AeadNonce;

    fn seal(
        buf: &mut impl Buffer,
        key: &Self::AeadKey,
        nonce: &Self::AeadNonce,
        aad: &[u8],
    ) -> Result<()> {
        type Key = aes_gcm::Key<Aes128Gcm>;
        type Nonce = aes_gcm::Nonce<<Aes128Gcm as AeadCore>::NonceSize>;

        let key: &Key = key.as_ref().into();
        let nonce: &Nonce = nonce.as_ref().into();

        let aead = Aes128Gcm::new(key);
        aead.encrypt_in_place(nonce, aad, buf).unwrap();

        Ok(())
    }

    fn open(
        buf: &mut impl Buffer,
        key: &Self::AeadKey,
        nonce: &Self::AeadNonce,
        aad: &[u8],
    ) -> Result<()> {
        type Key = aes_gcm::Key<Aes128Gcm>;
        type Nonce = aes_gcm::Nonce<<Aes128Gcm as AeadCore>::NonceSize>;

        let key: &Key = key.as_ref().into();
        let nonce: &Nonce = nonce.as_ref().into();

        let aead = Aes128Gcm::new(key);
        aead.decrypt_in_place(nonce, aad, buf)
            .map_err(|_| Error("AEAD error"))?;

        Ok(())
    }
}

impl DependentSizes for RustCryptoX25519 {
    type SerializedRatchetTree = BufferVec<{ RatchetTree::<RustCryptoX25519>::MAX_SIZE }>;
    type EncryptedGroupSecrets =
        BufferVec<{ GroupSecrets::<RustCryptoX25519>::MAX_SIZE + AEAD_OVERHEAD }>;
    type EncryptedGroupInfo =
        BufferVec<{ GroupInfo::<RustCryptoX25519>::MAX_SIZE + AEAD_OVERHEAD }>;
    type EncryptedPathSecret =
        BufferVec<{ PathSecret::<RustCryptoX25519>::MAX_SIZE + AEAD_OVERHEAD }>;
    type EncryptedSenderData = BufferVec<{ SenderData::MAX_SIZE + AEAD_OVERHEAD }>;
    type EncryptedPrivateMessageContent =
        BufferVec<{ PrivateMessageContent::<RustCryptoX25519>::MAX_SIZE + AEAD_OVERHEAD }>;
}
