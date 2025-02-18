use umls_core::{
    common::{Error, Result},
    crypto::{self, Crypto, DependentSizes},
    io::Write,
    protocol::{CipherSuite, P256_AES128GCM_SHA256_P256},
    protocol::{GroupInfo, GroupSecrets, PathSecret, PrivateMessageContent, SenderData},
    syntax::{Opaque, Raw, Serialize},
    treekem::RatchetTree,
};

use aes_gcm::{aead::Buffer, AeadCore, AeadInPlace, Aes128Gcm, KeyInit};
use heapless::Vec;
use hmac::{digest::FixedOutput, Mac, SimpleHmac};
use p256::{
    ecdh::diffie_hellman,
    ecdsa::{
        signature::hazmat::{PrehashSigner, PrehashVerifier},
        Signature, SigningKey, VerifyingKey,
    },
    elliptic_curve::sec1::{EncodedPoint, FromEncodedPoint, ToEncodedPoint},
    NistP256, PublicKey, SecretKey,
};
use rand::CryptoRng;
use sha2::{Digest, Sha256};

// XXX(RLB) The `dalek` implementations expect an RNG complying to an old version of the `rand`
// crate.  This wrapper just fixes the version mismatch.
struct BackportRng<'a, T: CryptoRng>(&'a mut T);

impl<T> old_rand_core::RngCore for BackportRng<'_, T>
where
    T: CryptoRng,
{
    fn next_u32(&mut self) -> u32 {
        rand::RngCore::next_u32(&mut self.0)
    }

    fn next_u64(&mut self) -> u64 {
        rand::RngCore::next_u64(&mut self.0)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        rand::RngCore::fill_bytes(&mut self.0, dest);
    }

    fn try_fill_bytes(
        &mut self,
        dest: &mut [u8],
    ) -> core::result::Result<(), old_rand_core::Error> {
        rand::RngCore::fill_bytes(&mut self.0, dest);
        Ok(())
    }
}

impl<T> old_rand_core::CryptoRng for BackportRng<'_, T> where T: CryptoRng {}

const HASH_OUTPUT_SIZE: usize = 32;
const HPKE_PRIVATE_KEY_SIZE: usize = 32;
const HPKE_PUBLIC_KEY_SIZE: usize = 65;
const HPKE_KEM_OUTPUT_SIZE: usize = HPKE_PUBLIC_KEY_SIZE;
const HPKE_KEM_SECRET_SIZE: usize = HASH_OUTPUT_SIZE;
const SIGNATURE_PRIVATE_KEY_SIZE: usize = 32;
const SIGNATURE_PUBLIC_KEY_SIZE: usize = 65;
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

mod hpke {
    use super::{
        AeadKey, AeadNonce, HashOutput, Hmac, Opaque, Vec, AEAD_KEY_SIZE, AEAD_NONCE_SIZE,
        HASH_OUTPUT_SIZE,
    };
    use umls_core::crypto::Hmac as _;
    use umls_core::io::Write as _;

    // 0x0020 = DHKEM(P256, HKDF-SHA256)
    const KEM_SUITE_ID: &[u8] = b"KEM\x00\x20";

    // suite_id = concat("HPKE", kem_id, kdf_id, aead_id)
    // kem_id  = 0x0020 = DHKEM(P256, HKDF-SHA256)
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
        out.0.resize_default(len).unwrap();
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
pub struct RustCryptoP256;

impl Crypto for RustCryptoP256 {
    const CIPHER_SUITE: CipherSuite = P256_AES128GCM_SHA256_P256;

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
        rng: &mut impl CryptoRng,
    ) -> Result<(Self::HpkePrivateKey, Self::HpkePublicKey)> {
        let raw_priv = SecretKey::random(&mut BackportRng(rng));
        let raw_pub = raw_priv.public_key();

        let hpke_priv = Self::HpkePrivateKey::try_from(raw_priv.to_bytes().as_ref()).unwrap();
        let hpke_key =
            Self::HpkePublicKey::try_from(raw_pub.as_affine().to_encoded_point(false).as_bytes())
                .unwrap();

        Ok((hpke_priv, hpke_key))
    }

    fn hpke_derive(seed: &Self::HashOutput) -> Result<(Self::HpkePrivateKey, Self::HpkePublicKey)> {
        let raw_priv = SecretKey::from_slice(seed.as_ref()).unwrap();
        let raw_pub = raw_priv.public_key();

        let hpke_priv = Self::HpkePrivateKey::try_from(raw_priv.to_bytes().as_ref()).unwrap();
        let hpke_key =
            Self::HpkePublicKey::try_from(raw_pub.as_affine().to_encoded_point(false).as_bytes())
                .unwrap();

        Ok((hpke_priv, hpke_key))
    }

    fn hpke_priv_to_pub(encryption_priv: &Self::HpkePrivateKey) -> Self::HpkePublicKey {
        let raw_priv = SecretKey::from_slice(encryption_priv.as_ref()).unwrap();
        let raw_pub = raw_priv.public_key();

        Self::HpkePublicKey::try_from(raw_pub.as_affine().to_encoded_point(false).as_bytes())
            .unwrap()
    }

    fn hpke_encap(
        rng: &mut impl CryptoRng,
        encryption_key: &Self::HpkePublicKey,
    ) -> (Self::HpkeKemOutput, Self::HpkeKemSecret) {
        let pk_r_m = encryption_key.as_ref();
        let pk_r_point = EncodedPoint::<NistP256>::from_bytes(pk_r_m).unwrap();
        let pk_r = PublicKey::from_encoded_point(&pk_r_point).unwrap();

        let sk_e = SecretKey::random(&mut BackportRng(rng));
        let pk_e = sk_e.public_key();
        let pk_e_point = pk_e.as_affine().to_encoded_point(false);
        let enc = pk_e_point.as_bytes();

        let dh = diffie_hellman(sk_e.to_nonzero_scalar(), pk_r.as_affine());

        let mut kem_context: Vec<u8, 130> = Vec::new();
        kem_context.extend_from_slice(enc).unwrap();
        kem_context.extend_from_slice(pk_r_m).unwrap();

        let shared_secret = hpke::extract_and_expand(dh.raw_secret_bytes(), kem_context.as_ref());

        let enc = Self::HpkeKemOutput::try_from(enc).unwrap();
        let shared_secret = Self::HpkeKemSecret::try_from(shared_secret.as_ref()).unwrap();
        (enc, shared_secret)
    }

    fn hpke_decap(
        encryption_priv: &Self::HpkePrivateKey,
        kem_output: &Self::HpkeKemOutput,
    ) -> Self::HpkeKemSecret {
        let sk_r = SecretKey::from_slice(encryption_priv.as_ref()).unwrap();
        let pk_r = sk_r.public_key();
        let pk_r_point = pk_r.as_affine().to_encoded_point(false);
        let pk_r_m = pk_r_point.as_bytes();

        let pk_e_point = EncodedPoint::<NistP256>::from_bytes(kem_output.as_ref()).unwrap();
        let pk_e = PublicKey::from_encoded_point(&pk_e_point).unwrap();

        let dh = diffie_hellman(sk_r.to_nonzero_scalar(), pk_e.as_affine());

        let mut kem_context: Vec<u8, 130> = Vec::new();
        kem_context.extend_from_slice(kem_output.as_ref()).unwrap();
        kem_context.extend_from_slice(pk_r_m).unwrap();

        let shared_secret = hpke::extract_and_expand(dh.raw_secret_bytes(), kem_context.as_ref());
        Self::HpkeKemSecret::try_from(shared_secret.as_ref()).unwrap()
    }

    fn hpke_key_nonce(secret: Self::HpkeKemSecret) -> (Self::AeadKey, Self::AeadNonce) {
        hpke::key_schedule(secret.as_ref())
    }

    type SignaturePrivateKey = Opaque<{ SIGNATURE_PRIVATE_KEY_SIZE }>;
    type SignaturePublicKey = Opaque<{ SIGNATURE_PUBLIC_KEY_SIZE }>;
    type Signature = Opaque<{ SIGNATURE_SIZE }>;

    fn sig_generate(
        rng: &mut impl CryptoRng,
    ) -> Result<(Self::SignaturePrivateKey, Self::SignaturePublicKey)> {
        let raw_priv = SigningKey::random(&mut BackportRng(rng));
        let raw_pub = raw_priv.verifying_key();

        let priv_bytes = raw_priv.to_bytes();
        let pub_bytes = raw_pub.to_encoded_point(false);

        let signature_priv = Self::SignaturePrivateKey::try_from(priv_bytes.as_slice()).unwrap();
        let signature_key = Self::SignaturePublicKey::try_from(pub_bytes.as_bytes()).unwrap();

        Ok((signature_priv, signature_key))
    }

    // XXX(RLB) Use the randomized variant?  Would need to plumb an RNG through
    fn sign(digest: &[u8], signature_priv: &Self::SignaturePrivateKey) -> Result<Self::Signature> {
        let priv_bytes = signature_priv.as_ref().try_into().unwrap();
        let raw_priv = SigningKey::from_bytes(priv_bytes).unwrap();

        let raw_sig: Signature = raw_priv.sign_prehash(digest).unwrap();
        Ok(Self::Signature::try_from(raw_sig.to_bytes().as_slice()).unwrap())
    }

    // XXX(RLB) Use the randomized variant?  Would need to plumb an RNG through
    fn verify(
        digest: &[u8],
        signature: &Self::Signature,
        signature_key: &Self::SignaturePublicKey,
    ) -> Result<()> {
        let key_bytes = signature_key.as_ref();
        let sig_bytes = signature.as_ref();

        let key_point = EncodedPoint::<NistP256>::from_bytes(key_bytes).unwrap();
        let raw_key = VerifyingKey::from_encoded_point(&key_point).unwrap();
        let raw_sig = Signature::try_from(sig_bytes).unwrap();

        let ver = raw_key.verify_prehash(digest, &raw_sig).is_ok();
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

impl DependentSizes for RustCryptoP256 {
    type SerializedRatchetTree = Opaque<{ RatchetTree::<RustCryptoP256>::MAX_SIZE }>;
    type EncryptedGroupSecrets =
        Opaque<{ GroupSecrets::<RustCryptoP256>::MAX_SIZE + AEAD_OVERHEAD }>;
    type EncryptedGroupInfo = Opaque<{ GroupInfo::<RustCryptoP256>::MAX_SIZE + AEAD_OVERHEAD }>;
    type EncryptedPathSecret = Opaque<{ PathSecret::<RustCryptoP256>::MAX_SIZE + AEAD_OVERHEAD }>;
    type EncryptedSenderData = Opaque<{ SenderData::MAX_SIZE + AEAD_OVERHEAD }>;
    type EncryptedPrivateMessageContent =
        Opaque<{ PrivateMessageContent::<RustCryptoP256>::MAX_SIZE + AEAD_OVERHEAD }>;
}
