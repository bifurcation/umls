use crate::common::*;
use crate::io::*;
use crate::protocol2::CipherSuite;
use crate::syntax2::*;

use aead::Buffer;
use core::fmt::Debug;
use rand_core::CryptoRngCore;

pub trait Hash: Default + Write {
    type Output;

    fn finalize(self) -> Self::Output;
}

pub trait Hmac: Write {
    type Output;

    fn new(key: &[u8]) -> Self;
    fn finalize(self) -> Self::Output;
}

pub trait Crypto: Clone + PartialEq + Default + Debug {
    const CIPHER_SUITE: CipherSuite;

    type Hash: Hash<Output = Self::HashOutput>;
    type Hmac: Hmac<Output = Self::HashOutput>;

    const HASH_OUTPUT_SIZE: usize;
    const AEAD_KEY_SIZE: usize;
    const AEAD_NONCE_SIZE: usize;

    type RawHashOutput: Clone
        + Debug
        + PartialEq
        + Serialize
        + Deserialize
        + for<'a> TryFrom<&'a [u8]>
        + AsRef<[u8]>;
    type HashOutput: Default
        + Clone
        + Debug
        + PartialEq
        + Serialize
        + Deserialize
        + for<'a> TryFrom<&'a [u8]>
        + AsRef<[u8]>;

    type HpkePrivateKey: Clone + Debug + Default + PartialEq + Serialize + Deserialize;
    type HpkePublicKey: Clone + Debug + Default + PartialEq + Serialize + Deserialize;
    type HpkeKemOutput: Clone + Debug + Default + PartialEq + Serialize + Deserialize;
    type HpkeKemSecret: Clone + Debug + Default + PartialEq + Serialize + Deserialize;

    fn hpke_generate(
        rng: &mut impl CryptoRngCore,
    ) -> Result<(Self::HpkePrivateKey, Self::HpkePublicKey)>;
    fn hpke_derive(seed: &Self::HashOutput) -> Result<(Self::HpkePrivateKey, Self::HpkePublicKey)>;
    fn hpke_priv_to_pub(encryption_priv: &Self::HpkePrivateKey) -> Self::HpkePublicKey;
    fn hpke_encap(
        rng: &mut impl CryptoRngCore,
        encryption_key: &Self::HpkePublicKey,
    ) -> (Self::HpkeKemOutput, Self::HpkeKemSecret);
    fn hpke_decap(
        encryption_priv: &Self::HpkePrivateKey,
        kem_output: &Self::HpkeKemOutput,
    ) -> Self::HpkeKemSecret;
    fn hpke_key_nonce(secret: Self::HpkeKemSecret) -> (Self::AeadKey, Self::AeadNonce);

    type SignaturePrivateKey: Clone + Debug + PartialEq + Serialize + Deserialize;
    type SignaturePublicKey: Clone + Debug + PartialEq + Serialize + Deserialize;
    type Signature: Clone + Debug + PartialEq + Serialize + Deserialize;

    fn sig_generate(
        rng: &mut impl CryptoRngCore,
    ) -> Result<(Self::SignaturePrivateKey, Self::SignaturePublicKey)>;
    fn sign(digest: &[u8], signature_priv: &Self::SignaturePrivateKey) -> Result<Self::Signature>;
    fn verify(
        digest: &[u8],
        signature: &Self::Signature,
        signature_key: &Self::SignaturePublicKey,
    ) -> Result<()>;

    type AeadKey: for<'a> TryFrom<&'a [u8], Error = Error>;
    type AeadNonce: for<'a> TryFrom<&'a [u8], Error = Error>;
    fn seal(
        buf: &mut impl Buffer,
        key: &Self::AeadKey,
        nonce: &Self::AeadNonce,
        aad: &[u8],
    ) -> Result<()>;
    fn open(
        buf: &mut impl Buffer,
        key: &Self::AeadKey,
        nonce: &Self::AeadNonce,
        aad: &[u8],
    ) -> Result<()>;

    // XXX(RLB): These constants are unfortunately needed due to the limitations on const generics.
    // We might need to arrange them separately (e.g., in a separate trait) to make it easier to
    // manage them.  They should basically be:
    //
    //    EncryptedT = Opaque<{ T::MAX_SIZE + C::AEAD_OVERHEAD }>
    type EncryptedGroupSecrets: Clone
        + Default
        + Debug
        + AsRef<[u8]>
        + Write
        + Serialize
        + Deserialize
        + Buffer;
    type EncryptedGroupInfo: Clone
        + Default
        + Debug
        + AsRef<[u8]>
        + Write
        + Serialize
        + Deserialize
        + Buffer;
    type EncryptedPathSecret: Clone
        + Default
        + Debug
        + AsRef<[u8]>
        + Write
        + Serialize
        + Deserialize
        + Buffer;
    type EncryptedSenderData: Clone
        + Default
        + Debug
        + AsRef<[u8]>
        + Write
        + Serialize
        + Deserialize
        + Buffer;
    type EncryptedPrivateMessageContent: Clone
        + Default
        + Debug
        + AsRef<[u8]>
        + Write
        + Serialize
        + Deserialize
        + Buffer;

    fn hmac(key: &[u8], data: &[u8]) -> Self::HashOutput {
        let mut hmac = Self::Hmac::new(key);
        hmac.write(data).unwrap();
        hmac.finalize()
    }

    fn derive_secret(secret: &Self::HashOutput, label: &'static [u8]) -> Self::HashOutput {
        Self::expand_with_label(secret, label, &[])
    }

    fn extract(salt: &Self::HashOutput, ikm: &Self::HashOutput) -> Self::HashOutput {
        Self::hmac(salt.as_ref(), ikm.as_ref())
    }

    fn expand_with_label_full(
        prk: &Self::HashOutput,
        label: &'static [u8],
        context: &[u8],
        len: u16,
    ) -> Self::HashOutput {
        // We never need more than one block of output
        //   T(0) = empty string (zero length)
        //   T(1) = HMAC-Hash(PRK, T(0) | info | 0x01)
        let mut h = Self::Hmac::new(prk.as_ref());

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

        h.finalize()
    }

    fn expand_with_label(
        secret: &Self::HashOutput,
        label: &'static [u8],
        context: &[u8],
    ) -> Self::HashOutput {
        Self::expand_with_label_full(secret, label, context, Self::HASH_OUTPUT_SIZE as u16)
    }

    fn welcome_key_nonce(secret: &Self::HashOutput) -> (Self::AeadKey, Self::AeadNonce) {
        let key_data =
            Self::expand_with_label_full(secret, b"key", &[], Self::AEAD_KEY_SIZE as u16);
        let nonce_data =
            Self::expand_with_label_full(secret, b"nonce", &[], Self::AEAD_NONCE_SIZE as u16);

        let key_data = &key_data.as_ref()[..Self::AEAD_KEY_SIZE];
        let nonce_data = &nonce_data.as_ref()[..Self::AEAD_NONCE_SIZE];

        let key = key_data.try_into().unwrap();
        let nonce = nonce_data.try_into().unwrap();

        (key, nonce)
    }

    fn sender_data_key_nonce(
        sender_data_secret: &Self::HashOutput,
        ciphertext: &[u8],
    ) -> (Self::AeadKey, Self::AeadNonce) {
        let ciphertext_sample = &ciphertext[..Self::HASH_OUTPUT_SIZE];

        let key_data = Self::expand_with_label_full(
            sender_data_secret,
            b"key",
            ciphertext_sample,
            Self::AEAD_KEY_SIZE as u16,
        );
        let nonce_data = Self::expand_with_label_full(
            sender_data_secret,
            b"nonce",
            ciphertext_sample,
            Self::AEAD_NONCE_SIZE as u16,
        );

        let key_data = &key_data.as_ref()[..Self::AEAD_KEY_SIZE];
        let nonce_data = &nonce_data.as_ref()[..Self::AEAD_NONCE_SIZE];

        let key = key_data.try_into().unwrap();
        let nonce = nonce_data.try_into().unwrap();

        (key, nonce)
    }

    fn tree_key_nonce(
        secret: &Self::HashOutput,
        generation: u32,
    ) -> (Self::AeadKey, Self::AeadNonce) {
        let generation = generation.to_be_bytes();
        let key_data = Self::expand_with_label_full(
            secret,
            b"key",
            generation.as_ref(),
            Self::AEAD_KEY_SIZE as u16,
        );
        let nonce_data = Self::expand_with_label_full(
            secret,
            b"nonce",
            generation.as_ref(),
            Self::AEAD_NONCE_SIZE as u16,
        );

        let key_data = &key_data.as_ref()[..Self::AEAD_KEY_SIZE];
        let nonce_data = &nonce_data.as_ref()[..Self::AEAD_NONCE_SIZE];

        let key = key_data.try_into().unwrap();
        let nonce = nonce_data.try_into().unwrap();

        (key, nonce)
    }

    fn hash_ref(label: &'static [u8], value: &impl Serialize) -> Result<Self::HashOutput> {
        let mut h = Self::Hash::default();

        Varint(label.len()).serialize(&mut h)?;
        h.write(label)?;

        let mut count = CountWriter::default();
        value.serialize(&mut count)?;

        Varint(count.len()).serialize(&mut h)?;
        value.serialize(&mut h)?;

        Ok(h.finalize())
    }

    fn signature_digest(message: &impl Serialize, label: &[u8]) -> Result<Self::HashOutput> {
        let mut h = Self::Hash::default();

        Varint(label.len()).serialize(&mut h)?;
        h.write(label)?;

        let mut count = CountWriter::default();
        message.serialize(&mut count)?;

        Varint(count.len()).serialize(&mut h)?;
        message.serialize(&mut h)?;

        Ok(h.finalize())
    }

    fn sign_with_label(
        message: &impl Serialize,
        label: &[u8],
        sig_priv: &Self::SignaturePrivateKey,
    ) -> Result<Self::Signature> {
        let digest = Self::signature_digest(message, label)?;
        Self::sign(digest.as_ref(), &sig_priv)
    }

    fn verify_with_label(
        message: &impl Serialize,
        label: &[u8],
        signature: &Self::Signature,
        sig_key: &Self::SignaturePublicKey,
    ) -> Result<()> {
        let digest = Self::signature_digest(message, label)?;
        Self::verify(digest.as_ref(), signature, sig_key)
    }
}

trait EncryptedObjects: Crypto {}

pub type RawHashOutput<C> = <C as Crypto>::RawHashOutput;
pub type HashOutput<C> = <C as Crypto>::HashOutput;
pub type HpkeKemOutput<C> = <C as Crypto>::HpkeKemOutput;
pub type HpkePrivateKey<C> = <C as Crypto>::HpkePrivateKey;
pub type HpkePublicKey<C> = <C as Crypto>::HpkePublicKey;
pub type SignaturePrivateKey<C> = <C as Crypto>::SignaturePrivateKey;
pub type SignaturePublicKey<C> = <C as Crypto>::SignaturePublicKey;
pub type Signature<C> = <C as Crypto>::Signature;
pub type AeadKey<C> = <C as Crypto>::AeadKey;
pub type AeadNonce<C> = <C as Crypto>::AeadNonce;
pub type EncryptedGroupSecrets<C> = <C as Crypto>::EncryptedGroupSecrets;
pub type EncryptedGroupInfo<C> = <C as Crypto>::EncryptedGroupInfo;
pub type EncryptedPathSecret<C> = <C as Crypto>::EncryptedPathSecret;
pub type EncryptedSenderData<C> = <C as Crypto>::EncryptedSenderData;
pub type EncryptedPrivateMessageContent<C> = <C as Crypto>::EncryptedPrivateMessageContent;

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct Signed<T: Serialize + Deserialize, C: Crypto> {
    pub tbs: T,
    pub signature: Signature<C>,
}

pub trait SignatureLabel {
    const SIGNATURE_LABEL: &[u8];
}

impl<T, C> Signed<T, C>
where
    T: Serialize + Deserialize,
    C: Crypto,
    Signed<T, C>: SignatureLabel,
{
    pub fn sign(tbs: T, sig_priv: &C::SignaturePrivateKey) -> Result<Self> {
        let signature = C::sign_with_label(&tbs, Self::SIGNATURE_LABEL, sig_priv)?;
        Ok(Self { tbs, signature })
    }

    pub fn re_sign(&mut self, sig_priv: &C::SignaturePrivateKey) -> Result<()> {
        self.signature = C::sign_with_label(&self.tbs, Self::SIGNATURE_LABEL, sig_priv)?;
        Ok(())
    }

    pub fn verify(&self, sig_key: &C::SignaturePublicKey) -> Result<()> {
        C::verify_with_label(&self.tbs, Self::SIGNATURE_LABEL, &self.signature, sig_key)
    }
}

pub trait AeadEncrypt<C, E>: Serialize + Deserialize
where
    C: Crypto,
    E: Default + AsRef<[u8]> + Write + Buffer,
{
    fn seal(&self, key: &AeadKey<C>, nonce: &AeadNonce<C>, aad: &[u8]) -> Result<E> {
        let mut buf = E::default();
        self.serialize(&mut buf)?;
        C::seal(&mut buf, key, nonce, aad)?;
        Ok(buf)
    }

    fn open(mut buf: E, key: &AeadKey<C>, nonce: &AeadNonce<C>, aad: &[u8]) -> Result<Self> {
        C::open(&mut buf, key, nonce, aad)?;
        Self::deserialize(&mut buf.as_ref())
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct HpkeCiphertext<C, E>
where
    C: Crypto,
    E: Clone + Serialize + Deserialize,
{
    kem_output: HpkeKemOutput<C>,
    ciphertext: E,
}

pub trait HpkeEncrypt<C, E>: AeadEncrypt<C, E>
where
    C: Crypto,
    E: Clone + Default + AsRef<[u8]> + Write + Serialize + Deserialize + Buffer,
{
    fn hpke_seal(
        &self,
        rng: &mut impl CryptoRngCore,
        encryption_key: &HpkePublicKey<C>,
        aad: &[u8],
    ) -> Result<HpkeCiphertext<C, E>> {
        let (kem_output, kem_secret) = C::hpke_encap(rng, &encryption_key);
        let (key, nonce) = C::hpke_key_nonce(kem_secret);
        let ciphertext = self.seal(&key, &nonce, aad)?;
        Ok(HpkeCiphertext {
            kem_output,
            ciphertext,
        })
    }

    fn hpke_open(
        ct: HpkeCiphertext<C, E>,
        encryption_priv: &HpkePrivateKey<C>,
        aad: &[u8],
    ) -> Result<Self> {
        let kem_secret = C::hpke_decap(encryption_priv, &ct.kem_output);
        let (key, nonce) = C::hpke_key_nonce(kem_secret);
        Self::open(ct.ciphertext, &key, &nonce, aad)
    }
}

impl<T, C, E> HpkeEncrypt<C, E> for T
where
    T: AeadEncrypt<C, E>,
    C: Crypto,
    E: Clone + Default + AsRef<[u8]> + Write + Serialize + Deserialize + Buffer,
{
}

// This module implements a test cryptographic provider based on Rust Crypto, implementing the MLS
// MTI ciphersuite (X25519, Ed25519, SHA-256, and AES-128-GCM).
#[cfg(test)]
pub mod test {
    use super::*;

    use crate::protocol2::X25519_AES128GCM_SHA256_ED25519;

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

    impl super::Hash for Hash {
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

    impl super::Hmac for Hmac {
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
        use crate::crypto2::Hmac as _;
        use crate::io::Write as _;

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

        fn hpke_derive(
            seed: &Self::HashOutput,
        ) -> Result<(Self::HpkePrivateKey, Self::HpkePublicKey)> {
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

            let signature_priv =
                Self::SignaturePrivateKey::try_from(priv_bytes.as_slice()).unwrap();
            let signature_key = Self::SignaturePublicKey::try_from(pub_bytes.as_slice()).unwrap();

            Ok((signature_priv, signature_key))
        }

        // TODO(RLB) Use pre-hashed variant
        fn sign(
            digest: &[u8],
            signature_priv: &Self::SignaturePrivateKey,
        ) -> Result<Self::Signature> {
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

            const TAG_SIZE: usize = 16;

            let key: &Key = key.as_ref().into();
            let nonce: &Nonce = nonce.as_ref().into();

            let aead = Aes128Gcm::new(key);
            aead.decrypt_in_place(nonce, aad, buf)
                .map_err(|_| Error("AEAD error"))?;

            Ok(())
        }

        // XXX(RLB) These numbers are wildly over-sized.  But it saves us having to actually
        // compute them.
        type EncryptedGroupSecrets = BufferVec<1000>;
        type EncryptedGroupInfo = BufferVec<10000>;
        type EncryptedPathSecret = BufferVec<100>;
        type EncryptedSenderData = BufferVec<100>;
        type EncryptedPrivateMessageContent = BufferVec<10000>;
    }
}
