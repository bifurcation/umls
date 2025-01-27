use crate::common::{Error, Result};
use crate::io::{CountWriter, Read, Write};
use crate::protocol::CipherSuite;
use crate::stack;
use crate::syntax::{Deserialize, Opaque, Serialize, Varint};

use aead::Buffer;
use core::fmt::Debug;
use heapless::Vec;
use rand::Rng;
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

pub trait Initializers {
    fn zero() -> Self;
    fn random(rng: &mut impl Rng) -> Self;
}

impl<const N: usize> Initializers for Opaque<N> {
    fn zero() -> Self {
        stack::update();
        let mut vec = Vec::new();
        vec.resize_default(N).unwrap();
        Self(vec)
    }

    fn random(rng: &mut impl Rng) -> Self {
        stack::update();
        let mut vec = Vec::new();
        vec.resize_default(N).unwrap();
        let slice: &mut [u8] = vec.as_mut();
        rng.fill(slice);
        Self(vec)
    }
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
        + AsRef<[u8]>
        + Initializers;

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

    type AeadKey: for<'a> TryFrom<&'a [u8], Error = Error> + AsMut<[u8]>;
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

    #[must_use]
    fn hmac(key: &[u8], data: &[u8]) -> Self::HashOutput {
        stack::update();
        let mut hmac = Self::Hmac::new(key);
        hmac.write(data).unwrap();
        hmac.finalize()
    }

    fn derive_secret(secret: &Self::HashOutput, label: &'static [u8]) -> Self::HashOutput {
        stack::update();
        Self::expand_with_label(secret, label, &[])
    }

    fn extract(salt: &Self::HashOutput, ikm: &Self::HashOutput) -> Self::HashOutput {
        stack::update();
        Self::hmac(salt.as_ref(), ikm.as_ref())
    }

    fn expand_with_label_full(
        prk: &Self::HashOutput,
        label: &'static [u8],
        context: &[u8],
        len: u16,
    ) -> Self::HashOutput {
        stack::update();
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
        stack::update();
        Self::expand_with_label_full(secret, label, context, Self::HASH_OUTPUT_SIZE as u16)
    }

    fn welcome_key_nonce(secret: &Self::HashOutput) -> (Self::AeadKey, Self::AeadNonce) {
        stack::update();
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
        stack::update();
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
        stack::update();
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
        stack::update();
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
        stack::update();
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
        stack::update();
        let digest = Self::signature_digest(message, label)?;
        Self::sign(digest.as_ref(), sig_priv)
    }

    fn verify_with_label(
        message: &impl Serialize,
        label: &[u8],
        signature: &Self::Signature,
        sig_key: &Self::SignaturePublicKey,
    ) -> Result<()> {
        stack::update();
        let digest = Self::signature_digest(message, label)?;
        Self::verify(digest.as_ref(), signature, sig_key)
    }
}

pub trait DependentSizes {
    // XXX(RLB): These constants are unfortunately needed due to the limitations on const generics.
    // We might need to arrange them separately (e.g., in a separate trait) to make it easier to
    // manage them.  They should basically be:
    //
    //    EncryptedT = Opaque<{ T::MAX_SIZE + C::AEAD_OVERHEAD }>
    type SerializedRatchetTree: Clone
        + Default
        + Debug
        + AsRef<[u8]>
        + Write
        + Serialize
        + Deserialize
        + Buffer;
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
}

pub trait CryptoSizes: Crypto + DependentSizes {}
impl<T> CryptoSizes for T where T: Crypto + DependentSizes {}

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
pub type SerializedRatchetTree<C> = <C as DependentSizes>::SerializedRatchetTree;
pub type EncryptedGroupSecrets<C> = <C as DependentSizes>::EncryptedGroupSecrets;
pub type EncryptedGroupInfo<C> = <C as DependentSizes>::EncryptedGroupInfo;
pub type EncryptedPathSecret<C> = <C as DependentSizes>::EncryptedPathSecret;
pub type EncryptedSenderData<C> = <C as DependentSizes>::EncryptedSenderData;
pub type EncryptedPrivateMessageContent<C> = <C as DependentSizes>::EncryptedPrivateMessageContent;

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
        stack::update();
        let signature = C::sign_with_label(&tbs, Self::SIGNATURE_LABEL, sig_priv)?;
        Ok(Self { tbs, signature })
    }

    pub fn re_sign(&mut self, sig_priv: &C::SignaturePrivateKey) -> Result<()> {
        stack::update();
        self.signature = C::sign_with_label(&self.tbs, Self::SIGNATURE_LABEL, sig_priv)?;
        Ok(())
    }

    pub fn verify(&self, sig_key: &C::SignaturePublicKey) -> Result<()> {
        stack::update();
        C::verify_with_label(&self.tbs, Self::SIGNATURE_LABEL, &self.signature, sig_key)
    }
}

pub trait AeadEncrypt<C, E>: Serialize + Deserialize
where
    C: Crypto,
    E: Default + AsRef<[u8]> + Write + Buffer,
{
    fn seal(&self, key: &AeadKey<C>, nonce: &AeadNonce<C>, aad: &[u8]) -> Result<E> {
        stack::update();
        let mut buf = E::default();
        self.serialize(&mut buf)?;
        C::seal(&mut buf, key, nonce, aad)?;
        Ok(buf)
    }

    fn open(mut buf: E, key: &AeadKey<C>, nonce: &AeadNonce<C>, aad: &[u8]) -> Result<Self> {
        stack::update();
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
        stack::update();
        let (kem_output, kem_secret) = C::hpke_encap(rng, encryption_key);
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
        stack::update();
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
