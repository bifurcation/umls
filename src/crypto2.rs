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
    type Key;
    type Output;

    fn new(key: &[u8]) -> Self;
    fn finalize(self) -> Self::Output;
}

pub trait Crypto: Clone + PartialEq + Default + Debug {
    const CIPHER_SUITE: CipherSuite;

    type Hash: Hash<Output = Self::HashOutput>;
    type Hmac: Hmac<Output = Self::HashOutput>;

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

    fn sign_with_label(
        tbs: &impl Serialize,
        label: &[u8],
        sig_priv: &Self::SignaturePrivateKey,
    ) -> Result<Self::Signature>;
    fn verify_with_label(
        tbs: &impl Serialize,
        label: &[u8],
        sig: &Self::Signature,
        sig_priv: &Self::SignaturePublicKey,
    ) -> Result<()>;

    const AEAD_OVERHEAD: usize;
    type AeadKey;
    type AeadNonce;
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

    fn sender_data_key_nonce(
        sender_data_secret: &Self::HashOutput,
        ciphertext: &[u8],
    ) -> (Self::AeadKey, Self::AeadNonce);

    // XXX(RLB): These constants are unfortunately needed due to the limitations on const generics.
    // We might need to arrange them separately (e.g., in a separate trait) to make it easier to
    // manage them.  They should basically be:
    //
    //    EncryptedT = Opaque<{ T::MAX_SIZE + C::AEAD_OVERHEAD }>
    type EncryptedGroupSecrets: Clone
        + Default
        + Debug
        + Read
        + Write
        + Serialize
        + Deserialize
        + Buffer;
    type EncryptedGroupInfo: Clone
        + Default
        + Debug
        + Read
        + Write
        + Serialize
        + Deserialize
        + Buffer;
    type EncryptedPathSecret: Clone
        + Default
        + Debug
        + Read
        + Write
        + Serialize
        + Deserialize
        + Buffer;
    type EncryptedSenderData: Clone
        + Default
        + Debug
        + Read
        + Write
        + Serialize
        + Deserialize
        + Buffer;
    type EncryptedPrivateMessageContent: Clone
        + Default
        + Debug
        + Read
        + Write
        + Serialize
        + Deserialize
        + Buffer;

    // XXX(RLB) These can probably be provided based on the above
    fn hmac(key: &[u8], data: &[u8]) -> Self::HashOutput;
    fn derive_secret(secret: &Self::HashOutput, label: &'static [u8]) -> Self::HashOutput;
    fn extract(salt: &Self::HashOutput, ikm: &Self::HashOutput) -> Self::HashOutput;
    fn expand_with_label(
        secret: &Self::HashOutput,
        label: &'static [u8],
        context: &[u8],
    ) -> Self::HashOutput;
    fn tree_key_nonce(
        secret: &Self::HashOutput,
        generation: u32,
    ) -> (Self::AeadKey, Self::AeadNonce);
    fn welcome_key_nonce(secret: &Self::HashOutput) -> (Self::AeadKey, Self::AeadNonce);
    fn hash_ref(label: &'static [u8], value: &impl Serialize) -> Result<Self::HashOutput>;
}

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
    E: Default + Read + Write + Buffer,
{
    fn seal(&self, key: &AeadKey<C>, nonce: &AeadNonce<C>, aad: &[u8]) -> Result<E> {
        let mut buf = E::default();
        self.serialize(&mut buf)?;
        C::seal(&mut buf, key, nonce, aad)?;
        Ok(buf)
    }

    fn open(mut buf: E, key: &AeadKey<C>, nonce: &AeadNonce<C>, aad: &[u8]) -> Result<Self> {
        C::open(&mut buf, key, nonce, aad)?;
        Self::deserialize(&mut buf)
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
    E: Clone + Default + Read + Write + Serialize + Deserialize + Buffer,
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
    E: Clone + Default + Read + Write + Serialize + Deserialize + Buffer,
{
}
