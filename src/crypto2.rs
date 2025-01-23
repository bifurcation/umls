use crate::common::*;
use crate::io::*;
use crate::syntax2::*;

use aead::Buffer;
use rand_core::CryptoRngCore;

pub trait Crypto: Clone {
    type RawHashOutput: Clone + Serialize + Deserialize;
    type HashOutput: Clone + Serialize + Deserialize;

    type HpkePrivateKey: Clone + Serialize + Deserialize;
    type HpkePublicKey: Clone + Serialize + Deserialize;
    type HpkeKemOutput: Clone + Serialize + Deserialize;
    type HpkeKemSecret: Clone + Serialize + Deserialize;

    fn hpke_encap(
        rng: &mut impl CryptoRngCore,
        encryption_key: &Self::HpkePublicKey,
    ) -> (Self::HpkeKemOutput, Self::HpkeKemSecret);
    fn hpke_decap(
        encryption_priv: &Self::HpkePrivateKey,
        kem_output: &Self::HpkeKemOutput,
    ) -> Self::HpkeKemSecret;
    fn hpke_key_nonce(secret: Self::HpkeKemSecret) -> (Self::AeadKey, Self::AeadNonce);

    type SignaturePrivateKey: Serialize + Deserialize;
    type SignaturePublicKey: Serialize + Deserialize;
    type Signature: Serialize + Deserialize;

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
    type EncryptedGroupSecrets: Default + Read + Write + Serialize + Deserialize + Buffer;
    type EncryptedGroupInfo: Default + Read + Write + Serialize + Deserialize + Buffer;
    type EncryptedPathSecret: Default + Read + Write + Serialize + Deserialize + Buffer;
    type EncryptedSenderData: Default + Read + Write + Serialize + Deserialize + Buffer;
    type EncryptedPrivateMessageContent: Default + Read + Write + Serialize + Deserialize + Buffer;
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

#[derive(Serialize, Deserialize)]
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

    pub fn verify(&self, sig_key: &C::SignaturePublicKey) -> Result<()> {
        C::verify_with_label(&self.tbs, Self::SIGNATURE_LABEL, &self.signature, sig_key)
    }
}

pub trait AeadEncrypt<C, E>: Serialize + Deserialize
where
    C: Crypto,
    E: Default + Read + Write + Buffer,
{
    fn seal(self, key: &AeadKey<C>, nonce: &AeadNonce<C>, aad: &[u8]) -> Result<E> {
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

#[derive(Serialize, Deserialize)]
pub struct HpkeCiphertext<C, E>
where
    C: Crypto,
    E: Serialize + Deserialize,
{
    kem_output: HpkeKemOutput<C>,
    ciphertext: E,
}

pub trait HpkeEncrypt<C, E>: AeadEncrypt<C, E>
where
    C: Crypto,
    E: Default + Read + Write + Serialize + Deserialize + Buffer,
{
    fn hpke_seal(
        self,
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
