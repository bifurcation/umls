use crate::common::*;
use crate::io::*;
use crate::syntax2::*;

use aead::Buffer;
use heapless::Vec;
use rand_core::CryptoRngCore;

// XXX(RLB): It would be good to make this an attribute of the cipher suite.  This causes problems
// with sizing encrypted objects, because you can't invoke C::AEAD_OVERHEAD generically. ("cannot
// perform const operation using `C`")  And this is the value for all known ciphersuites anyway.
const AEAD_OVERHEAD: usize = 16;

trait Crypto {
    type HashOutput: Serialize + Deserialize;

    type HpkePrivateKey: Serialize + Deserialize;
    type HpkePublicKey: Serialize + Deserialize;
    type HpkeKemOutput: Serialize + Deserialize;
    type HpkeKemSecret: Serialize + Deserialize;

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

    // XXX(RLB): These constants are unfortunately needed due to the limitations on const generics.
    // We might need to arrange them separately (e.g., in a separate trait) to make it easier to
    // manage them.  They should basically be:
    //
    //    EncryptedT = Opaque<{ T::MAX_SIZE + C::AEAD_OVERHEAD }>
    type EncryptedGroupSecrets: Default + Read + Write + Serialize + Deserialize + Buffer;
}

type HashOutput<C> = <C as Crypto>::HashOutput;
type HpkeKemOutput<C> = <C as Crypto>::HpkeKemOutput;
type HpkePrivateKey<C> = <C as Crypto>::HpkePrivateKey;
type HpkePublicKey<C> = <C as Crypto>::HpkePublicKey;
type SignaturePrivateKey<C> = <C as Crypto>::SignaturePrivateKey;
type SignaturePublicKey<C> = <C as Crypto>::SignaturePublicKey;
type Signature<C> = <C as Crypto>::Signature;
type AeadKey<C> = <C as Crypto>::AeadKey;
type AeadNonce<C> = <C as Crypto>::AeadNonce;

#[derive(Serialize, Deserialize)]
struct Signed<T: Serialize + Deserialize, C: Crypto> {
    pub tbs: T,
    pub signature: Signature<C>,
}

trait SignatureLabel {
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

trait AeadEncrypt<C, E>: Serialize + Deserialize
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
struct HpkeCiphertext<C, E>
where
    C: Crypto,
    E: Serialize + Deserialize,
{
    kem_output: HpkeKemOutput<C>,
    ciphertext: E,
}

trait HpkeEncrypt<C, E>: AeadEncrypt<C, E>
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

mod consts {
    // Credentials
    pub const MAX_CREDENTIALS_SIZE: usize = 32;

    // Capabilities
    pub const MAX_PROTOCOL_VERSIONS: usize = 1;
    pub const MAX_CIPHER_SUITES: usize = 1;
    pub const MAX_EXTENSION_TYPES: usize = 0;
    pub const MAX_PROPOSAL_TYPES: usize = 0;
    pub const MAX_CREDENTIAL_TYPES: usize = 1;

    // LeafNode extensions
    pub const MAX_LEAF_NODE_EXTENSIONS: usize = 0;
    pub const MAX_LEAF_NODE_EXTENSION_LEN: usize = 0;

    // KeyPackage extensions
    pub const MAX_KEY_PACKAGE_EXTENSIONS: usize = 0;
    pub const MAX_KEY_PACKAGE_EXTENSION_LEN: usize = 0;

    // GroupContext
    pub const MAX_GROUP_ID_SIZE: usize = 16;
    pub const MAX_GROUP_CONTEXT_EXTENSIONS: usize = 0;
    pub const MAX_GROUP_CONTEXT_EXTENSION_LEN: usize = 0;

    // GroupInfo
    pub const MAX_GROUP_INFO_EXTENSIONS: usize = 0;
    pub const MAX_GROUP_INFO_EXTENSION_LEN: usize = 0;
}

#[derive(Serialize, Deserialize)]
struct BasicCredential(Opaque<{ consts::MAX_CREDENTIALS_SIZE }>);

#[derive(Serialize, Deserialize)]
#[discriminant = "u8"]
enum Credential {
    #[discriminant = "1"]
    Basic(BasicCredential),
}

#[derive(Serialize, Deserialize)]
struct ProtocolVersion(u16);

#[derive(Serialize, Deserialize)]
struct CipherSuite(u16);

#[derive(Serialize, Deserialize)]
struct ExtensionType(u16);

#[derive(Serialize, Deserialize)]
struct ProposalType(u16);

#[derive(Serialize, Deserialize)]
struct CredentialType(u16);

#[derive(Serialize, Deserialize)]
struct Capabilities {
    versions: Vec<ProtocolVersion, { consts::MAX_PROTOCOL_VERSIONS }>,
    cipher_suites: Vec<CipherSuite, { consts::MAX_CIPHER_SUITES }>,
    extensions: Vec<ExtensionType, { consts::MAX_EXTENSION_TYPES }>,
    proposals: Vec<ProposalType, { consts::MAX_PROPOSAL_TYPES }>,
    credentials: Vec<CredentialType, { consts::MAX_CREDENTIAL_TYPES }>,
}

#[derive(Serialize, Deserialize)]
struct Lifetime {
    not_before: u64,
    not_after: u64,
}

#[derive(Serialize, Deserialize)]
#[discriminant = "u8"]
enum LeafNodeSource<C: Crypto> {
    #[discriminant = "1"]
    KeyPackage(Lifetime),

    #[discriminant = "2"]
    Update(Nil),

    #[discriminant = "3"]
    Commit(HashOutput<C>),
}

#[derive(Serialize, Deserialize)]
struct LeafNodeExtension {
    extension_type: ExtensionType,
    extension_data: Opaque<{ consts::MAX_LEAF_NODE_EXTENSION_LEN }>,
}

#[derive(Serialize, Deserialize)]
struct LeafNodeTbs<C: Crypto> {
    signature_key: SignaturePrivateKey<C>,
    encryption_key: HpkePrivateKey<C>,
    credential: Credential,
    capabilities: Capabilities,
    leaf_node_source: LeafNodeSource<C>,
    extensions: Vec<LeafNodeExtension, { consts::MAX_LEAF_NODE_EXTENSIONS }>,
}

type LeafNode<C> = Signed<LeafNodeTbs<C>, C>;

impl<C: Crypto> SignatureLabel for LeafNode<C> {
    const SIGNATURE_LABEL: &[u8] = b"LeafNodeTBS";
}

#[derive(Serialize, Deserialize)]
struct KeyPackageExtension {
    extension_type: ExtensionType,
    extension_data: Opaque<{ consts::MAX_KEY_PACKAGE_EXTENSION_LEN }>,
}

#[derive(Serialize, Deserialize)]
struct KeyPackageTbs<C: Crypto> {
    protocol_version: ProtocolVersion,
    cipher_suite: CipherSuite,
    init_key: HpkePublicKey<C>,
    leaf_node: LeafNode<C>,
    extensions: Vec<KeyPackageExtension, { consts::MAX_KEY_PACKAGE_EXTENSIONS }>,
}

type KeyPackage<C> = Signed<KeyPackageTbs<C>, C>;

impl<C: Crypto> SignatureLabel for KeyPackage<C> {
    const SIGNATURE_LABEL: &[u8] = b"KeyPackageTBS";
}

#[derive(Serialize, Deserialize)]
struct KeyPackagePriv<C: Crypto> {
    init_priv: HpkePrivateKey<C>,
    encryption_priv: HpkePrivateKey<C>,
    signature_priv: SignaturePrivateKey<C>,
}

#[derive(Serialize, Deserialize)]
struct GroupId(Opaque<{ consts::MAX_GROUP_ID_SIZE }>);

#[derive(Serialize, Deserialize)]
struct Epoch(u64);

#[derive(Serialize, Deserialize)]
struct TreeHash<C: Crypto>(HashOutput<C>);

#[derive(Serialize, Deserialize)]
struct ConfirmedTranscriptHash<C: Crypto>(HashOutput<C>);

#[derive(Serialize, Deserialize)]
struct GroupContextExtension {
    extension_type: ExtensionType,
    extension_data: Opaque<{ consts::MAX_GROUP_CONTEXT_EXTENSION_LEN }>,
}

#[derive(Serialize, Deserialize)]
struct GroupContext<C: Crypto> {
    version: ProtocolVersion,
    cipher_suite: CipherSuite,
    group_id: GroupId,
    epoch: Epoch,
    tree_hash: TreeHash<C>,
    confirmed_transcript_hash: ConfirmedTranscriptHash<C>,
    extensions: Vec<GroupContextExtension, { consts::MAX_GROUP_CONTEXT_EXTENSIONS }>,
}

#[derive(Serialize, Deserialize)]
struct LeafIndex(u32);

#[derive(Serialize, Deserialize)]
struct ConfirmationTag<C: Crypto>(HashOutput<C>);

#[derive(Serialize, Deserialize)]
struct GroupInfoExtension {
    extension_type: ExtensionType,
    extension_data: Opaque<{ consts::MAX_GROUP_INFO_EXTENSION_LEN }>,
}

#[derive(Serialize, Deserialize)]
struct GroupInfoTbs<C: Crypto> {
    group_context: GroupContext<C>,
    extensions: Vec<GroupInfoExtension, { consts::MAX_GROUP_INFO_EXTENSIONS }>,
    confirmation_tag: ConfirmationTag<C>,
    signer: LeafIndex,
}

type GroupInfo<C> = Signed<GroupInfoTbs<C>, C>;

impl<C: Crypto> SignatureLabel for GroupInfo<C> {
    const SIGNATURE_LABEL: &[u8] = b"GroupInfoTBS";
}

#[derive(Serialize, Deserialize)]
struct JoinerSecret<C: Crypto>(HashOutput<C>);

#[derive(Serialize, Deserialize)]
struct PathSecret<C: Crypto>(HashOutput<C>);

#[derive(Serialize, Deserialize)]
struct GroupSecrets<C: Crypto> {
    joiner_secret: JoinerSecret<C>,
    path_secret: Option<PathSecret<C>>,

    // XXX(RLB): This is a stub for now because we don't support PSKs.
    psks: Vec<Nil, 0>,
}

impl<C: Crypto> AeadEncrypt<C, C::EncryptedGroupSecrets> for GroupSecrets<C> {}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn encrypted() {
        let _x = EncryptedThing::default();
    }

    #[test]
    fn signed() {
        // TODO
    }
}
