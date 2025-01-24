use crate::common::*;
use crate::crypto::*;
use crate::io::*;
use crate::stack;
use crate::syntax::*;

use heapless::Vec;

pub mod consts {
    use super::{CredentialType, ExtensionType, ProtocolVersion, WireFormat};

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
    pub const MAX_GROUP_ID_SIZE: usize = 32;
    pub const MAX_GROUP_CONTEXT_EXTENSIONS: usize = 0;
    pub const MAX_GROUP_CONTEXT_EXTENSION_LEN: usize = 0;

    // GroupInfo
    pub const MAX_GROUP_INFO_EXTENSIONS: usize = 1;

    // Welcome
    pub const MAX_JOINERS_PER_WELCOME: usize = 1;

    // RatchetTree
    pub const MAX_GROUP_SIZE: usize = 8;
    pub const MAX_RESOLUTION_SIZE: usize = MAX_GROUP_SIZE / 2;
    pub const MAX_TREE_DEPTH: usize = (MAX_GROUP_SIZE.ilog2() as usize) + 1;
    pub const EXTENSION_TYPE_RATCHET_TREE: ExtensionType = ExtensionType(0x0002);

    // Commit
    pub const MAX_PROPOSALS_PER_COMMIT: usize = 1;

    // PrivateMessage
    pub const MAX_PRIVATE_MESSAGE_AAD_LEN: usize = 0;
    pub const SUPPORTED_VERSION: ProtocolVersion = ProtocolVersion(0x0001); // mls10
    pub const SUPPORTED_CREDENTIAL_TYPE: CredentialType = CredentialType(0x0001); // basic
    pub const SUPPORTED_WIRE_FORMAT: WireFormat = WireFormat(0x0002); // mls_private_message
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct BasicCredential(pub Opaque<{ consts::MAX_CREDENTIALS_SIZE }>);

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
#[discriminant = "u8"]
pub enum Credential {
    #[discriminant = "1"]
    Basic(BasicCredential),
}

#[derive(Copy, Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct ProtocolVersion(u16);

impl Default for ProtocolVersion {
    fn default() -> Self {
        stack::update();
        consts::SUPPORTED_VERSION
    }
}

#[derive(Copy, Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct CipherSuite(u16);

// https://www.iana.org/assignments/mls/mls.xhtml#mls-ciphersuites
pub const X25519_AES128GCM_SHA256_ED25519: CipherSuite = CipherSuite(0x0001);
pub const P256_AES128GCM_SHA256_P256: CipherSuite = CipherSuite(0x0002);

#[derive(Copy, Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct ExtensionType(u16);

#[derive(Copy, Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct ProposalType(u16);

#[derive(Copy, Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct CredentialType(u16);

#[derive(Clone, PartialEq, Default, Debug, Serialize, Deserialize)]
pub struct Capabilities {
    versions: Vec<ProtocolVersion, { consts::MAX_PROTOCOL_VERSIONS }>,
    cipher_suites: Vec<CipherSuite, { consts::MAX_CIPHER_SUITES }>,
    extensions: Vec<ExtensionType, { consts::MAX_EXTENSION_TYPES }>,
    proposals: Vec<ProposalType, { consts::MAX_PROPOSAL_TYPES }>,
    credentials: Vec<CredentialType, { consts::MAX_CREDENTIAL_TYPES }>,
}

impl Capabilities {
    pub fn new<C: Crypto>() -> Self {
        stack::update();
        Self {
            versions: Vec::from_slice(&[consts::SUPPORTED_VERSION]).unwrap(),
            cipher_suites: Vec::from_slice(&[C::CIPHER_SUITE]).unwrap(),
            credentials: Vec::from_slice(&[consts::SUPPORTED_CREDENTIAL_TYPE]).unwrap(),
            ..Default::default()
        }
    }
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct Lifetime {
    not_before: u64,
    not_after: u64,
}

impl Default for Lifetime {
    fn default() -> Self {
        stack::update();
        Self {
            not_before: u64::MIN,
            not_after: u64::MAX,
        }
    }
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
#[discriminant = "u8"]
pub enum LeafNodeSource<C: Crypto> {
    #[discriminant = "1"]
    KeyPackage(Lifetime),

    #[discriminant = "2"]
    Update(Nil),

    #[discriminant = "3"]
    Commit(HashOutput<C>),
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct LeafNodeExtension {
    extension_type: ExtensionType,
    extension_data: Opaque<{ consts::MAX_LEAF_NODE_EXTENSION_LEN }>,
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct LeafNodeTbs<C: Crypto> {
    pub signature_key: SignaturePublicKey<C>,
    pub encryption_key: HpkePublicKey<C>,
    pub credential: Credential,
    pub capabilities: Capabilities,
    pub leaf_node_source: LeafNodeSource<C>,
    pub extensions: Vec<LeafNodeExtension, { consts::MAX_LEAF_NODE_EXTENSIONS }>,
}

pub type LeafNode<C> = Signed<LeafNodeTbs<C>, C>;

impl<C: Crypto> SignatureLabel for LeafNode<C> {
    const SIGNATURE_LABEL: &[u8] = b"LeafNodeTBS";
}

#[derive(Clone, Serialize, Deserialize)]
pub struct KeyPackageExtension {
    pub extension_type: ExtensionType,
    pub extension_data: Opaque<{ consts::MAX_KEY_PACKAGE_EXTENSION_LEN }>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct KeyPackageTbs<C: Crypto> {
    pub protocol_version: ProtocolVersion,
    pub cipher_suite: CipherSuite,
    pub init_key: HpkePublicKey<C>,
    pub leaf_node: LeafNode<C>,
    pub extensions: Vec<KeyPackageExtension, { consts::MAX_KEY_PACKAGE_EXTENSIONS }>,
}

pub type KeyPackage<C> = Signed<KeyPackageTbs<C>, C>;

impl<C: Crypto> SignatureLabel for KeyPackage<C> {
    const SIGNATURE_LABEL: &[u8] = b"KeyPackageTBS";
}

#[derive(Debug, Serialize, Deserialize)]
pub struct KeyPackagePriv<C: Crypto> {
    pub init_priv: HpkePrivateKey<C>,
    pub encryption_priv: HpkePrivateKey<C>,
    pub signature_priv: SignaturePrivateKey<C>,
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct GroupId(pub Opaque<{ consts::MAX_GROUP_ID_SIZE }>);

#[derive(Copy, Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct Epoch(pub u64);

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct TreeHash<C: Crypto>(pub HashOutput<C>);

#[derive(Clone, Default, Debug, Serialize, Deserialize)]
pub struct ConfirmedTranscriptHash<C: Crypto>(pub HashOutput<C>);

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GroupContextExtension {
    pub extension_type: ExtensionType,
    pub extension_data: Opaque<{ consts::MAX_GROUP_CONTEXT_EXTENSION_LEN }>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GroupContext<C: Crypto> {
    pub version: ProtocolVersion,
    pub cipher_suite: CipherSuite,
    pub group_id: GroupId,
    pub epoch: Epoch,
    pub tree_hash: TreeHash<C>,
    pub confirmed_transcript_hash: ConfirmedTranscriptHash<C>,
    pub extensions: Vec<GroupContextExtension, { consts::MAX_GROUP_CONTEXT_EXTENSIONS }>,
}

// To be able to materialize GroupContext in static memory, we can remove the generic dependency
// from MAX_SIZE by assuming that the two hashes are at most 64 bytes long.  This is true of all
// current cipher
// suites.
const GROUP_CONTEXT_MAX_SIZE: usize = ProtocolVersion::MAX_SIZE
    + CipherSuite::MAX_SIZE
    + GroupId::MAX_SIZE
    + Epoch::MAX_SIZE
    + 64
    + 64
    + (consts::MAX_GROUP_CONTEXT_EXTENSIONS * consts::MAX_GROUP_CONTEXT_EXTENSION_LEN);

impl<C: Crypto> Materialize for GroupContext<C> {
    type Storage = Vec<u8, { GROUP_CONTEXT_MAX_SIZE }>;
}

#[derive(Copy, Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct LeafIndex(pub u32);

// TODO(RLB) We should implement a constant-time version of PartialEq for this type.
#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct ConfirmationTag<C: Crypto>(pub HashOutput<C>);

#[derive(Debug, Serialize, Deserialize)]
pub struct GroupInfoExtension<C: CryptoSizes> {
    pub extension_type: ExtensionType,
    pub extension_data: SerializedRatchetTree<C>,
}

#[derive(Serialize, Deserialize)]
pub struct GroupInfoTbs<C: CryptoSizes> {
    pub group_context: GroupContext<C>,
    pub extensions: Vec<GroupInfoExtension<C>, { consts::MAX_GROUP_INFO_EXTENSIONS }>,
    pub confirmation_tag: ConfirmationTag<C>,
    pub signer: LeafIndex,
}

pub type GroupInfo<C> = Signed<GroupInfoTbs<C>, C>;

impl<C: CryptoSizes> SignatureLabel for GroupInfo<C> {
    const SIGNATURE_LABEL: &[u8] = b"GroupInfoTBS";
}

impl<C: CryptoSizes> AeadEncrypt<C, EncryptedGroupInfo<C>> for GroupInfo<C> {}

#[derive(Serialize, Deserialize)]
pub struct JoinerSecret<C: Crypto>(pub HashOutput<C>);

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PathSecret<C: Crypto>(pub HashOutput<C>);

#[derive(Serialize, Deserialize)]
pub struct GroupSecrets<C: Crypto> {
    pub joiner_secret: JoinerSecret<C>,
    pub path_secret: Option<PathSecret<C>>,

    // XXX(RLB): This is a stub for now because we don't support PSKs.
    pub psks: Vec<Nil, 0>,
}

impl<C: CryptoSizes> AeadEncrypt<C, EncryptedGroupSecrets<C>> for GroupSecrets<C> {}

pub type HpkeEncryptedGroupSecrets<C> = HpkeCiphertext<C, EncryptedGroupSecrets<C>>;

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct HashRef<C: Crypto>(pub HashOutput<C>);

#[derive(Debug, Serialize, Deserialize)]
pub struct EncryptedGroupSecretsEntry<C: CryptoSizes> {
    pub new_member: HashRef<C>,
    pub encrypted_group_secrets: HpkeCiphertext<C, EncryptedGroupSecrets<C>>,
}

#[derive(Serialize, Deserialize)]
pub struct Welcome<C: CryptoSizes> {
    pub cipher_suite: CipherSuite,
    pub secrets: Vec<EncryptedGroupSecretsEntry<C>, { consts::MAX_JOINERS_PER_WELCOME }>,
    pub encrypted_group_info: EncryptedGroupInfo<C>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct RawPathSecret<C: Crypto>(pub RawHashOutput<C>);

impl<C: CryptoSizes> AeadEncrypt<C, EncryptedPathSecret<C>> for RawPathSecret<C> {}

pub type HpkeEncryptedPathSecret<C> = HpkeCiphertext<C, EncryptedPathSecret<C>>;

#[derive(Serialize, Deserialize)]
pub struct UpdatePathNode<C: CryptoSizes> {
    pub encryption_key: HpkePublicKey<C>,
    pub encrypted_path_secret: Vec<HpkeEncryptedPathSecret<C>, { consts::MAX_RESOLUTION_SIZE }>,
}

#[derive(Serialize, Deserialize)]
pub struct UpdatePath<C: CryptoSizes> {
    pub leaf_node: LeafNode<C>,
    pub nodes: Vec<UpdatePathNode<C>, { consts::MAX_TREE_DEPTH }>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Add<C: Crypto> {
    pub key_package: KeyPackage<C>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Remove {
    pub removed: LeafIndex,
}

#[derive(Clone, Serialize, Deserialize)]
#[discriminant = "u16"]
pub enum Proposal<C: Crypto> {
    #[discriminant = "1"]
    Add(Add<C>),

    #[discriminant = "3"]
    Remove(Remove),
}

#[derive(Serialize, Deserialize)]
#[discriminant = "u8"]
pub enum ProposalOrRef<C: Crypto> {
    #[discriminant = "1"]
    Proposal(Proposal<C>),
}

#[derive(Serialize, Deserialize)]
pub struct Commit<C: CryptoSizes> {
    pub proposals: Vec<ProposalOrRef<C>, { consts::MAX_PROPOSALS_PER_COMMIT }>,
    pub path: Option<UpdatePath<C>>,
}

#[derive(Serialize, Deserialize)]
#[discriminant = "u8"]
pub enum Sender {
    #[discriminant = "1"]
    Member(LeafIndex),
}

#[derive(Serialize, Deserialize)]
#[discriminant = "u8"]
pub enum MessageContent<C: CryptoSizes> {
    #[discriminant = "3"]
    Commit(Commit<C>),
}

#[derive(Clone, Default, Serialize, Deserialize)]
pub struct PrivateMessageAad(Opaque<{ consts::MAX_PRIVATE_MESSAGE_AAD_LEN }>);

#[derive(Serialize, Deserialize)]
pub struct FramedContent<C: CryptoSizes> {
    pub group_id: GroupId,
    pub epoch: Epoch,
    pub sender: Sender,
    pub authenticated_data: PrivateMessageAad,
    pub content: MessageContent<C>,
}

#[derive(Serialize, Deserialize)]
pub struct WireFormat(u16);

#[derive(Serialize, Deserialize)]
#[discriminant = "u8"]
pub enum FramedContentBinder<C: Crypto> {
    #[discriminant = "1"]
    Member(GroupContext<C>),
}

#[derive(Serialize, Deserialize)]
pub struct FramedContentTbs<C: CryptoSizes> {
    pub version: ProtocolVersion,
    pub wire_format: WireFormat,
    pub content: FramedContent<C>,
    pub binder: FramedContentBinder<C>,
}

pub type SignedFramedContent<C> = Signed<FramedContentTbs<C>, C>;

impl<C: CryptoSizes> SignatureLabel for SignedFramedContent<C> {
    const SIGNATURE_LABEL: &[u8] = b"FramedContentTBS";
}

#[derive(PartialEq, Serialize, Deserialize)]
pub struct Generation(pub u32);

#[derive(Serialize, Deserialize)]
pub struct ReuseGuard(pub [u8; 4]);

#[derive(Copy, Clone, Serialize, Deserialize)]
struct ContentType(u8);

const CONTENT_TYPE_COMMIT: ContentType = ContentType(3);

pub struct SenderDataSecret<C: Crypto>(pub HashOutput<C>);

#[derive(Serialize, Materialize)]
struct SenderDataAad<'a> {
    group_id: &'a GroupId,
    epoch: Epoch,
    content_type: ContentType,
}

#[derive(Serialize, Deserialize)]
pub struct SenderData {
    pub leaf_index: LeafIndex,
    pub generation: Generation,
    pub reuse_guard: ReuseGuard,
}

impl<C: CryptoSizes> AeadEncrypt<C, EncryptedSenderData<C>> for SenderData {}

#[derive(Serialize, Materialize)]
struct PrivateMessageContentAad<'a> {
    group_id: &'a GroupId,
    epoch: Epoch,
    content_type: ContentType,
    authenticated_data: &'a PrivateMessageAad,
}

#[derive(Serialize, Deserialize)]
pub struct PrivateMessageContent<C: CryptoSizes> {
    commit: Commit<C>,
    signature: Signature<C>,
    confirmation_tag: ConfirmationTag<C>,
}

impl<C: CryptoSizes> AeadEncrypt<C, EncryptedPrivateMessageContent<C>>
    for PrivateMessageContent<C>
{
}

#[derive(Clone, Serialize, Deserialize)]
pub struct PrivateMessage<C: CryptoSizes> {
    group_id: GroupId,
    epoch: Epoch,
    content_type: ContentType,
    authenticated_data: PrivateMessageAad,
    encrypted_sender_data: EncryptedSenderData<C>,
    ciphertext: EncryptedPrivateMessageContent<C>,
}

impl<C: CryptoSizes> PrivateMessage<C> {
    pub fn new(
        signed_framed_content: SignedFramedContent<C>,
        confirmation_tag: ConfirmationTag<C>,
        sender_data: SenderData,
        mut key: AeadKey<C>,
        nonce: AeadNonce<C>,
        sender_data_secret: &SenderDataSecret<C>,
        authenticated_data: PrivateMessageAad,
    ) -> Result<Self> {
        stack::update();
        // Form payload
        let MessageContent::Commit(commit) = signed_framed_content.tbs.content.content;
        let signature = signed_framed_content.signature;
        let plaintext = PrivateMessageContent {
            commit,
            signature,
            confirmation_tag,
        };

        // Encrypt payload
        key.as_mut()
            .iter_mut()
            .zip(sender_data.reuse_guard.0.iter())
            .for_each(|(k, r)| *k ^= r);
        let group_id = signed_framed_content.tbs.content.group_id;
        let epoch = signed_framed_content.tbs.content.epoch;
        let aad = PrivateMessageContentAad {
            group_id: &group_id,
            epoch,
            content_type: CONTENT_TYPE_COMMIT,
            authenticated_data: &authenticated_data,
        }
        .materialize()?;

        let ciphertext = plaintext.seal(&key, &nonce, &aad)?;

        // Encrypt sender data
        let (key, nonce) = C::sender_data_key_nonce(&sender_data_secret.0, ciphertext.as_ref());
        let aad = SenderDataAad {
            group_id: &group_id,
            epoch,
            content_type: CONTENT_TYPE_COMMIT,
        }
        .materialize()?;

        let encrypted_sender_data = AeadEncrypt::<C, _>::seal(&sender_data, &key, &nonce, &aad)?;

        Ok(Self {
            group_id,
            epoch,
            content_type: CONTENT_TYPE_COMMIT,
            authenticated_data,
            encrypted_sender_data,
            ciphertext,
        })
    }

    pub fn open(
        self,
        sender_data_secret: &SenderDataSecret<C>,
        sender_key_source: &impl SenderKeySource<C>,
        group_context: &GroupContext<C>,
    ) -> Result<(SignedFramedContent<C>, ConfirmationTag<C>)> {
        stack::update();
        // Check outer properties are correct
        if self.group_id != group_context.group_id {
            return Err(Error("Wrong group"));
        }

        if self.epoch != group_context.epoch {
            return Err(Error("Wrong epoch"));
        }

        // Decrypt sender data
        let (key, nonce) =
            C::sender_data_key_nonce(&sender_data_secret.0, self.ciphertext.as_ref());
        let aad = SenderDataAad {
            group_id: &self.group_id,
            epoch: self.epoch,
            content_type: CONTENT_TYPE_COMMIT,
        }
        .materialize()?;

        let sender_data =
            AeadEncrypt::<C, _>::open(self.encrypted_sender_data, &key, &nonce, &aad)?;
        let SenderData {
            leaf_index,
            generation,
            reuse_guard,
        } = sender_data;

        // Look up keys for the sender and generation
        let (mut key, nonce) = sender_key_source
            .find_keys(leaf_index, generation)
            .ok_or(Error("Unknown sender"))?;
        key.as_mut()
            .iter_mut()
            .zip(reuse_guard.0.iter())
            .for_each(|(k, r)| *k ^= r);

        // Decrypt content
        let aad = PrivateMessageContentAad {
            group_id: &self.group_id,
            epoch: self.epoch,
            content_type: CONTENT_TYPE_COMMIT,
            authenticated_data: &self.authenticated_data,
        }
        .materialize()?;

        let content = PrivateMessageContent::open(self.ciphertext, &key, &nonce, &aad)?;

        // Construct objects to return
        let tbs = FramedContentTbs {
            version: consts::SUPPORTED_VERSION,
            wire_format: consts::SUPPORTED_WIRE_FORMAT,
            content: FramedContent {
                group_id: self.group_id,
                epoch: self.epoch,
                sender: Sender::Member(leaf_index),
                authenticated_data: self.authenticated_data,
                content: MessageContent::Commit(content.commit),
            },
            binder: FramedContentBinder::<C>::Member(group_context.clone()),
        };

        let signed_framed_content = SignedFramedContent {
            tbs,
            signature: content.signature,
        };
        let confirmation_tag = content.confirmation_tag;

        Ok((signed_framed_content, confirmation_tag))
    }
}

pub trait SenderKeySource<C: Crypto> {
    fn find_keys<'a>(
        &self,
        sender: LeafIndex,
        generation: Generation,
    ) -> Option<(AeadKey<C>, AeadNonce<C>)>;
}
