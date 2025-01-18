use crate::common::*;
use crate::crypto::{self, *};
use crate::io::*;
use crate::key_schedule::*;
use crate::stack::*;
use crate::syntax::*;
use crate::{
    make_storage, mls_enum, mls_newtype_opaque, mls_newtype_primitive, mls_struct, serialize,
    stack_ptr, tick,
};

use core::ops::{Deref, DerefMut};
use heapless::Vec;
use rand_core::CryptoRngCore;

pub mod consts {
    use super::{CredentialType, ExtensionType, ProtocolVersion, WireFormat};

    use crate::syntax::Serialize;
    use crate::treekem::RatchetTree;

    pub const SUPPORTED_VERSION: ProtocolVersion = ProtocolVersion(0x0001); // mls10
    pub const SUPPORTED_CREDENTIAL_TYPE: CredentialType = CredentialType(0x0001); // basic
    pub const SUPPORTED_WIRE_FORMAT: WireFormat = WireFormat(0x0002); // mls_private_message

    pub const MAX_CREDENTIAL_SIZE: usize = 128;
    pub const MAX_PROTOCOL_VERSIONS: usize = 1;
    pub const MAX_CIPHER_SUITES: usize = 1;
    pub const MAX_EXTENSION_TYPES: usize = 0;
    pub const MAX_PROPOSAL_TYPES: usize = 0;
    pub const MAX_CREDENTIAL_TYPES: usize = 1;
    pub const MAX_EXTENSION_SIZE: usize = 128;
    pub const MAX_EXTENSIONS: usize = 0;
    pub const MAX_GROUP_ID_SIZE: usize = 128;
    pub const MAX_WELCOME_PSKS: usize = 0;
    pub const MAX_GROUP_INFO_EXTENSIONS: usize = 1;
    pub const MAX_GROUP_INFO_EXTENSION_SIZE: usize = RatchetTree::MAX_SIZE;
    pub const MAX_JOINERS_PER_WELCOME: usize = 1;
    pub const MAX_PRIVATE_MESSAGE_AAD_SIZE: usize = 0;
    pub const MAX_PROPOSALS_PER_COMMIT: usize = 1;

    pub const MAX_GROUP_SIZE: usize = 8;
    pub const MAX_TREE_DEPTH: usize = (MAX_GROUP_SIZE.ilog2() as usize) + 1;

    pub const EXTENSION_TYPE_RATCHET_TREE: ExtensionType = ExtensionType(0x0002);
}

// A macro to generate signed data structures
macro_rules! mls_signed {
    ($signed_owned_type:ident + $label:literal => $val_owned_type:ident) => {
        #[derive(Clone, Default, Debug, PartialEq)]
        pub struct $signed_owned_type {
            pub tbs: $val_owned_type,
            pub signature: Signature,
        }

        impl $signed_owned_type {
            const SIGNATURE_LABEL: &[u8] = $label;

            pub fn new(
                tbs: $val_owned_type,
                signature_priv: &SignaturePrivateKey,
            ) -> Result<$signed_owned_type> {
                tick!();

                // Serialize the part to be signed
                let tbs_raw = serialize!($val_owned_type, tbs);

                // Populate the signature
                let signature =
                    crypto::sign_with_label(&tbs_raw, Self::SIGNATURE_LABEL, signature_priv)?;

                let group_info = $signed_owned_type { tbs, signature };
                Ok(group_info)
            }

            pub fn re_sign(&mut self, signature_priv: &SignaturePrivateKey) -> Result<()> {
                tick!();

                let tbs_raw = serialize!($val_owned_type, self.tbs);
                self.signature =
                    crypto::sign_with_label(&tbs_raw, Self::SIGNATURE_LABEL, signature_priv)?;
                Ok(())
            }

            pub fn verify(&self, signature_key: &SignaturePublicKey) -> Result<()> {
                tick!();

                let tbs_raw = serialize!($val_owned_type, self.tbs);
                crypto::verify_with_label(
                    tbs_raw.as_ref(),
                    $signed_owned_type::SIGNATURE_LABEL,
                    signature_key,
                    &self.signature,
                )
            }
        }

        impl Deref for $signed_owned_type {
            type Target = $val_owned_type;

            fn deref(&self) -> &Self::Target {
                tick!();

                &self.tbs
            }
        }

        impl DerefMut for $signed_owned_type {
            fn deref_mut(&mut self) -> &mut Self::Target {
                tick!();

                &mut self.tbs
            }
        }

        impl Serialize for $signed_owned_type {
            const MAX_SIZE: usize = sum(&[$val_owned_type::MAX_SIZE, Signature::MAX_SIZE]);

            fn serialize(&self, writer: &mut impl Write) -> Result<()> {
                tick!();

                self.tbs.serialize(writer)?;
                self.signature.serialize(writer)?;
                Ok(())
            }
        }

        impl<'a> Deserialize<'a> for $signed_owned_type {
            fn deserialize(reader: &mut impl ReadRef<'a>) -> Result<Self> {
                let tbs = $val_owned_type::deserialize(reader)?;
                let signature = Signature::deserialize(reader)?;

                Ok(Self { tbs, signature })
            }
        }
    };
}

// A macro to generate AEAD-encrypted data structures
macro_rules! mls_encrypted {
    ($ct_owned_type:ident, $pt_owned_type:ident,) => {
        mls_newtype_opaque! {
            $ct_owned_type,
            { $pt_owned_type::MAX_SIZE + crypto::AEAD_OVERHEAD }
        }

        impl $ct_owned_type {
            const MAX_CT_SIZE: usize = $pt_owned_type::MAX_SIZE + crypto::AEAD_OVERHEAD;

            pub fn seal(
                plaintext: $pt_owned_type,
                key: AeadKey,
                nonce: AeadNonce,
                aad: &[u8],
            ) -> Result<Self> {
                tick!();

                let pt = serialize!($pt_owned_type, plaintext);

                let mut ct = Vec::<u8, { Self::MAX_CT_SIZE }>::new();
                crypto::aead_seal(&mut ct, &pt, key, nonce, aad);

                Ok(Self(Opaque::from(ct)))
            }

            pub fn open(
                &self,
                key: AeadKey,
                nonce: AeadNonce,
                aad: &[u8],
            ) -> Result<Vec<u8, { $pt_owned_type::MAX_SIZE }>> {
                tick!();

                let ct = self.0.as_ref();

                let mut pt = Vec::new();
                let len = crypto::aead_open(&mut pt, &ct, key, nonce, aad)?;

                Ok(pt)
            }
        }
    };
}

// A macro to generate HPKE-encrypted data structures, with a given AEAD-encrypted struct
macro_rules! mls_hpke_encrypted {
    ($hpke_owned_type:ident,
     $ct_owned_type:ident,
     $pt_owned_type:ident,) => {
        mls_struct! {
            $hpke_owned_type,
            kem_output: HpkeKemOutput,
            ciphertext: $ct_owned_type,
        }

        impl $hpke_owned_type {
            pub fn seal(
                rng: &mut impl CryptoRngCore,
                plaintext: $pt_owned_type,
                encryption_key: &HpkePublicKey,
                aad: &[u8],
            ) -> Result<Self> {
                tick!();

                let (kem_output, kem_secret) = crypto::hpke_encap(rng, &encryption_key);
                let (key, nonce) = crypto::hpke_key_nonce(kem_secret);

                let ciphertext = $ct_owned_type::seal(plaintext, key, nonce, aad)?;

                Ok(Self {
                    kem_output,
                    ciphertext,
                })
            }

            pub fn open(
                &self,
                encryption_priv: &HpkePrivateKey,
                aad: &[u8],
            ) -> Result<Vec<u8, { $pt_owned_type::MAX_SIZE }>> {
                tick!();

                let kem_secret = crypto::hpke_decap(encryption_priv, &self.kem_output);
                let (key, nonce) = crypto::hpke_key_nonce(kem_secret);

                self.ciphertext.open(key, nonce, aad)
            }
        }
    };
}

// Optional values
impl<T: Serialize> Serialize for Option<T> {
    const MAX_SIZE: usize = 1 + T::MAX_SIZE;

    fn serialize(&self, writer: &mut impl Write) -> Result<()> {
        tick!();

        match self {
            None => writer.write(&[0]),
            Some(val) => writer.write(&[1]).and_then(|_| val.serialize(writer)),
        }
    }
}

impl<'a, V: Deserialize<'a>> Deserialize<'a> for Option<V> {
    fn deserialize(reader: &mut impl ReadRef<'a>) -> Result<Self> {
        tick!();

        let indicator = u8::deserialize(reader)?;
        match indicator {
            0 => Ok(None),
            1 => V::deserialize(reader).and_then(|val| Ok(Some(val))),
            _ => Err(Error("Invalid encoding")),
        }
    }
}

// Credentials
mls_newtype_opaque! {
    BasicCredential,
    consts::MAX_CREDENTIAL_SIZE
}

mls_enum! {
    u16 => Credential,
    1 => Basic(BasicCredential),
}

impl Default for Credential {
    fn default() -> Self {
        tick!();

        Self::Basic(BasicCredential::default())
    }
}

impl From<&[u8]> for Credential {
    fn from(val: &[u8]) -> Self {
        tick!();

        let vec: Vec<u8, { consts::MAX_CREDENTIAL_SIZE }> = val.try_into().unwrap();
        Credential::Basic(BasicCredential::from(Opaque::from(vec)))
    }
}

// Capabilities
mls_newtype_primitive! { ProtocolVersion => u16 }
mls_newtype_primitive! { ExtensionType => u16 }
mls_newtype_primitive! { ProposalType => u16 }
mls_newtype_primitive! { CredentialType => u16 }

type ProtocolVersionList = Vec<ProtocolVersion, { consts::MAX_PROTOCOL_VERSIONS }>;
type CipherSuiteList = Vec<CipherSuite, { consts::MAX_CIPHER_SUITES }>;
type ExtensionTypeList = Vec<ExtensionType, { consts::MAX_EXTENSION_TYPES }>;
type ProposalTypeList = Vec<ProposalType, { consts::MAX_PROPOSAL_TYPES }>;
type CredentialTypeList = Vec<CredentialType, { consts::MAX_CREDENTIAL_TYPES }>;

mls_struct! {
    Capabilities,
    versions: ProtocolVersionList,
    cipher_suites: CipherSuiteList,
    extensions: ExtensionTypeList,
    proposals: ProposalTypeList,
    credentials: CredentialTypeList,
}

// Leaf node source
mls_newtype_primitive! { Timestamp => u64 }

mls_struct! {
    Lifetime,
    not_before: Timestamp,
    not_after: Timestamp,
}

mls_enum! {
    u8 => LeafNodeSource,
    1 => KeyPackage(Lifetime),
    2 => Update(Nil),
    3 => Commit(HashOutput),
}

impl Default for LeafNodeSource {
    fn default() -> Self {
        tick!();

        let infinite_lifetime = Lifetime {
            not_before: Timestamp(0),
            not_after: Timestamp(u64::MAX),
        };
        Self::KeyPackage(infinite_lifetime)
    }
}

// Extensions
mls_newtype_opaque! {
    ExtensionData,
    consts::MAX_EXTENSION_SIZE
}

mls_struct! {
    Extension,
    extension_type: ExtensionType,
    extension_data: ExtensionData,
}

type ExtensionList = Vec<Extension, { consts::MAX_EXTENSIONS }>;

// LeafNode
mls_struct! {
    LeafNodeTbs,
    encryption_key: HpkePublicKey,
    signature_key: SignaturePublicKey,
    credential: Credential,
    capabilities: Capabilities,
    leaf_node_source: LeafNodeSource,
    extensions: ExtensionList,
}

mls_struct! {
    LeafNodePriv,
    encryption_priv: HpkePrivateKey,
    signature_priv: SignaturePrivateKey,
}

mls_signed! { LeafNode + b"LeafNodeTBS" => LeafNodeTbs }

// KeyPackage
mls_struct! {
    KeyPackageTbs,
    protocol_version: ProtocolVersion,
    cipher_suite: CipherSuite,
    init_key: HpkePublicKey,
    leaf_node: LeafNode,
    extensions: ExtensionList,
}

mls_struct! {
    KeyPackagePriv,
    init_priv: HpkePrivateKey,
    encryption_priv: HpkePrivateKey,
    signature_priv: SignaturePrivateKey,
}

mls_signed! { KeyPackage + b"KeyPackageTBS" => KeyPackageTbs }

// GroupInfo
mls_newtype_opaque! {
    GroupId,
    consts::MAX_GROUP_ID_SIZE
}

mls_newtype_primitive! { Epoch => u64 }

mls_struct! {
    GroupContext,
    version: ProtocolVersion,
    cipher_suite: CipherSuite,
    group_id: GroupId,
    epoch: Epoch,
    tree_hash: HashOutput,
    confirmed_transcript_hash: HashOutput,
    extensions: ExtensionList,
}

// Extensions
mls_newtype_opaque! {
    GroupInfoExtensionData,
    consts::MAX_GROUP_INFO_EXTENSION_SIZE
}

mls_struct! {
    GroupInfoExtension,
    extension_type: ExtensionType,
    extension_data: GroupInfoExtensionData,
}

type GroupInfoExtensionList = Vec<GroupInfoExtension, { consts::MAX_GROUP_INFO_EXTENSIONS }>;

mls_newtype_primitive! { LeafIndex => u32 }

mls_struct! {
    GroupInfoTbs,
    group_context: GroupContext,
    extensions: GroupInfoExtensionList,
    confirmation_tag: HashOutput,
    signer: LeafIndex,
}

mls_signed! { GroupInfo + b"GroupInfoTBS" => GroupInfoTbs }

// Welcome

pub type OptionalPathSecret = Option<HashOutput>;

// XXX(RLB) These are stubs for now because we don't support PSKs; the `psks` vector must always
// have length zero.
type PreSharedKeyIDList = Vec<Nil, { consts::MAX_WELCOME_PSKS }>;

mls_struct! {
    GroupSecrets,
    joiner_secret: JoinerSecret,
    path_secret: OptionalPathSecret,
    psks: PreSharedKeyIDList,
}

mls_encrypted! {
    AeadEncryptedGroupSecrets,
    GroupSecrets,
}

mls_hpke_encrypted! {
    HpkeEncryptedGroupSecrets,
    AeadEncryptedGroupSecrets,
    GroupSecrets,
}

mls_struct! {
    EncryptedGroupSecrets,
    new_member: HashOutput,
    encrypted_group_secrets: HpkeEncryptedGroupSecrets,
}

type EncryptedGroupSecretsList = Vec<EncryptedGroupSecrets, { consts::MAX_JOINERS_PER_WELCOME }>;

mls_encrypted! {
    EncryptedGroupInfo,
    GroupInfo,
}

mls_struct! {
    Welcome,
    cipher_suite: CipherSuite,
    secrets: EncryptedGroupSecretsList,
    encrypted_group_info: EncryptedGroupInfo,
}

// PrivateMessage
type RawPathSecret = Raw<{ crypto::consts::HASH_OUTPUT_SIZE }>;

mls_encrypted! {
    AeadEncryptedPathSecret,
    RawPathSecret,
}

mls_hpke_encrypted! {
    EncryptedPathSecret,
    AeadEncryptedPathSecret,
    RawPathSecret,
}

type EncryptedPathSecretList = Vec<EncryptedPathSecret, { consts::MAX_TREE_DEPTH }>;

mls_struct! {
    UpdatePathNode,
    encryption_key: HpkePublicKey,
    encrypted_path_secret: EncryptedPathSecretList,
}

pub type UpdatePathNodeList = Vec<UpdatePathNode, { consts::MAX_TREE_DEPTH }>;

mls_struct! {
    UpdatePath,
    leaf_node: LeafNode,
    nodes: UpdatePathNodeList,
}

mls_struct! {
    Add,
    key_package: KeyPackage,
}

mls_struct! {
    Remove,
    removed: LeafIndex,
}

mls_enum! {
    u16 => Proposal,
    1 => Add(Add),
    3 => Remove(Remove),
}

mls_enum! {
    u8 => ProposalOrRef,
    1 => Proposal(Proposal),
}

type OptionalUpdatePath = Option<UpdatePath>;

type ProposalList = Vec<ProposalOrRef, { consts::MAX_PROPOSALS_PER_COMMIT }>;

mls_struct! {
    Commit,
    proposals: ProposalList,
    path: OptionalUpdatePath,
}

mls_enum! {
    u8 => Sender,
    1 => Member(LeafIndex),
}

impl Default for Sender {
    fn default() -> Self {
        tick!();

        Self::Member(LeafIndex(0))
    }
}

mls_enum! {
    u8 => MessageContent,
    3 => Commit(Commit),
}

impl Default for MessageContent {
    fn default() -> Self {
        tick!();

        Self::Commit(Commit::default())
    }
}

mls_newtype_opaque! {
    PrivateMessageAad,
    consts::MAX_PRIVATE_MESSAGE_AAD_SIZE
}

mls_struct! {
    FramedContent,
    group_id: GroupId,
    epoch: Epoch,
    sender: Sender,
    authenticated_data: PrivateMessageAad,
    content: MessageContent,
}

mls_newtype_primitive! { WireFormat => u16 }

mls_enum! {
    u8 => FramedContentBinder,
    1 => Member(GroupContext),
}

impl Default for FramedContentBinder {
    fn default() -> Self {
        tick!();

        Self::Member(GroupContext::default())
    }
}

mls_struct! {
    FramedContentTbs,
    version: ProtocolVersion,
    wire_format: WireFormat,
    content: FramedContent,
    binder: FramedContentBinder,
}

mls_signed! {
    SignedFramedContent + b"FramedContentTBS"
    => FramedContentTbs
}

mls_newtype_primitive! { Generation => u32 }
mls_newtype_primitive! { ReuseGuard => u32 }

struct SenderDataAad<'a> {
    group_id: &'a GroupId,
    epoch: Epoch,
    content_type: ContentType,
}

impl<'a> Serialize for SenderDataAad<'a> {
    const MAX_SIZE: usize = sum(&[GroupId::MAX_SIZE, Epoch::MAX_SIZE, ContentType::MAX_SIZE]);

    fn serialize(&self, writer: &mut impl Write) -> Result<()> {
        tick!();

        self.group_id.serialize(writer)?;
        self.epoch.serialize(writer)?;
        self.content_type.serialize(writer)?;
        Ok(())
    }
}

mls_struct! {
    SenderData,
    leaf_index: LeafIndex,
    generation: Generation,
    reuse_guard: ReuseGuard,
}

mls_encrypted! {
    EncryptedSenderData,
    SenderData,
}

struct PrivateMessageContentAad<'a> {
    group_id: &'a GroupId,
    epoch: Epoch,
    content_type: ContentType,
    authenticated_data: &'a PrivateMessageAad,
}

impl<'a> Serialize for PrivateMessageContentAad<'a> {
    const MAX_SIZE: usize = sum(&[
        GroupId::MAX_SIZE,
        Epoch::MAX_SIZE,
        ContentType::MAX_SIZE,
        PrivateMessageAad::MAX_SIZE,
    ]);

    fn serialize(&self, writer: &mut impl Write) -> Result<()> {
        tick!();

        self.group_id.serialize(writer)?;
        self.epoch.serialize(writer)?;
        self.content_type.serialize(writer)?;
        self.authenticated_data.serialize(writer)?;
        Ok(())
    }
}

mls_struct! {
    PrivateMessageContent,
    commit: Commit,
    // XXX(RLB) Destructured FramedContentAuthData
    signature: Signature,
    confirmation_tag: HashOutput,
    // XXX(RLB) No padding
}

mls_encrypted! {
    EncryptedPrivateMessageContent,
    PrivateMessageContent,
}

mls_newtype_primitive! { ContentType => u8 }

const CONTENT_TYPE_COMMIT: ContentType = ContentType(3);

mls_struct! {
    PrivateMessage,
    group_id: GroupId,
    epoch: Epoch,
    content_type: ContentType,
    authenticated_data: PrivateMessageAad,
    encrypted_sender_data: EncryptedSenderData,
    ciphertext: EncryptedPrivateMessageContent,
}

impl PrivateMessage {
    pub fn new(
        signed_framed_content: SignedFramedContent,
        confirmation_tag: HashOutput,
        sender_data: SenderData,
        key: AeadKey,
        nonce: AeadNonce,
        sender_data_secret: &HashOutput,
        authenticated_data: PrivateMessageAad,
    ) -> Result<Self> {
        tick!();

        // Form payload
        let MessageContent::Commit(commit) = signed_framed_content.tbs.content.content;
        let signature = signed_framed_content.signature;
        let plaintext = PrivateMessageContent {
            commit,
            signature,
            confirmation_tag,
        };

        // Encrypt payload
        let group_id = signed_framed_content.tbs.content.group_id;
        let epoch = signed_framed_content.tbs.content.epoch;
        let aad = serialize!(
            PrivateMessageContentAad,
            PrivateMessageContentAad {
                group_id: &group_id,
                epoch,
                content_type: CONTENT_TYPE_COMMIT,
                authenticated_data: &authenticated_data,
            }
        );

        let ciphertext = EncryptedPrivateMessageContent::seal(plaintext, key, nonce, &aad)?;

        // Encrypt sender data
        let (key, nonce) = crypto::sender_data_key_nonce(sender_data_secret, ciphertext.as_ref());
        let aad = serialize!(
            SenderDataAad,
            SenderDataAad {
                group_id: &group_id,
                epoch,
                content_type: CONTENT_TYPE_COMMIT,
            }
        );

        let encrypted_sender_data = EncryptedSenderData::seal(sender_data, key, nonce, &aad)?;

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
        sender_data_secret: &HashOutput,
        sender_key_source: &impl SenderKeySource,
        group_context: &GroupContext,
    ) -> Result<(SignedFramedContent, HashOutput)> {
        tick!();

        // Check outer properties are correct
        if self.group_id != group_context.group_id {
            return Err(Error("Wrong group"));
        }

        if self.epoch != group_context.epoch {
            return Err(Error("Wrong epoch"));
        }

        // Decrypt sender data
        let (key, nonce) =
            crypto::sender_data_key_nonce(sender_data_secret, self.ciphertext.as_ref());
        let aad = serialize!(
            SenderDataAad,
            SenderDataAad {
                group_id: &self.group_id,
                epoch: self.epoch,
                content_type: CONTENT_TYPE_COMMIT,
            }
        );

        let sender_data_data = self.encrypted_sender_data.open(key, nonce, &aad)?;
        let SenderData {
            leaf_index,
            generation,
            reuse_guard, // TODO(RLB) Actually apply the reuse guard
        } = SenderData::deserialize(&mut sender_data_data.as_slice())?;

        // Look up keys for the sender and generation
        let (key, nonce) = sender_key_source
            .find_keys(leaf_index, generation)
            .ok_or(Error("Unknown sender"))?;

        // Decrypt content
        let aad = serialize!(
            PrivateMessageContentAad,
            PrivateMessageContentAad {
                group_id: &self.group_id,
                epoch: self.epoch,
                content_type: CONTENT_TYPE_COMMIT,
                authenticated_data: &self.authenticated_data,
            }
        );

        let plaintext_data = self.ciphertext.open(key, nonce, &aad)?;
        let content = PrivateMessageContent::deserialize(&mut plaintext_data.as_slice())?;

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
            binder: FramedContentBinder::Member(group_context.clone()),
        };

        let signed_framed_content = SignedFramedContent {
            tbs,
            signature: content.signature,
        };
        let confirmation_tag = content.confirmation_tag;

        Ok((signed_framed_content, confirmation_tag))
    }
}

pub trait SenderKeySource {
    fn find_keys<'a>(
        &self,
        sender: LeafIndex,
        generation: Generation,
    ) -> Option<(AeadKey, AeadNonce)>;
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::make_storage;

    macro_rules! test_sign_verify {
        ($signed_owned_type:ident, $tbs_owned_type:ident) => {
            let rng = &mut rand::thread_rng();
            let (signature_priv, signature_key) = crypto::generate_sig(rng).unwrap();
            let tbs = $tbs_owned_type::default();
            let signed = $signed_owned_type::new(tbs, &signature_priv).unwrap();

            let mut storage = make_storage!($signed_owned_type);
            signed.serialize(&mut storage).unwrap();

            let mut reader = storage.as_slice();
            let deserialized = $signed_owned_type::deserialize(&mut reader).unwrap();

            deserialized.verify(&signature_key).unwrap();
        };
    }

    #[test]
    fn signed_objects() {
        test_sign_verify!(LeafNode, LeafNodeTbs);
        test_sign_verify!(KeyPackage, KeyPackageTbs);
        test_sign_verify!(GroupInfo, GroupInfoTbs);
    }
}
