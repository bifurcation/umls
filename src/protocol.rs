use crate::common::*;
use crate::crypto::{self, *};
use crate::io::*;
use crate::syntax::*;
use crate::{
    make_storage, mls_enum, mls_newtype_opaque, mls_newtype_primitive, mls_struct,
    mls_struct_serialize, serialize,
};

use core::marker::PhantomData;
use core::ops::{Deref, DerefMut};
use heapless::Vec;

mod consts {
    use super::{CredentialType, ProtocolVersion, WireFormat};

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
    pub const MAX_GROUP_ID_SIZE: usize = 16;
    pub const MAX_WELCOME_PSKS: usize = 0;
    pub const MAX_JOINERS_PER_WELCOME: usize = 1;
    pub const MAX_PRIVATE_MESSAGE_AAD_SIZE: usize = 0;
    pub const MAX_PROPOSALS_PER_COMMIT: usize = 1;
    pub const MAX_UPDATE_PATH_LENGTH: usize = 2; // TODO(RLB) log2(MAX_GROUP_SIZE)
}

// A macro to generate signed data structures
macro_rules! mls_signed {
    ($signed_owned_type:ident + $signed_view_type:ident + $label:literal =>
     $val_owned_type:ident + $val_view_type:ident) => {
        #[derive(Clone, Default, Debug, PartialEq)]
        pub struct $signed_owned_type {
            to_be_signed: $val_owned_type,
            to_be_signed_raw: Vec<u8, { <$val_owned_type>::MAX_SIZE }>,
            signature: Signature,
        }

        #[derive(Clone, Debug, PartialEq)]
        pub struct $signed_view_type<'a> {
            to_be_signed: $val_view_type<'a>,
            to_be_signed_raw: &'a [u8],
            signature: SignatureView<'a>,
        }
        impl $signed_owned_type {
            const SIGNATURE_LABEL: &[u8] = $label;

            fn new(
                to_be_signed: $val_owned_type,
                signature_priv: SignaturePrivateKeyView,
            ) -> Result<$signed_owned_type> {
                // Serialize the part to be signed
                let mut to_be_signed_raw = Vec::new();
                to_be_signed.serialize(&mut to_be_signed_raw)?;

                // Populate the signature
                let signature = crypto::sign_with_label(
                    &to_be_signed_raw,
                    Self::SIGNATURE_LABEL,
                    signature_priv,
                )?;

                let group_info = $signed_owned_type {
                    to_be_signed,
                    to_be_signed_raw,
                    signature,
                };
                Ok(group_info)
            }
        }

        impl<'a> $signed_view_type<'a> {
            fn verify(&self, signature_key: SignaturePublicKeyView) -> Result<bool> {
                crypto::verify_with_label(
                    self.to_be_signed_raw.as_ref(),
                    $signed_owned_type::SIGNATURE_LABEL,
                    signature_key,
                    self.signature.clone(),
                )
            }
        }

        impl Serialize for $signed_owned_type {
            const MAX_SIZE: usize = sum(&[$val_owned_type::MAX_SIZE, Signature::MAX_SIZE]);

            fn serialize(&self, writer: &mut impl Write) -> Result<()> {
                self.to_be_signed.serialize(writer)?;
                self.signature.serialize(writer)?;
                Ok(())
            }
        }

        impl<'a> Deserialize<'a> for $signed_view_type<'a> {
            fn deserialize(reader: &mut impl ReadRef<'a>) -> Result<Self> {
                let mut sub_reader = reader.fork();

                let to_be_signed = $val_view_type::deserialize(&mut sub_reader)?;
                let to_be_signed_raw = reader.read_ref(sub_reader.position())?;
                let signature = SignatureView::deserialize(reader)?;

                Ok(Self {
                    to_be_signed,
                    to_be_signed_raw,
                    signature,
                })
            }
        }

        impl AsView for $signed_owned_type {
            type View<'a> = $signed_view_type<'a>;

            fn as_view<'a>(&'a self) -> Self::View<'a> {
                Self::View {
                    to_be_signed: self.to_be_signed.as_view(),
                    to_be_signed_raw: &self.to_be_signed_raw,
                    signature: self.signature.as_view(),
                }
            }
        }

        impl<'a> ToOwned for $signed_view_type<'a> {
            type Owned = $signed_owned_type;

            fn to_owned(&self) -> Self::Owned {
                Self::Owned {
                    to_be_signed: self.to_be_signed.to_owned(),
                    to_be_signed_raw: self.to_be_signed_raw.try_into().unwrap(),
                    signature: self.signature.to_owned(),
                }
            }
        }
    };
}

// A macro to generate AEAD-encrypted data structures
macro_rules! mls_encrypted {
    ($ct_owned_type:ident + $ct_view_type:ident,
     $pt_owned_type:ident + $pt_view_type:ident,) => {
        mls_newtype_opaque! {
            $ct_owned_type + $ct_view_type,
            { $pt_owned_type::MAX_SIZE + crypto::AEAD_OVERHEAD }
        }

        impl $ct_owned_type {
            const MAX_CT_SIZE: usize = $pt_owned_type::MAX_SIZE + crypto::AEAD_OVERHEAD;

            fn seal(
                plaintext: $pt_owned_type,
                key: AeadKey,
                nonce: AeadNonce,
                aad: &[u8],
            ) -> Result<Self> {
                let pt = serialize!($pt_owned_type, plaintext);

                let mut ct = Vec::<u8, { Self::MAX_CT_SIZE }>::new();
                ct.resize_default(pt.len() + crypto::AEAD_OVERHEAD)
                    .map_err(|_| Error("Unexpected error"))?;
                let len = crypto::aead_seal(&mut ct, &pt, key, nonce, aad);
                ct.resize_default(len)
                    .map_err(|_| Error("Unexpected error"))?;

                Ok(Self(Opaque::from(ct)))
            }
        }

        impl<'a> $ct_view_type<'a> {
            fn open(
                &self,
                key: AeadKey,
                nonce: AeadNonce,
                aad: &[u8],
            ) -> Result<Vec<u8, { $pt_owned_type::MAX_SIZE }>> {
                let ct = self.0.as_ref();

                let mut pt = Vec::new();
                pt.resize_default(pt.capacity())
                    .map_err(|_| Error("Unexpected error"))?;
                let len = crypto::aead_open(&mut pt, &ct, key, nonce, aad)?;
                pt.resize(len, 0).map_err(|_| Error("Unexpected error"))?;

                Ok(pt)
            }
        }
    };
}

// A macro to generate HPKE-encrypted data structures, with a given AEAD-encrypted struct
macro_rules! mls_hpke_encrypted {
    ($hpke_owned_type:ident + $hpke_view_type:ident,
     $ct_owned_type:ident + $ct_view_type:ident,
     $pt_owned_type:ident + $pt_view_type:ident,) => {
        mls_struct! {
            $hpke_owned_type + $hpke_view_type,
            kem_output: HpkeKemOutput + HpkeKemOutputView,
            ciphertext: $ct_owned_type + $ct_view_type,
        }

        impl $hpke_owned_type {
            fn seal(
                plaintext: $pt_owned_type,
                encryption_key: HpkePublicKeyView,
                aad: &[u8],
            ) -> Result<Self> {
                let (kem_output, kem_secret) = crypto::hpke_encap(encryption_key);
                let (key, nonce) = crypto::hpke_key_nonce(kem_secret);

                let ciphertext = $ct_owned_type::seal(plaintext, key, nonce, aad)?;

                Ok(Self {
                    kem_output,
                    ciphertext,
                })
            }
        }

        impl<'a> $hpke_view_type<'a> {
            fn open(
                &self,
                encryption_priv: HpkePrivateKeyView,
                aad: &[u8],
            ) -> Result<Vec<u8, { $pt_owned_type::MAX_SIZE }>> {
                let kem_secret = crypto::hpke_decap(encryption_priv, self.kem_output);
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
        match self {
            None => writer.write(&[0]),
            Some(val) => writer.write(&[1]).and_then(|_| val.serialize(writer)),
        }
    }
}

impl<'a, V: Deserialize<'a>> Deserialize<'a> for Option<V> {
    fn deserialize(reader: &mut impl ReadRef<'a>) -> Result<Self> {
        let indicator = u8::deserialize(reader)?;
        match indicator {
            0 => Ok(None),
            1 => V::deserialize(reader).and_then(|val| Ok(Some(val))),
            _ => Err(Error("Invalid encoding")),
        }
    }
}

impl<T: AsView> AsView for Option<T> {
    type View<'a>
        = Option<T::View<'a>>
    where
        T: 'a;

    fn as_view<'a>(&'a self) -> Self::View<'a> {
        match self {
            None => None,
            Some(val) => Some(val.as_view()),
        }
    }
}

impl<V: ToOwned> ToOwned for Option<V> {
    type Owned = Option<V::Owned>;

    fn to_owned(&self) -> Self::Owned {
        match self {
            None => None,
            Some(val) => Some(val.to_owned()),
        }
    }
}

// Credentials
mls_newtype_opaque! {
    BasicCredential + BasicCredentialView,
    consts::MAX_CREDENTIAL_SIZE
}

mls_enum! {
    u16 => Credential + CredentialView,
    1 => Basic(BasicCredential + BasicCredentialView),
}

impl Default for Credential {
    fn default() -> Self {
        Self::Basic(BasicCredential::default())
    }
}

// Capabilities
mls_newtype_primitive! { ProtocolVersion + ProtocolVersionView => u16 }
mls_newtype_primitive! { ExtensionType + ExtensionTypeView => u16 }
mls_newtype_primitive! { ProposalType + ProposalTypeView => u16 }
mls_newtype_primitive! { CredentialType + CredentialTypeView => u16 }

type ProtocolVersionList = Vec<ProtocolVersion, { consts::MAX_PROTOCOL_VERSIONS }>;
type ProtocolVersionListView<'a> = Vec<ProtocolVersionView<'a>, { consts::MAX_PROTOCOL_VERSIONS }>;

type CipherSuiteList = Vec<CipherSuite, { consts::MAX_CIPHER_SUITES }>;
type CipherSuiteListView<'a> = Vec<CipherSuiteView<'a>, { consts::MAX_CIPHER_SUITES }>;

type ExtensionTypeList = Vec<ExtensionType, { consts::MAX_EXTENSION_TYPES }>;
type ExtensionTypeListView<'a> = Vec<ExtensionTypeView<'a>, { consts::MAX_EXTENSION_TYPES }>;

type ProposalTypeList = Vec<ProposalType, { consts::MAX_PROPOSAL_TYPES }>;
type ProposalTypeListView<'a> = Vec<ProposalTypeView<'a>, { consts::MAX_PROPOSAL_TYPES }>;

type CredentialTypeList = Vec<CredentialType, { consts::MAX_CREDENTIAL_TYPES }>;
type CredentialTypeListView<'a> = Vec<CredentialTypeView<'a>, { consts::MAX_CREDENTIAL_TYPES }>;

mls_struct! {
    Capabilities + CapabilitiesView,
    versions: ProtocolVersionList + ProtocolVersionListView,
    cipher_suites: CipherSuiteList + CipherSuiteListView,
    extensions: ExtensionTypeList + ExtensionTypeListView,
    proposals: ProposalTypeList + ProposalTypeListView,
    credentials: CredentialTypeList + CredentialTypeListView,
}

// Leaf node source
mls_newtype_primitive! { Timestamp + TimestampView => u64 }

mls_struct! {
    Lifetime + LifetimeView,
    not_before: Timestamp + TimestampView,
    not_after: Timestamp + TimestampView,
}

mls_enum! {
    u8 => LeafNodeSource + LeafNodeSourceView,
    1 => KeyPackage(Lifetime + LifetimeView),
    2 => Update(Nil + NilView),
    3 => Commit(HashOutput + HashOutputView),
}

impl Default for LeafNodeSource {
    fn default() -> Self {
        let infinite_lifetime = Lifetime {
            not_before: Timestamp(0),
            not_after: Timestamp(u64::MAX),
        };
        Self::KeyPackage(infinite_lifetime)
    }
}

// Extensions
mls_newtype_opaque! {
    ExtensionData + ExtensionDataView,
    consts::MAX_EXTENSION_SIZE
}

mls_struct! {
    Extension + ExtensionView,
    extension_type: ExtensionType + ExtensionTypeView,
    extension_data: ExtensionData + ExtensionDataView,
}

type ExtensionList = Vec<Extension, { consts::MAX_EXTENSIONS }>;
type ExtensionListView<'a> = Vec<ExtensionView<'a>, { consts::MAX_EXTENSIONS }>;

// LeafNode
mls_struct! {
    LeafNodeTbs + LeafNodeTbsView,
    encryption_key: HpkePublicKey + HpkePublicKeyView,
    signature_key: SignaturePublicKey + SignaturePublicKeyView,
    credential: Credential + CredentialView,
    capabilities: Capabilities + CapabilitiesView,
    leaf_node_source: LeafNodeSource + LeafNodeSourceView,
    extensions: ExtensionList + ExtensionListView,
}

mls_struct! {
    LeafNodePriv + LeafNodePrivView,
    encryption_priv: HpkePrivateKey + HpkePrivateKeyView,
    signature_priv: SignaturePrivateKey + SignaturePrivateKeyView,
}

mls_signed! { LeafNode + LeafNodeView + b"LeafNodeTBS" => LeafNodeTbs + LeafNodeTbsView }

// KeyPackage
mls_struct! {
    KeyPackageTbs + KeyPackageTbsView,
    protocol_version: ProtocolVersion + ProtocolVersionView,
    cipher_suite: CipherSuite + CipherSuiteView,
    init_key: HpkePublicKey + HpkePublicKeyView,
    leaf_node: LeafNode + LeafNodeView,
    extensions: ExtensionList + ExtensionListView,
}

mls_struct! {
    KeyPackagePriv + KeyPackagePrivView,
    init_priv: HpkePrivateKey + HpkePrivateKeyView,
    leaf_node_priv: LeafNodePriv + LeafNodePrivView,
}

mls_signed! { KeyPackage + KeyPackageView + b"KeyPackageTBS" => KeyPackageTbs + KeyPackageTbsView }

// GroupInfo
mls_newtype_opaque! {
    GroupId + GroupIdView,
    consts::MAX_GROUP_ID_SIZE
}

mls_newtype_primitive! { Epoch + EpochView => u64 }

mls_struct! {
    GroupContext + GroupContextView,
    version: ProtocolVersion + ProtocolVersionView,
    group_id: GroupId + GroupIdView,
    epoch: Epoch + EpochView,
    tree_hash: HashOutput + HashOutputView,
    confirmed_transcript_hash: HashOutput + HashOutputView,
    extensions: ExtensionList + ExtensionListView,
}

mls_newtype_primitive! { LeafIndex + LeafIndexView => u32 }

mls_struct! {
    GroupInfoTbs + GroupInfoTbsView,
    group_context: GroupContext + GroupContextView,
    extensions: ExtensionList + ExtensionListView,
    confirmation_tag: HashOutput + HashOutputView,
    signer: LeafIndex + LeafIndexView,
}

mls_signed! { GroupInfo + GroupInfoView + b"GroupInfoTBS" => GroupInfoTbs + GroupInfoTbsView }

// Welcome

type OptionalPathSecret = Option<HashOutput>;
type OptionalPathSecretView<'a> = Option<HashOutputView<'a>>;

// XXX(RLB) These are stubs for now because we don't support PSKs; the `psks` vector must always
// have length zero.
type PreSharedKeyIDList = Vec<Nil, { consts::MAX_WELCOME_PSKS }>;
type PreSharedKeyIDListView<'a> = Vec<NilView<'a>, { consts::MAX_WELCOME_PSKS }>;

mls_struct! {
    GroupSecrets + GroupSecretsView,
    joiner_secret: HashOutput + HashOutputView,
    path_secret: OptionalPathSecret + OptionalPathSecretView,
    psks: PreSharedKeyIDList + PreSharedKeyIDListView,
}

mls_encrypted! {
    AeadEncryptedGroupSecrets + AeadEncryptedGroupSecretsView,
    GroupSecrets + GroupSecretsView,
}

mls_hpke_encrypted! {
    HpkeEncryptedGroupSecrets + HpkeEncryptedGroupSecretsView,
    AeadEncryptedGroupSecrets + AeadEncryptedGroupSecretsView,
    GroupSecrets + GroupSecretsView,
}

mls_struct! {
    EncryptedGroupSecrets + EncryptedGroupSecretsView,
    new_member: HashOutput + HashOutputView,
    encrypted_group_secrets: HpkeEncryptedGroupSecrets + HpkeEncryptedGroupSecretsView,
}

type EncryptedGroupSecretsList = Vec<EncryptedGroupSecrets, { consts::MAX_JOINERS_PER_WELCOME }>;
type EncryptedGroupSecretsListView<'a> =
    Vec<EncryptedGroupSecretsView<'a>, { consts::MAX_JOINERS_PER_WELCOME }>;

mls_encrypted! {
    EncryptedGroupInfo + EncryptedGroupInfoView,
    GroupInfo + GroupInfoView,
}

mls_struct! {
    Welcome + WelcomeView,
    cipher_suite: CipherSuite + CipherSuiteView,
    secrets: EncryptedGroupSecretsList + EncryptedGroupSecretsListView,
    encrypted_group_info: EncryptedGroupInfo + EncryptedGroupInfoView,
}

// PrivateMessage
mls_encrypted! {
    EncryptedPathSecret + EncryptedPathSecretView,
    HashOutput + HashOutputView,
}

mls_struct! {
    UpdatePathNode + UpdatePathNodeView,
    encryption_key: HpkePublicKey + HpkePublicKeyView,
    encrypted_path_secret: EncryptedPathSecret + EncryptedPathSecretView,
}

type UpdatePathNodeList = Vec<UpdatePathNode, { consts::MAX_PROPOSALS_PER_COMMIT }>;
type UpdatePathNodeListView<'a> = Vec<UpdatePathNodeView<'a>, { consts::MAX_PROPOSALS_PER_COMMIT }>;

mls_struct! {
    UpdatePath + UpdatePathView,
    leaf_node: LeafNode + LeafNodeView,
    nodes: UpdatePathNodeList + UpdatePathNodeListView,
}

mls_struct! {
    Add + AddView,
    key_package: KeyPackage + KeyPackageView,
}

mls_struct! {
    Remove + RemoveView,
    removed: LeafIndex + LeafIndexView,
}

mls_enum! {
    u16 => Proposal + ProposalView,
    1 => Add(Add + AddView),
    3 => Remove(Remove + RemoveView),
}

mls_enum! {
    u8 => ProposalOrRef + ProposalOrRefView,
    1 => Proposal(Proposal + ProposalView),
}

type OptionalUpdatePath = Option<UpdatePath>;
type OptionalUpdatePathView<'a> = Option<UpdatePathView<'a>>;

type ProposalList = Vec<ProposalOrRef, { consts::MAX_PROPOSALS_PER_COMMIT }>;
type ProposalListView<'a> = Vec<ProposalOrRefView<'a>, { consts::MAX_PROPOSALS_PER_COMMIT }>;

mls_struct! {
    Commit + CommitView,
    proposals: ProposalList + ProposalListView,
    path: OptionalUpdatePath + OptionalUpdatePathView,
}

mls_enum! {
    u8 => Sender + SenderView,
    1 => Member(LeafIndex + LeafIndexView),
}

impl Default for Sender {
    fn default() -> Self {
        Self::Member(LeafIndex(0))
    }
}

mls_enum! {
    u8 => MessageContent + MessageContentView,
    3 => Commit(Commit + CommitView),
}

impl Default for MessageContent {
    fn default() -> Self {
        Self::Commit(Commit::default())
    }
}

mls_newtype_opaque! {
    PrivateMessageAad + PrivateMessageAadView,
    consts::MAX_PRIVATE_MESSAGE_AAD_SIZE
}

mls_struct! {
    FramedContent + FramedContentView,
    group_id: GroupId + GroupIdView,
    epoch: Epoch + EpochView,
    sender: Sender + SenderView,
    authenticated_data: PrivateMessageAad + PrivateMessageAadView,
    content: MessageContent + MessageContentView,
}

mls_newtype_primitive! { WireFormat + WireFormatView => u16 }

mls_enum! {
    u8 => FramedContentBinder + FramedContentBinderView,
    1 => Member(GroupContext + GroupContextView),
}

impl Default for FramedContentBinder {
    fn default() -> Self {
        Self::Member(GroupContext::default())
    }
}

mls_struct! {
    FramedContentTbs + FramedContentTbsView,
    version: ProtocolVersion + ProtocolVersionView,
    wire_format: WireFormat + WireFormatView,
    content: FramedContent + FramedContentView,
    binder: FramedContentBinder + FramedContentBinderView,
}

mls_signed! {
    SignedFramedContent + SignedFramedContentView + b"FramedContentTBS"
    => FramedContentTbs + FramedContentTbsView
}

mls_newtype_primitive! { Generation + GenerationView => u32 }
mls_newtype_primitive! { ReuseGuard + ReuseGuardView => u32 }

struct SenderDataAad<'a> {
    group_id: GroupIdView<'a>,
    epoch: Epoch,
    content_type: ContentType,
}

impl<'a> Serialize for SenderDataAad<'a> {
    const MAX_SIZE: usize = sum(&[GroupId::MAX_SIZE, Epoch::MAX_SIZE, ContentType::MAX_SIZE]);

    fn serialize(&self, writer: &mut impl Write) -> Result<()> {
        self.group_id.serialize(writer)?;
        self.epoch.serialize(writer)?;
        self.content_type.serialize(writer)?;
        Ok(())
    }
}

mls_struct! {
    SenderData + SenderDataView,
    leaf_index: LeafIndex + LeafIndexView,
    generation: Generation + GenerationView,
    reuse_guard: ReuseGuard + ReuseGuardView,
}

mls_encrypted! {
    EncryptedSenderData + EncryptedSenderDataView,
    SenderData + SenderDataView,
}

struct PrivateMessageContentAad<'a> {
    group_id: GroupIdView<'a>,
    epoch: Epoch,
    content_type: ContentType,
    authenticated_data: PrivateMessageAadView<'a>,
}

impl<'a> Serialize for PrivateMessageContentAad<'a> {
    const MAX_SIZE: usize = sum(&[
        GroupId::MAX_SIZE,
        Epoch::MAX_SIZE,
        ContentType::MAX_SIZE,
        PrivateMessageAad::MAX_SIZE,
    ]);

    fn serialize(&self, writer: &mut impl Write) -> Result<()> {
        self.group_id.serialize(writer)?;
        self.epoch.serialize(writer)?;
        self.content_type.serialize(writer)?;
        self.authenticated_data.serialize(writer)?;
        Ok(())
    }
}

mls_struct! {
    PrivateMessageContent + PrivateMessageContentView,
    commit: Commit + CommitView,
    // XXX(RLB) Destructured FramedContentAuthData
    signature: Signature + SignatureView,
    confirmation_tag: HashOutput + HashOutputView,
    // XXX(RLB) No padding
}

mls_encrypted! {
    EncryptedPrivateMessageContent + EncryptedPrivateMessageContentView,
    PrivateMessageContent + PrivateMessageContentView,
}

mls_newtype_primitive! { ContentType + ContentTypeView => u8 }

const CONTENT_TYPE_COMMIT: ContentType = ContentType(3);

mls_struct! {
    PrivateMessage + PrivateMessageView,
    group_id: GroupId + GroupIdView,
    epoch: Epoch + EpochView,
    content_type: ContentType + ContentTypeView,
    authenticated_data: PrivateMessageAad + PrivateMessageAadView,
    encrypted_sender_data: EncryptedSenderData + EncryptedSenderDataView,
    ciphertext: EncryptedPrivateMessageContent + EncryptedPrivateMessageContentView,
}

impl PrivateMessage {
    fn new(
        signed_framed_content: SignedFramedContent,
        confirmation_tag: HashOutput,
        sender_data: SenderData,
        key: AeadKey,
        nonce: AeadNonce,
        sender_data_secret: HashOutputView,
        authenticated_data: PrivateMessageAad,
    ) -> Result<Self> {
        // Form payload
        let MessageContent::Commit(commit) = signed_framed_content.to_be_signed.content.content;
        let signature = signed_framed_content.signature;
        let plaintext = PrivateMessageContent {
            commit,
            signature,
            confirmation_tag,
        };

        // Encrypt payload
        let group_id = signed_framed_content.to_be_signed.content.group_id;
        let epoch = signed_framed_content.to_be_signed.content.epoch;
        let aad = serialize!(
            PrivateMessageContentAad,
            PrivateMessageContentAad {
                group_id: group_id.as_view(),
                epoch,
                content_type: CONTENT_TYPE_COMMIT,
                authenticated_data: authenticated_data.as_view(),
            }
        );

        let ciphertext = EncryptedPrivateMessageContent::seal(plaintext, key, nonce, &aad)?;

        // Encrypt sender data
        let (key, nonce) = crypto::sender_data_key_nonce(sender_data_secret, ciphertext.as_ref());
        let aad = serialize!(
            SenderDataAad,
            SenderDataAad {
                group_id: group_id.as_view(),
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
}

impl<'a> PrivateMessageView<'a> {
    fn open(
        &self,
        sender_data_secret: HashOutputView,
        sender_key_source: &impl SenderKeySource,
        group_context: GroupContext,
    ) -> Result<(SignedFramedContent, HashOutput)> {
        // Check outer properties are correct
        if self.group_id != group_context.group_id.as_view() {
            return Err(Error("Wrong group"));
        }

        if self.epoch != group_context.epoch.as_view() {
            return Err(Error("Wrong epoch"));
        }

        // Decrypt sender data
        let (key, nonce) =
            crypto::sender_data_key_nonce(sender_data_secret, self.ciphertext.as_ref());
        let aad = serialize!(
            SenderDataAad,
            SenderDataAad {
                group_id: self.group_id,
                epoch: self.epoch.to_owned(),
                content_type: CONTENT_TYPE_COMMIT,
            }
        );

        let sender_data_data = self.encrypted_sender_data.open(key, nonce, &aad)?;
        let mut sender_data_reader = SliceReader::new(&sender_data_data);
        let sender_data = SenderDataView::deserialize(&mut sender_data_reader)?;

        // Look up keys for the sender and generation
        let leaf_index = sender_data.leaf_index.to_owned();
        let generation = sender_data.generation.to_owned();
        let (key, nonce) = sender_key_source
            .find_keys(leaf_index, generation)
            .ok_or(Error("Unknown sender"))?;

        // Decrypt content
        let aad = serialize!(
            PrivateMessageContentAad,
            PrivateMessageContentAad {
                group_id: self.group_id,
                epoch: self.epoch.to_owned(),
                content_type: CONTENT_TYPE_COMMIT,
                authenticated_data: self.authenticated_data,
            }
        );

        let plaintext_data = self.ciphertext.open(key, nonce, &aad)?;
        let mut plaintext_reader = SliceReader::new(&plaintext_data);
        let content = PrivateMessageContentView::deserialize(&mut plaintext_reader)?;

        // Construct objects to return
        let to_be_signed = FramedContentTbs {
            version: consts::SUPPORTED_VERSION,
            wire_format: consts::SUPPORTED_WIRE_FORMAT,
            content: FramedContent {
                group_id: self.group_id.to_owned(),
                epoch: self.epoch.to_owned(),
                sender: Sender::Member(leaf_index),
                authenticated_data: self.authenticated_data.to_owned(),
                content: MessageContent::Commit(content.commit.to_owned()),
            },
            binder: FramedContentBinder::Member(group_context),
        };
        let to_be_signed_raw = serialize!(FramedContentTbs, to_be_signed);

        let signed_framed_content = SignedFramedContent {
            to_be_signed,
            to_be_signed_raw,
            signature: content.signature.to_owned(),
        };
        let confirmation_hash = content.confirmation_tag.to_owned();

        todo!();
    }
}

trait SenderKeySource {
    fn find_keys<'a>(
        &self,
        sender: LeafIndex,
        generation: Generation,
    ) -> Option<(AeadKey, AeadNonce)>;
}

// SignedFramedContent::new(...)
//
// // Update transcript
//
// (SignedFramedContent, confirmation_tag, key, nonce, sender_data_secret)
// -> PrivateMessage
//
// =====
//
//

// * Form FramedContent
// * Sign FramedContent
// * Update transcript hash => confirmation_tag
//
// * Form payload
// * Encrypt payload
//
// * Form sender data
// * Encrypt sender data with SenderDataAAD

// TODO(RLB): Keep building toward PrivateMessage

// TODO(RLB): Stub structs below this line

mls_struct! {
    Dummy + DummyView,
    dummy: Nil + NilView,
}

pub type GroupState = Dummy;
pub type GroupStateView<'a> = DummyView<'a>;

#[cfg(test)]
mod test {
    use super::*;
    use crate::io::SliceReader;
    use crate::make_storage;

    macro_rules! test_sign_verify {
        ($signed_owned_type:ident, $signed_view_type:ident, $tbs_owned_type:ident) => {
            let rng = &mut rand::thread_rng();
            let (signature_priv, signature_key) = crypto::generate_sig(rng).unwrap();
            let tbs = $tbs_owned_type::default();
            let signed = $signed_owned_type::new(tbs, signature_priv.as_view()).unwrap();

            let mut storage = make_storage!($signed_owned_type);
            signed.serialize(&mut storage).unwrap();

            let mut reader = SliceReader::new(&storage);
            let view = $signed_view_type::deserialize(&mut reader).unwrap();

            let ver = view.verify(signature_key.as_view()).unwrap();
            assert!(ver);
        };
    }

    #[test]
    fn signed_objects() {
        test_sign_verify!(LeafNode, LeafNodeView, LeafNodeTbs);
        test_sign_verify!(KeyPackage, KeyPackageView, KeyPackageTbs);
        test_sign_verify!(GroupInfo, GroupInfoView, GroupInfoTbs);
    }
}
