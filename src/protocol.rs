use crate::common::*;
use crate::crypto::{self, *};
use crate::io::*;
use crate::syntax::*;
use crate::{mls_enum, mls_newtype_opaque, mls_newtype_primitive, mls_struct};

use core::marker::PhantomData;
use core::ops::{Deref, DerefMut};
use heapless::Vec;
use rand_core::CryptoRngCore;

mod consts {
    use super::{CredentialType, ProtocolVersion};

    pub const SUPPORTED_VERSION: ProtocolVersion = ProtocolVersion(0x0001); // mls10
    pub const SUPPORTED_CREDENTIAL_TYPE: CredentialType = CredentialType(0x0001); // basic

    pub const MAX_CREDENTIAL_SIZE: usize = 128;
    pub const MAX_PROTOCOL_VERSIONS: usize = 1;
    pub const MAX_CIPHER_SUITES: usize = 1;
    pub const MAX_EXTENSION_TYPES: usize = 0;
    pub const MAX_PROPOSAL_TYPES: usize = 0;
    pub const MAX_CREDENTIAL_TYPES: usize = 1;
    pub const MAX_EXTENSION_SIZE: usize = 128;
    pub const MAX_EXTENSIONS: usize = 0;
    pub const MAX_GROUP_ID_SIZE: usize = 16;
}

// Credentials
mls_newtype_opaque! {
    BasicCredential + BasicCredentialView,
    BasicCredentialData + BasicCredentialViewData,
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
    ExtensionDataData + ExtensionDataViewData,
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

#[derive(Clone, Default, Debug, PartialEq)]
struct LeafNode {
    to_be_signed: LeafNodeTbs,
    to_be_signed_raw: Vec<u8, { Self::MAX_SIZE }>,
    signature: Signature,
}

#[derive(Clone, Debug, PartialEq)]
struct LeafNodeView<'a> {
    to_be_signed: LeafNodeTbsView<'a>,
    to_be_signed_raw: &'a [u8],
    signature: SignatureView<'a>,
}

impl LeafNode {
    const SIGNATURE_LABEL: &[u8] = b"LeafNodeTBS";

    fn new(
        rng: &mut impl CryptoRngCore,
        leaf_node_source: LeafNodeSource,
        signature_priv: SignaturePrivateKey,
        signature_key: SignaturePublicKey,
        credential: Credential,
    ) -> Result<(LeafNodePriv, LeafNode)> {
        // Construct the TBS object
        let mut capabilities = Capabilities::default();
        capabilities
            .versions
            .push(consts::SUPPORTED_VERSION)
            .map_err(|_| Error("Too many items"))?;
        capabilities
            .cipher_suites
            .push(crypto::CIPHER_SUITE)
            .map_err(|_| Error("Too many items"))?;
        capabilities
            .credentials
            .push(consts::SUPPORTED_CREDENTIAL_TYPE)
            .map_err(|_| Error("Too many items"))?;

        let (encryption_priv, encryption_key) = crypto::generate_hpke(rng)?;

        let to_be_signed = LeafNodeTbs {
            encryption_key,
            signature_key,
            credential,
            leaf_node_source,
            ..Default::default()
        };

        // Serialize the part to be signed
        let mut to_be_signed_raw = Vec::new();
        to_be_signed.serialize(&mut to_be_signed_raw)?;

        // Populate the signature
        let signature = crypto::sign_with_label(
            &to_be_signed_raw,
            Self::SIGNATURE_LABEL,
            signature_priv.as_view(),
        )?;

        let leaf_node_priv = LeafNodePriv {
            encryption_priv,
            signature_priv,
        };
        let leaf_node = LeafNode {
            to_be_signed,
            to_be_signed_raw,
            signature,
        };
        Ok((leaf_node_priv, leaf_node))
    }
}

impl<'a> LeafNodeView<'a> {
    fn verify(&self) -> Result<bool> {
        crypto::verify_with_label(
            self.to_be_signed_raw.as_ref(),
            LeafNode::SIGNATURE_LABEL,
            self.to_be_signed.signature_key.clone(),
            self.signature.clone(),
        )
    }
}

impl Serialize for LeafNode {
    const MAX_SIZE: usize = sum(&[LeafNodeTbs::MAX_SIZE, Signature::MAX_SIZE]);

    fn serialize(&self, writer: &mut impl Write) -> Result<()> {
        self.to_be_signed.serialize(writer)?;
        self.signature.serialize(writer)?;
        Ok(())
    }
}

impl<'a> Deserialize<'a> for LeafNodeView<'a> {
    fn deserialize(reader: &mut impl ReadRef<'a>) -> Result<Self> {
        let mut sub_reader = reader.fork();

        let to_be_signed = LeafNodeTbsView::deserialize(&mut sub_reader)?;
        let to_be_signed_raw = reader.read_ref(sub_reader.position())?;
        let signature = SignatureView::deserialize(reader)?;

        Ok(Self {
            to_be_signed,
            to_be_signed_raw,
            signature,
        })
    }
}

impl AsView for LeafNode {
    type View<'a> = LeafNodeView<'a>;

    fn as_view<'a>(&'a self) -> Self::View<'a> {
        Self::View {
            to_be_signed: self.to_be_signed.as_view(),
            to_be_signed_raw: &self.to_be_signed_raw,
            signature: self.signature.as_view(),
        }
    }
}

impl<'a> ToOwned for LeafNodeView<'a> {
    type Owned = LeafNode;

    fn to_owned(&self) -> Self::Owned {
        Self::Owned {
            to_be_signed: self.to_be_signed.to_owned(),
            to_be_signed_raw: self.to_be_signed_raw.try_into().unwrap(),
            signature: self.signature.to_owned(),
        }
    }
}

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

#[derive(Clone, Default, Debug, PartialEq)]
pub struct KeyPackage {
    to_be_signed: KeyPackageTbs,
    to_be_signed_raw: Vec<u8, { Self::MAX_SIZE }>,
    signature: Signature,
}

#[derive(Clone, Debug, PartialEq)]
pub struct KeyPackageView<'a> {
    to_be_signed: KeyPackageTbsView<'a>,
    to_be_signed_raw: &'a [u8],
    signature: SignatureView<'a>,
}

impl KeyPackage {
    const SIGNATURE_LABEL: &[u8] = b"KeyPackageTBS";

    fn new(
        rng: &mut impl CryptoRngCore,
        signature_priv: SignaturePrivateKey,
        signature_key: SignaturePublicKey,
        credential: Credential,
    ) -> Result<(KeyPackagePriv, KeyPackage)> {
        // Create the KeyPackageTbs
        let (init_priv, init_key) = crypto::generate_hpke(rng)?;

        let (leaf_node_priv, leaf_node) = LeafNode::new(
            rng,
            LeafNodeSource::KeyPackage(Lifetime::default()),
            signature_priv.clone(),
            signature_key,
            credential,
        )?;

        let to_be_signed = KeyPackageTbs {
            protocol_version: consts::SUPPORTED_VERSION,
            cipher_suite: crypto::CIPHER_SUITE,
            init_key,
            leaf_node,
            ..Default::default()
        };

        // Serialize the part to be signed
        let mut to_be_signed_raw = Vec::new();
        to_be_signed.serialize(&mut to_be_signed_raw)?;

        // Populate the signature
        let signature = crypto::sign_with_label(
            &to_be_signed_raw,
            Self::SIGNATURE_LABEL,
            signature_priv.as_view(),
        )?;

        let key_package_priv = KeyPackagePriv {
            init_priv,
            leaf_node_priv,
        };
        let key_package = KeyPackage {
            to_be_signed,
            to_be_signed_raw,
            signature,
        };
        Ok((key_package_priv, key_package))
    }
}

impl<'a> KeyPackageView<'a> {
    fn verify(&self) -> Result<bool> {
        crypto::verify_with_label(
            self.to_be_signed_raw.as_ref(),
            KeyPackage::SIGNATURE_LABEL,
            self.to_be_signed
                .leaf_node
                .to_be_signed
                .signature_key
                .clone(),
            self.signature.clone(),
        )
    }
}

impl Serialize for KeyPackage {
    const MAX_SIZE: usize = sum(&[KeyPackageTbs::MAX_SIZE, Signature::MAX_SIZE]);

    fn serialize(&self, writer: &mut impl Write) -> Result<()> {
        self.to_be_signed.serialize(writer)?;
        self.signature.serialize(writer)?;
        Ok(())
    }
}

impl<'a> Deserialize<'a> for KeyPackageView<'a> {
    fn deserialize(reader: &mut impl ReadRef<'a>) -> Result<Self> {
        let mut sub_reader = reader.fork();

        let to_be_signed = KeyPackageTbsView::deserialize(&mut sub_reader)?;
        let to_be_signed_raw = reader.read_ref(sub_reader.position())?;
        let signature = SignatureView::deserialize(reader)?;

        Ok(Self {
            to_be_signed,
            to_be_signed_raw,
            signature,
        })
    }
}

impl AsView for KeyPackage {
    type View<'a> = KeyPackageView<'a>;

    fn as_view<'a>(&'a self) -> Self::View<'a> {
        Self::View {
            to_be_signed: self.to_be_signed.as_view(),
            to_be_signed_raw: &self.to_be_signed_raw,
            signature: self.signature.as_view(),
        }
    }
}

impl<'a> ToOwned for KeyPackageView<'a> {
    type Owned = KeyPackage;

    fn to_owned(&self) -> Self::Owned {
        Self::Owned {
            to_be_signed: self.to_be_signed.to_owned(),
            to_be_signed_raw: self.to_be_signed_raw.try_into().unwrap(),
            signature: self.signature.to_owned(),
        }
    }
}

// GroupInfo
mls_newtype_opaque! {
    GroupId + GroupIdView,
    GroupIdData + GroupIdViewData,
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

#[derive(Clone, Default, Debug, PartialEq)]
struct GroupInfo {
    to_be_signed: GroupInfoTbs,
    to_be_signed_raw: Vec<u8, { Self::MAX_SIZE }>,
    signature: Signature,
}

#[derive(Clone, Debug, PartialEq)]
struct GroupInfoView<'a> {
    to_be_signed: GroupInfoTbsView<'a>,
    to_be_signed_raw: &'a [u8],
    signature: SignatureView<'a>,
}

impl GroupInfo {
    const SIGNATURE_LABEL: &[u8] = b"GroupInfoTBS";

    fn new(
        to_be_signed: GroupInfoTbs,
        signature_priv: SignaturePrivateKeyView,
    ) -> Result<GroupInfo> {
        // Serialize the part to be signed
        let mut to_be_signed_raw = Vec::new();
        to_be_signed.serialize(&mut to_be_signed_raw)?;

        // Populate the signature
        let signature =
            crypto::sign_with_label(&to_be_signed_raw, Self::SIGNATURE_LABEL, signature_priv)?;

        let group_info = GroupInfo {
            to_be_signed,
            to_be_signed_raw,
            signature,
        };
        Ok(group_info)
    }
}

impl<'a> GroupInfoView<'a> {
    fn verify(&self, signature_key: SignaturePublicKeyView) -> Result<bool> {
        crypto::verify_with_label(
            self.to_be_signed_raw.as_ref(),
            GroupInfo::SIGNATURE_LABEL,
            signature_key,
            self.signature.clone(),
        )
    }
}

impl Serialize for GroupInfo {
    const MAX_SIZE: usize = sum(&[GroupInfoTbs::MAX_SIZE, Signature::MAX_SIZE]);

    fn serialize(&self, writer: &mut impl Write) -> Result<()> {
        self.to_be_signed.serialize(writer)?;
        self.signature.serialize(writer)?;
        Ok(())
    }
}

impl<'a> Deserialize<'a> for GroupInfoView<'a> {
    fn deserialize(reader: &mut impl ReadRef<'a>) -> Result<Self> {
        let mut sub_reader = reader.fork();

        let to_be_signed = GroupInfoTbsView::deserialize(&mut sub_reader)?;
        let to_be_signed_raw = reader.read_ref(sub_reader.position())?;
        let signature = SignatureView::deserialize(reader)?;

        Ok(Self {
            to_be_signed,
            to_be_signed_raw,
            signature,
        })
    }
}

impl AsView for GroupInfo {
    type View<'a> = GroupInfoView<'a>;

    fn as_view<'a>(&'a self) -> Self::View<'a> {
        Self::View {
            to_be_signed: self.to_be_signed.as_view(),
            to_be_signed_raw: &self.to_be_signed_raw,
            signature: self.signature.as_view(),
        }
    }
}

impl<'a> ToOwned for GroupInfoView<'a> {
    type Owned = GroupInfo;

    fn to_owned(&self) -> Self::Owned {
        Self::Owned {
            to_be_signed: self.to_be_signed.to_owned(),
            to_be_signed_raw: self.to_be_signed_raw.try_into().unwrap(),
            signature: self.signature.to_owned(),
        }
    }
}

// TODO(RLB): Stub structs below this line

mls_struct! {
    Dummy + DummyView,
    dummy: Nil + NilView,
}

pub type Welcome = Dummy;
pub type WelcomeView<'a> = DummyView<'a>;

pub type GroupState = Dummy;
pub type GroupStateView<'a> = DummyView<'a>;

pub type PrivateMessage = Dummy;
pub type PrivateMessageView<'a> = DummyView<'a>;

#[cfg(test)]
mod test {
    use super::*;
    use crate::io::SliceReader;
    use crate::make_storage;

    #[test]
    fn leaf_node_sign_verify() {
        let rng = &mut rand::thread_rng();

        let (signature_priv, signature_key) = crypto::generate_sig(rng).unwrap();
        let credential = Credential::default();

        let (_leaf_node_priv, leaf_node) = LeafNode::new(
            rng,
            LeafNodeSource::default(),
            signature_priv,
            signature_key,
            credential,
        )
        .unwrap();

        let mut storage = make_storage!(LeafNode);
        leaf_node.serialize(&mut storage).unwrap();

        let mut reader = SliceReader::new(&storage);
        let leaf_node_view = LeafNodeView::deserialize(&mut reader).unwrap();

        let ver = leaf_node_view.verify().unwrap();
        assert!(ver);
    }

    #[test]
    fn key_package_sign_verify() {
        let rng = &mut rand::thread_rng();

        let (signature_priv, signature_key) = crypto::generate_sig(rng).unwrap();
        let credential = Credential::default();

        let (_key_package_priv, key_package) =
            KeyPackage::new(rng, signature_priv, signature_key, credential).unwrap();

        let mut storage = make_storage!(KeyPackage);
        key_package.serialize(&mut storage).unwrap();

        let mut reader = SliceReader::new(&storage);
        let key_package_view = KeyPackageView::deserialize(&mut reader).unwrap();

        let ver = key_package_view.verify().unwrap();
        assert!(ver);
    }

    #[test]
    fn group_info_sign_verify() {
        let rng = &mut rand::thread_rng();

        let (signature_priv, signature_key) = crypto::generate_sig(rng).unwrap();

        let to_be_signed = GroupInfoTbs::default();

        let group_info = GroupInfo::new(to_be_signed, signature_priv.as_view()).unwrap();

        let mut storage = make_storage!(GroupInfo);
        group_info.serialize(&mut storage).unwrap();

        let mut reader = SliceReader::new(&storage);
        let group_info_view = GroupInfoView::deserialize(&mut reader).unwrap();

        let ver = group_info_view.verify(signature_key.as_view()).unwrap();
        assert!(ver);
    }
}
