use crate::common::*;
use crate::crypto::*;
use crate::io::*;
use crate::syntax::*;
use crate::{mls_enum, mls_newtype, mls_newtype_opaque, mls_struct};

use core::ops::Deref;

mod consts {
    pub const MAX_CREDENTIAL_SIZE: usize = 128;
    pub const MAX_PROTOCOL_VERSIONS: usize = 1;
    pub const MAX_CIPHER_SUITES: usize = 1;
    pub const MAX_EXTENSION_TYPES: usize = 0;
    pub const MAX_PROPOSAL_TYPES: usize = 0;
    pub const MAX_CREDENTIAL_TYPES: usize = 1;
    pub const MAX_EXTENSION_SIZE: usize = 128;
    pub const MAX_EXTENSIONS: usize = 0;
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
mls_newtype! { ProtocolVersion + ProtocolVersionView => U16 + U16View }
mls_newtype! { CipherSuite + CipherSuiteView => U16 + U16View }
mls_newtype! { ExtensionType + ExtensionTypeView => U16 + U16View }
mls_newtype! { ProposalType + ProposalTypeView => U16 + U16View }
mls_newtype! { CredentialType + CredentialTypeView => U16 + U16View }

type ProtocolVersionList = Vector<ProtocolVersion, { consts::MAX_PROTOCOL_VERSIONS }>;
type ProtocolVersionListView<'a> =
    VectorView<'a, ProtocolVersionView<'a>, { consts::MAX_PROTOCOL_VERSIONS }>;

type CipherSuiteList = Vector<CipherSuite, { consts::MAX_CIPHER_SUITES }>;
type CipherSuiteListView<'a> = VectorView<'a, CipherSuiteView<'a>, { consts::MAX_CIPHER_SUITES }>;

type ExtensionTypeList = Vector<ExtensionType, { consts::MAX_EXTENSION_TYPES }>;
type ExtensionTypeListView<'a> =
    VectorView<'a, ExtensionTypeView<'a>, { consts::MAX_EXTENSION_TYPES }>;

type ProposalTypeList = Vector<ProposalType, { consts::MAX_PROPOSAL_TYPES }>;
type ProposalTypeListView<'a> =
    VectorView<'a, ProposalTypeView<'a>, { consts::MAX_PROPOSAL_TYPES }>;

type CredentialTypeList = Vector<CredentialType, { consts::MAX_CREDENTIAL_TYPES }>;
type CredentialTypeListView<'a> =
    VectorView<'a, CredentialTypeView<'a>, { consts::MAX_CREDENTIAL_TYPES }>;

mls_struct! {
    Capabilities + CapabilitiesView,
    versions: ProtocolVersionList + ProtocolVersionListView,
    cipher_suites: CipherSuiteList + CipherSuiteListView,
    extensions: ExtensionTypeList + ExtensionTypeListView,
    proposals: ProposalTypeList + ProposalTypeListView,
    credentials: CredentialTypeList + CredentialTypeListView,
}

// Leaf node source
mls_struct! {
    Lifetime + LifetimeView,
    not_before: U64 + U64View,
    not_after: U64 + U64View,
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
            not_before: U64::from(0),
            not_after: U64::from(u64::MAX),
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

type ExtensionListData = Vector<Extension, { consts::MAX_EXTENSIONS }>;
type ExtensionListDataView<'a> = VectorView<'a, ExtensionView<'a>, { consts::MAX_EXTENSIONS }>;

mls_newtype! { ExtensionList + ExtensionListView => ExtensionListData + ExtensionListDataView }

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
    LeafNode + LeafNodeView,
    to_be_signed: LeafNodeTbs + LeafNodeTbsView,
    signature: Signature + SignatureView,
}

// TODO(RLB) Sign / verify

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
    KeyPackage + KeyPackageView,
    to_be_signed: KeyPackageTbs + KeyPackageTbsView,
    signature: Signature + SignatureView,
}

// TODO(RLB) Sign / verify
