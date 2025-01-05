use crate::common::*;
use crate::crypto::{self, *};
use crate::io::*;
use crate::syntax::*;
use crate::{mls_enum, mls_newtype_opaque, mls_newtype_primitive, mls_struct};

use core::marker::PhantomData;
use core::ops::{Deref, DerefMut};
use heapless::Vec;

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

mls_signed! { GroupInfo + GroupInfoView + b"GroupInfoTBS" => GroupInfoTbs + GroupInfoTbsView }

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
        }
    }

    #[test]
    fn signed_objects() {
        test_sign_verify!(LeafNode, LeafNodeView, LeafNodeTbs);
        test_sign_verify!(KeyPackage, KeyPackageView, KeyPackageTbs);
        test_sign_verify!(GroupInfo, GroupInfoView, GroupInfoTbs);
    }
}
