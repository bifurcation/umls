use crate::common::*;
use crate::crypto::{self, *};
use crate::io::*;
use crate::syntax::*;
use crate::{mls_enum, mls_newtype, mls_newtype_opaque, mls_struct};

use core::ops::Deref;
use heapless::Vec;
use rand_core::CryptoRngCore;

mod consts {
    pub const SUPPORTED_VERSION: u16 = 0x0001; // mls10
    pub const SUPPORTED_CREDENTIAL_TYPE: u16 = 0x0001; // basic

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

type ExtensionListData = Vec<Extension, { consts::MAX_EXTENSIONS }>;
type ExtensionListDataView<'a> = Vec<ExtensionView<'a>, { consts::MAX_EXTENSIONS }>;

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
            .push(ProtocolVersion::from(U16::from(consts::SUPPORTED_VERSION)))
            .map_err(|_| Error("Too many items"))?;
        capabilities
            .cipher_suites
            .push(CipherSuite::from(U16::from(CIPHER_SUITE)))
            .map_err(|_| Error("Too many items"))?;
        capabilities
            .credentials
            .push(CredentialType::from(U16::from(
                consts::SUPPORTED_CREDENTIAL_TYPE,
            )))
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
struct KeyPackage {
    to_be_signed: KeyPackageTbs,
    to_be_signed_raw: Vec<u8, { Self::MAX_SIZE }>,
    signature: Signature,
}

#[derive(Clone, Debug, PartialEq)]
struct KeyPackageView<'a> {
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
            protocol_version: ProtocolVersion::from(U16::from(consts::SUPPORTED_VERSION)),
            cipher_suite: CipherSuite::from(U16::from(crypto::CIPHER_SUITE)),
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
}
