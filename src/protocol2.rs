use crate::common::*;
use crate::io::*;
use crate::syntax2::*;

use derive_serialize::Signed;
use heapless::Vec;

trait Crypto {
    type HashOutput: Serialize + Deserialize;

    type HpkePrivateKey: Serialize + Deserialize;
    type HpkePublicKey: Serialize + Deserialize;

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
}

type HashOutput<C> = <C as Crypto>::HashOutput;
type HpkePrivateKey<C> = <C as Crypto>::HpkePrivateKey;
type HpkePublicKey<C> = <C as Crypto>::HpkePublicKey;
type SignaturePrivateKey<C> = <C as Crypto>::SignaturePrivateKey;
type SignaturePublicKey<C> = <C as Crypto>::SignaturePublicKey;
type Signature<C> = <C as Crypto>::Signature;

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

#[derive(Serialize, Deserialize, Signed)]
#[label = b"LeafNodeTbs"]
struct LeafNode<C: Crypto> {
    tbs: LeafNodeTbs<C>,
    signature: Signature<C>,
}

trait Signed<C: Crypto>: Sized {
    type ToBeSigned: Serialize;
    const LABEL: &[u8];

    fn new(tbs: Self::ToBeSigned, signature: C::Signature) -> Self;
    fn tbs(&self) -> &Self::ToBeSigned;
    fn signature(&self) -> &C::Signature;

    fn sign(tbs: Self::ToBeSigned, sig_priv: &C::SignaturePrivateKey) -> Result<Self> {
        let sig = C::sign_with_label(&tbs, Self::LABEL, sig_priv)?;
        Ok(Self::new(tbs, sig))
    }

    fn verify(&self, sig_key: &C::SignaturePublicKey) -> Result<()> {
        C::verify_with_label(self.tbs(), Self::LABEL, self.signature(), sig_key)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn signed_structs() {
        // TODO
    }
}
