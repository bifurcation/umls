use crate::common::*;
use crate::io::*;
use crate::syntax2::*;

trait CipherSuite {
    type HashOutput: Serialize + Deserialize;
    type HpkePrivateKey: Serialize + Deserialize;
    type HpkePublicKey: Serialize + Deserialize;
    type SignaturePrivateKey: Serialize + Deserialize;
    type SignaturePublicKey: Serialize + Deserialize;
}

#[derive(Serialize, Deserialize)]
struct LeafNodeTbs<C: CipherSuite> {
    signature_key: C::SignaturePrivateKey,
    encryption_key: C::HpkePrivateKey,
    // credential <- requires Opaque
    // capabilities <- requires Vec
    // leaf_node_source <- requires Opaque
    // extensions <- requires Vec, Opaque
}
