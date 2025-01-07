use crate::common::*;
use crate::crypto::*;
use crate::io::*;
use crate::key_schedule::*;
use crate::protocol::*;
use crate::syntax::*;
use crate::treekem::*;
use crate::{mls_struct, mls_struct_serialize};

mls_struct! {
    GroupState + GroupStateView,

    // Shared state
    ratchet_tree: RatchetTree + RatchetTreeView,
    group_context: GroupContext + GroupContextView,
    interim_transcript_hash: HashOutput + HashOutputView,
    init_secret: InitSecret + InitSecretView,

    // Local state
    my_index: LeafIndex + LeafIndexView,
    my_signature_priv: SignaturePrivateKey + SignaturePrivateKeyView,
}
