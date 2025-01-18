use crate::common::*;
use crate::crypto::*;
use crate::io::*;
use crate::key_schedule::*;
use crate::protocol::*;
use crate::stack::*;
use crate::syntax::*;
use crate::treekem::*;
use crate::{mls_struct, stack_ptr, tick};

mls_struct! {
    GroupState,

    // Shared state
    ratchet_tree: RatchetTree,
    group_context: GroupContext,
    interim_transcript_hash: HashOutput,
    epoch_secret: EpochSecret,

    // Local state
    my_index: LeafIndex,
    my_signature_priv: SignaturePrivateKey,
    my_ratchet_tree_priv: RatchetTreePriv,
}

impl GroupState {
    pub fn epoch_authenticator(&self) -> HashOutput {
        tick!();
        self.epoch_secret.epoch_authenticator()
    }
}

impl SenderKeySource for GroupState {
    fn find_keys<'a>(
        &self,
        sender: LeafIndex,
        generation: Generation,
    ) -> Option<(AeadKey, AeadNonce)> {
        tick!();
        let (gen, key, nonce) = self
            .epoch_secret
            .handshake_key(sender, self.ratchet_tree.size());
        if gen == *generation {
            Some((key, nonce))
        } else {
            None
        }
    }
}
