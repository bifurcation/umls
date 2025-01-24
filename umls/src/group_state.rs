use umls_core::{common::*, crypto::*, io::*, protocol::*, stack, syntax::*, treekem::*};

use crate::key_schedule::*;
use crate::transcript_hash::InterimTranscriptHash;

#[derive(Debug, Serialize, Deserialize)]
pub struct GroupState<C: Crypto> {
    // Shared state
    pub ratchet_tree: RatchetTree<C>,
    pub group_context: GroupContext<C>,
    pub interim_transcript_hash: InterimTranscriptHash<C>,
    pub epoch_secret: EpochSecret<C>,

    // Local state
    pub my_index: LeafIndex,
    pub my_signature_priv: SignaturePrivateKey<C>,
    pub my_ratchet_tree_priv: RatchetTreePriv<C>,
}

impl<C: Crypto> GroupState<C> {
    pub fn epoch_authenticator(&self) -> EpochAuthenticator<C> {
        stack::update();
        self.epoch_secret.epoch_authenticator()
    }
}

impl<C: Crypto> SenderKeySource<C> for GroupState<C> {
    fn find_keys<'a>(
        &self,
        sender: LeafIndex,
        generation: Generation,
    ) -> Option<(AeadKey<C>, AeadNonce<C>)> {
        stack::update();
        let (gen, key, nonce) = self
            .epoch_secret
            .handshake_key(sender, self.ratchet_tree.size());
        if gen == generation {
            Some((key, nonce))
        } else {
            None
        }
    }
}
