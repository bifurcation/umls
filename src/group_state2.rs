use crate::common::*;
use crate::crypto2::*;
use crate::io::*;
use crate::key_schedule2::*;
use crate::protocol2::*;
use crate::syntax2::*;
use crate::transcript_hash2::InterimTranscriptHash;
use crate::treekem2::*;

#[derive(Serialize, Deserialize)]
struct GroupState<C: Crypto> {
    // Shared state
    ratchet_tree: RatchetTree<C>,
    group_context: GroupContext<C>,
    interim_transcript_hash: InterimTranscriptHash<C>,
    epoch_secret: EpochSecret<C>,

    // Local state
    my_index: LeafIndex,
    my_signature_priv: SignaturePrivateKey<C>,
    my_ratchet_tree_priv: RatchetTreePriv<C>,
}

impl<C: Crypto> GroupState<C> {
    pub fn epoch_authenticator(&self) -> HashOutput<C> {
        self.epoch_secret.epoch_authenticator()
    }
}

impl<C: Crypto> SenderKeySource<C> for GroupState<C> {
    fn find_keys<'a>(
        &self,
        sender: LeafIndex,
        generation: Generation,
    ) -> Option<(AeadKey<C>, AeadNonce<C>)> {
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
