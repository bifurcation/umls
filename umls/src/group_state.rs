use umls_core::{
    common::{Error, Result},
    crypto::{
        AeadEncrypt, AeadKey, AeadNonce, Crypto, CryptoSizes, HpkeEncrypt, SerializedRatchetTree,
        SignaturePrivateKey, SignaturePublicKey,
    },
    io::{Read, Write},
    protocol::{
        self, Add, Capabilities, Commit, ConfirmedTranscriptHash, Credential,
        EncryptedGroupSecretsEntry, Epoch, FramedContent, FramedContentBinder, FramedContentTbs,
        Generation, GroupContext, GroupId, GroupInfo, GroupInfoExtension, GroupInfoTbs,
        GroupSecrets, HashRef, KeyPackage, KeyPackagePriv, KeyPackageTbs, LeafIndex, LeafNode,
        LeafNodeSource, LeafNodeTbs, Lifetime, MessageContent, PrivateMessage, PrivateMessageAad,
        Proposal, ProposalOrRef, ProtocolVersion, Remove, ReuseGuard, Sender, SenderData,
        SenderKeySource, SignedFramedContent, Welcome,
    },
    stack,
    syntax::{Deserialize, Materialize, Serialize},
    treekem::{RatchetTree, RatchetTreePriv},
};

use crate::key_schedule::{EpochAuthenticator, EpochSecret, KeyScheduleJoinerSecret};
use crate::transcript_hash::{self, InterimTranscriptHash};
use heapless::Vec;

use rand::{CryptoRng, Rng};

pub trait MakeKeyPackage<C: Crypto> {
    fn create(
        rng: &mut impl CryptoRng,
        signature_priv: SignaturePrivateKey<C>,
        signature_key: SignaturePublicKey<C>,
        credential: Credential,
    ) -> Result<(KeyPackagePriv<C>, KeyPackage<C>)>;
}

impl<C: Crypto> MakeKeyPackage<C> for KeyPackage<C> {
    fn create(
        rng: &mut impl CryptoRng,
        signature_priv: SignaturePrivateKey<C>,
        signature_key: SignaturePublicKey<C>,
        credential: Credential,
    ) -> Result<(KeyPackagePriv<C>, KeyPackage<C>)> {
        stack::update();
        let (encryption_priv, encryption_key) = C::hpke_generate(rng)?;
        let (init_priv, init_key) = C::hpke_generate(rng)?;

        // Form the leaf node
        let leaf_node_tbs = LeafNodeTbs {
            encryption_key,
            signature_key,
            credential,
            capabilities: Capabilities::new::<C>(),
            leaf_node_source: LeafNodeSource::KeyPackage(Lifetime::default()),
            extensions: Vec::default(),
        };

        let leaf_node = LeafNode::sign(leaf_node_tbs, &signature_priv)?;

        // Form the key package
        let key_package_tbs = KeyPackageTbs {
            protocol_version: ProtocolVersion::default(),
            cipher_suite: C::CIPHER_SUITE,
            init_key,
            leaf_node,
            extensions: Vec::default(),
        };

        let key_package = KeyPackage::sign(key_package_tbs, &signature_priv)?;

        // Form the private state
        let key_package_priv = KeyPackagePriv {
            init_priv,
            encryption_priv,
            signature_priv,
        };

        Ok((key_package_priv, key_package))
    }
}

pub enum Operation<C: CryptoSizes> {
    Add(KeyPackage<C>),
    Remove(LeafIndex),
}

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

impl<C: CryptoSizes> GroupState<C> {
    pub fn epoch_authenticator(&self) -> EpochAuthenticator<C> {
        stack::update();
        self.epoch_secret.epoch_authenticator()
    }

    pub fn create(
        rng: &mut impl CryptoRng,
        key_package_priv: KeyPackagePriv<C>,
        key_package: KeyPackage<C>,
        group_id: GroupId,
    ) -> Result<Self> {
        stack::update();
        // Construct the ratchet tree
        let mut ratchet_tree = RatchetTree::default();
        ratchet_tree.add_leaf(key_package.tbs.leaf_node)?;

        // Generate a fresh epoch secret
        let epoch_secret = EpochSecret::new(rng);

        // Set the group context
        let group_context = GroupContext {
            version: ProtocolVersion::default(),
            cipher_suite: C::CIPHER_SUITE,
            group_id,
            epoch: Epoch(0),
            tree_hash: ratchet_tree.root_hash()?,
            confirmed_transcript_hash: ConfirmedTranscriptHash::default(),
            extensions: Vec::default(),
        };

        // Compute the interim transcript hash
        let confirmation_tag =
            epoch_secret.confirmation_tag(&group_context.confirmed_transcript_hash);
        let interim_transcript_hash =
            transcript_hash::interim(&group_context.confirmed_transcript_hash, &confirmation_tag)?;

        let my_ratchet_tree_priv = RatchetTreePriv {
            encryption_priv: key_package_priv.encryption_priv,
            ..Default::default()
        };

        Ok(GroupState {
            ratchet_tree,
            group_context,
            interim_transcript_hash,
            epoch_secret,
            my_index: LeafIndex(0),
            my_signature_priv: key_package_priv.signature_priv,
            my_ratchet_tree_priv,
        })
    }

    pub fn join(
        key_package_priv: KeyPackagePriv<C>,
        key_package: &KeyPackage<C>,
        welcome: Welcome<C>,
    ) -> Result<Self> {
        stack::update();
        // Verify that the Welcome is for us
        let kp_ref = C::hash_ref(b"MLS 1.0 KeyPackage Reference", &key_package)?;
        if welcome.secrets[0].new_member != HashRef(kp_ref) {
            return Err(Error("Misdirected Welcome"));
        }

        // Decrypt the Group Secrets
        let group_secrets = GroupSecrets::hpke_open(
            welcome.secrets[0].encrypted_group_secrets.clone(),
            &key_package_priv.init_priv,
            &[],
        )?;

        if !group_secrets.psks.is_empty() {
            return Err(Error("Not implemented"));
        }

        // Decrypt the GroupInfo
        let member_secret = group_secrets.joiner_secret.advance();
        let (welcome_key, welcome_nonce) = member_secret.welcome_key_nonce();

        let group_info = GroupInfo::open(
            welcome.encrypted_group_info,
            &welcome_key,
            &welcome_nonce,
            &[],
        )?;

        // Extract the ratchet tree from an extension
        let ratchet_tree_extension = group_info
            .tbs
            .extensions
            .iter()
            .find(|ext| ext.extension_type == protocol::consts::EXTENSION_TYPE_RATCHET_TREE);

        let Some(ratchet_tree_extension) = ratchet_tree_extension else {
            return Err(Error("Not implemented"));
        };

        let ratchet_tree = {
            let extension_data: &SerializedRatchetTree<C> = &ratchet_tree_extension.extension_data;
            RatchetTree::deserialize(&mut extension_data.as_ref())?
        };

        let tree_hash = ratchet_tree.root_hash()?;
        let parent_hash_valid = ratchet_tree.parent_hash_valid()?;
        if tree_hash != group_info.tbs.group_context.tree_hash || !parent_hash_valid {
            return Err(Error("Invalid ratchet tree"));
        }

        // Find our own leaf in the ratchet tree
        let Some(my_index) = ratchet_tree.find(&key_package.tbs.leaf_node) else {
            return Err(Error("Joiner not present in tree"));
        };

        // Verify the signature on the GroupInfo
        let sender = group_info.tbs.signer;
        {
            // Scoped to bound the lifetime of signer_leaf
            let Some(signer_leaf) = ratchet_tree.leaf_node_at(sender) else {
                return Err(Error("GroupInfo signer not present in tree"));
            };

            group_info.verify(&signer_leaf.tbs.signature_key)?;
        }

        // Update the key schedule
        let group_context = group_info.tbs.group_context;
        let group_context_bytes = group_context.materialize()?;
        let epoch_secret = member_secret.advance(&group_context_bytes);

        let confirmation_tag =
            epoch_secret.confirmation_tag(&group_context.confirmed_transcript_hash);
        let interim_transcript_hash =
            transcript_hash::interim(&group_context.confirmed_transcript_hash, &confirmation_tag)?;

        // Construct the ratchet tree private state
        let my_ratchet_tree_priv = RatchetTreePriv::new(
            &ratchet_tree,
            my_index,
            sender,
            group_secrets.path_secret,
            key_package_priv.encryption_priv,
        )?;

        assert!(my_ratchet_tree_priv.consistent(&ratchet_tree, my_index));

        // Import the data into a GroupState
        Ok(GroupState {
            ratchet_tree,
            group_context,
            interim_transcript_hash,
            epoch_secret,
            my_index,
            my_signature_priv: key_package_priv.signature_priv,
            my_ratchet_tree_priv,
        })
    }

    // TODO(RLB) Break this function up, find commonalities with handle_commit
    #[allow(clippy::too_many_lines)]
    pub fn send_commit(
        &mut self,
        rng: &mut impl CryptoRng,
        operation: Operation<C>,
    ) -> Result<(PrivateMessage<C>, Option<Welcome<C>>)> {
        stack::update();
        // Snapshot off required bits of the previous state
        let group_context_prev = self.group_context.clone();
        let epoch_secret_prev = self.epoch_secret.clone();
        let ratchet_tree_size_prev = self.ratchet_tree.size();

        // Apply the operation and return the proposal that will communicate it
        let (proposal, joiner_location) = match operation {
            Operation::Add(key_package) => {
                // Verify the KeyPackage and the LeafNode
                let signature_key = &key_package.tbs.leaf_node.tbs.signature_key;
                key_package.verify(signature_key)?;
                key_package.tbs.leaf_node.verify(signature_key)?;

                // Add the joiner to the tree
                let joiner_location = self
                    .ratchet_tree
                    .add_leaf(key_package.tbs.leaf_node.clone())?;

                (Proposal::Add(Add { key_package }), Some(joiner_location))
            }
            Operation::Remove(removed) => {
                // Remove the member from the tree
                self.ratchet_tree.remove_leaf(removed)?;
                self.my_ratchet_tree_priv.blank_path(
                    self.my_index,
                    removed,
                    self.ratchet_tree.size().into(),
                );

                (Proposal::Remove(Remove { removed }), None)
            }
        };

        // Update the committer's direct path
        let (ratchet_tree_priv, update_path) =
            self.ratchet_tree
                .update_direct_path(rng, self.my_index, &self.my_signature_priv)?;

        self.my_ratchet_tree_priv = ratchet_tree_priv;

        // Encrypt a new secret to the group, using a provisional group context
        self.group_context.epoch.0 += 1;
        self.group_context.tree_hash = self.ratchet_tree.root_hash()?;

        let update_path = self.ratchet_tree.encrypt_path_secrets(
            rng,
            self.my_index,
            &self.group_context,
            &self.my_ratchet_tree_priv,
            update_path,
        )?;

        assert!(self
            .my_ratchet_tree_priv
            .consistent(&self.ratchet_tree, self.my_index));

        // Form the Commit and the enclosing SignedFramedContent
        let mut commit = Commit {
            path: Some(update_path),
            proposals: Vec::default(),
        };
        commit
            .proposals
            .push(ProposalOrRef::Proposal(proposal.clone()))
            .map_err(|_| Error("Too many entries"))?;

        let framed_content = FramedContent {
            group_id: group_context_prev.group_id.clone(),
            epoch: group_context_prev.epoch,
            sender: Sender::Member(self.my_index),
            authenticated_data: PrivateMessageAad::default(),
            content: MessageContent::Commit(commit),
        };

        let framed_content_tbs = FramedContentTbs {
            version: ProtocolVersion::default(),
            wire_format: protocol::consts::SUPPORTED_WIRE_FORMAT,
            content: framed_content,
            binder: FramedContentBinder::Member(group_context_prev),
        };

        let signed_framed_content =
            SignedFramedContent::sign(framed_content_tbs, &self.my_signature_priv)?;

        // Update the confirmed transcript hash
        self.group_context.confirmed_transcript_hash = transcript_hash::confirmed(
            &self.interim_transcript_hash,
            &signed_framed_content.tbs.content,
            &signed_framed_content.signature,
        )?;

        // Ratchet forward the key schedule
        let commit_secret = self.my_ratchet_tree_priv.commit_secret();
        let (joiner_secret, welcome_key, welcome_nonce) = self
            .epoch_secret
            .advance(&commit_secret, &self.group_context)?;

        // Form the PrivateMessage
        let confirmation_tag = self
            .epoch_secret
            .confirmation_tag(&self.group_context.confirmed_transcript_hash);
        self.interim_transcript_hash = transcript_hash::interim(
            &self.group_context.confirmed_transcript_hash,
            &confirmation_tag,
        )?;
        let (generation, key, nonce) =
            epoch_secret_prev.handshake_key(self.my_index, ratchet_tree_size_prev);

        let sender_data = SenderData {
            leaf_index: self.my_index,
            generation,
            reuse_guard: ReuseGuard(rng.random()),
        };

        let private_message = PrivateMessage::new(
            signed_framed_content,
            confirmation_tag.clone(),
            &sender_data,
            &key,
            nonce,
            &epoch_secret_prev.sender_data_secret(),
            PrivateMessageAad::default(),
        )?;

        // Form the Welcome if required
        let welcome = if let Proposal::Add(Add { key_package }) = &proposal {
            let joiner_location = joiner_location.unwrap();
            let path_secret = self.ratchet_tree.select_path_secret(
                &self.my_ratchet_tree_priv,
                self.my_index,
                joiner_location,
            )?;

            let group_secrets = GroupSecrets {
                joiner_secret,
                path_secret: Some(path_secret),
                psks: Vec::default(),
            };

            let encrypted_group_secrets =
                group_secrets.hpke_seal(rng, &key_package.tbs.init_key, &[])?;
            let new_member = HashRef(C::hash_ref(b"MLS 1.0 KeyPackage Reference", key_package)?);
            let encrypted_group_secrets = EncryptedGroupSecretsEntry {
                new_member,
                encrypted_group_secrets,
            };

            let mut secrets = Vec::new();
            secrets.push(encrypted_group_secrets).unwrap();

            let mut ratchet_tree_extension = GroupInfoExtension {
                extension_type: protocol::consts::EXTENSION_TYPE_RATCHET_TREE,
                extension_data: Default::default(),
            };

            self.ratchet_tree
                .serialize(&mut ratchet_tree_extension.extension_data)?;

            let mut extensions = Vec::new();
            extensions.push(ratchet_tree_extension).unwrap();

            let group_info_tbs = GroupInfoTbs {
                group_context: self.group_context.clone(),
                extensions,
                confirmation_tag,
                signer: self.my_index,
            };

            let group_info = GroupInfo::sign(group_info_tbs, &self.my_signature_priv)?;
            let encrypted_group_info = group_info.seal(&welcome_key, &welcome_nonce, &[])?;

            Some(Welcome {
                cipher_suite: C::CIPHER_SUITE,
                secrets,
                encrypted_group_info,
            })
        } else {
            None
        };

        Ok((private_message, welcome))
    }

    pub fn handle_commit(&mut self, commit: PrivateMessage<C>) -> Result<()> {
        stack::update();
        // Unwrap the PrivateMessage and verify its signature
        let sender_data_secret = self.epoch_secret.sender_data_secret();
        let (signed_framed_content, confirmation_tag_message) =
            commit.open(&sender_data_secret, self, &self.group_context)?;

        let Sender::Member(sender) = signed_framed_content.tbs.content.sender;
        {
            let Some(signer_leaf) = self.ratchet_tree.leaf_node_at(sender) else {
                return Err(Error("Commit signer not present in tree"));
            };

            signed_framed_content.verify(&signer_leaf.tbs.signature_key)?;
        }

        // Unwrap the Commit and apply it to the ratchet tree
        let MessageContent::Commit(commit) = &signed_framed_content.tbs.content.content;

        if commit.proposals.len() != 1 {
            return Err(Error("Not implemented"));
        }

        let ProposalOrRef::Proposal(proposal) = &commit.proposals[0];

        match proposal {
            Proposal::Add(add) => {
                self.ratchet_tree
                    .add_leaf(add.key_package.tbs.leaf_node.clone())?;
            }
            Proposal::Remove(remove) => {
                self.ratchet_tree.remove_leaf(remove.removed)?;
                self.my_ratchet_tree_priv.blank_path(
                    self.my_index,
                    remove.removed,
                    self.ratchet_tree.size().into(),
                );
            }
        }

        // Merge the update path into the tree
        let update_path = commit
            .path
            .as_ref()
            .ok_or(Error("No update path in Commit"))?;
        let parent_hash = self.ratchet_tree.merge(&update_path.nodes, sender)?;

        if update_path.leaf_node.tbs.leaf_node_source != LeafNodeSource::Commit(parent_hash) {
            return Err(Error("Invalid parent hash"));
        }
        self.ratchet_tree
            .merge_leaf(sender, update_path.leaf_node.clone());

        // Decapsulate the UpdatePath
        self.group_context.epoch.0 += 1;
        self.group_context.tree_hash = self.ratchet_tree.root_hash()?;

        self.ratchet_tree.decap(
            &mut self.my_ratchet_tree_priv,
            update_path,
            sender,
            self.my_index,
            &self.group_context,
        )?;

        assert!(self
            .my_ratchet_tree_priv
            .consistent(&self.ratchet_tree, self.my_index));

        // Update the confirmed transcript hash
        self.group_context.confirmed_transcript_hash = transcript_hash::confirmed(
            &self.interim_transcript_hash,
            &signed_framed_content.tbs.content,
            &signed_framed_content.signature,
        )?;

        // Ratchet forward the key schedule
        let commit_secret = self.my_ratchet_tree_priv.commit_secret();
        let _ = self
            .epoch_secret
            .advance(&commit_secret, &self.group_context)?;

        // Verify the confirmation tag
        let confirmation_tag_computed = self
            .epoch_secret
            .confirmation_tag(&self.group_context.confirmed_transcript_hash);

        if confirmation_tag_message != confirmation_tag_computed {
            return Err(Error("Invalid confirmation tag"));
        }

        self.interim_transcript_hash = transcript_hash::interim(
            &self.group_context.confirmed_transcript_hash,
            &confirmation_tag_computed,
        )?;

        Ok(())
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
