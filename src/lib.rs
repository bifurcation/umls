#![no_std]
#![allow(dead_code)]
#![allow(unused_variables)]

mod common;
mod crypto;
mod group_state;
mod io;
mod key_schedule;
mod protocol;
mod syntax;
mod transcript_hash;
mod tree_math;
mod treekem;

use common::*;
use crypto::*;
use group_state::*;
use io::*;
use key_schedule::*;
use protocol::*;
use syntax::*;
use treekem::*;

use heapless::Vec;
use rand::Rng;
use rand_core::CryptoRngCore;

pub fn make_key_package(
    rng: &mut (impl Rng + CryptoRngCore),
    signature_priv: SignaturePrivateKey,
    signature_key: SignaturePublicKey,
    credential: Credential,
) -> Result<(KeyPackagePriv, KeyPackage)> {
    let (encryption_priv, encryption_key) = crypto::generate_hpke(rng)?;
    let (init_priv, init_key) = crypto::generate_hpke(rng)?;

    // Form the leaf node
    let leaf_node_tbs = LeafNodeTbs {
        encryption_key,
        signature_key,
        credential,
        capabilities: Capabilities {
            versions: [protocol::consts::SUPPORTED_VERSION]
                .as_ref()
                .try_into()
                .unwrap(),
            cipher_suites: [crypto::consts::CIPHER_SUITE].as_ref().try_into().unwrap(),
            credentials: [protocol::consts::SUPPORTED_CREDENTIAL_TYPE]
                .as_ref()
                .try_into()
                .unwrap(),
            ..Default::default()
        },
        leaf_node_source: Default::default(),
        extensions: Default::default(),
    };

    let leaf_node = LeafNode::new(leaf_node_tbs, signature_priv.as_view())?;

    // Form the key package
    let key_package_tbs = KeyPackageTbs {
        protocol_version: protocol::consts::SUPPORTED_VERSION,
        cipher_suite: crypto::consts::CIPHER_SUITE,
        init_key,
        leaf_node,
        extensions: Default::default(),
    };

    let key_package = KeyPackage::new(key_package_tbs, signature_priv.as_view())?;

    // Form the private state
    let key_package_priv = KeyPackagePriv {
        init_priv,
        encryption_priv,
        signature_priv,
    };

    Ok((key_package_priv, key_package))
}

pub fn create_group(
    rng: &mut (impl Rng + CryptoRngCore),
    key_package_priv: KeyPackagePrivView,
    key_package: KeyPackageView,
    group_id: GroupId,
) -> Result<GroupState> {
    // Construct the ratchet tree
    let mut ratchet_tree = RatchetTree::default();
    ratchet_tree.add_leaf(key_package.leaf_node.to_object())?;

    // Generate a fresh epoch secret
    let epoch_secret = EpochSecret::from(Opaque::random(rng));

    // Set the group context
    let group_context = GroupContext {
        version: protocol::consts::SUPPORTED_VERSION,
        cipher_suite: crypto::consts::CIPHER_SUITE,
        group_id,
        epoch: Epoch(0),
        tree_hash: ratchet_tree.root_hash()?,
        confirmed_transcript_hash: Default::default(),
        extensions: Default::default(),
    };

    // Compute the interim transcript hash
    let confirmation_tag = epoch_secret.confirmation_tag(&group_context.confirmed_transcript_hash);
    let interim_transcript_hash =
        transcript_hash::interim(&group_context.confirmed_transcript_hash, &confirmation_tag)?;

    Ok(GroupState {
        ratchet_tree,
        group_context,
        interim_transcript_hash,
        epoch_secret,
        my_index: LeafIndex(0),
        my_signature_priv: key_package_priv.signature_priv.to_object(),
        ..Default::default()
    })
}

pub fn join_group(
    key_package_priv: KeyPackagePrivView,
    key_package: KeyPackageView,
    welcome: WelcomeView,
) -> Result<GroupState> {
    // Verify that the Welcome is for us
    let kp_ref = crypto::hash_ref(b"MLS 1.0 KeyPackage Reference", &key_package.to_object())?;
    if welcome.secrets[0].new_member != kp_ref.as_view() {
        return Err(Error("Misdirected Welcome"));
    }

    // Decrypt the Group Secrets
    let group_secrets_data = welcome.secrets[0]
        .encrypted_group_secrets
        .open(key_package_priv.init_priv, &[])?;
    let mut group_secrets_reader = SliceReader::new(&group_secrets_data);
    let group_secrets = GroupSecretsView::deserialize(&mut group_secrets_reader)?;

    if !group_secrets.psks.is_empty() {
        return Err(Error("Not implemented"));
    }

    // Decrypt the GroupInfo
    let member_secret = group_secrets.joiner_secret.advance();
    let (welcome_key, welcome_nonce) = member_secret.welcome_key_nonce();

    let group_info_data = welcome
        .encrypted_group_info
        .open(welcome_key, welcome_nonce, &[])?;
    let mut group_info_reader = SliceReader::new(&group_info_data);
    let group_info = GroupInfoView::deserialize(&mut group_info_reader)?;

    // Extract the ratchet tree from an extension
    let ratchet_tree_extension = group_info.extensions.iter().find(|ext| {
        ext.extension_type.to_object() == protocol::consts::EXTENSION_TYPE_RATCHET_TREE
    });

    let Some(ratchet_tree_extension) = ratchet_tree_extension else {
        return Err(Error("Not implemented"));
    };

    let ratchet_tree_data = ratchet_tree_extension.extension_data;
    let mut ratchet_tree_reader = SliceReader::new(ratchet_tree_data.as_ref());
    let ratchet_tree = RatchetTreeView::deserialize(&mut ratchet_tree_reader)?;
    let ratchet_tree = ratchet_tree.to_object();

    let tree_hash = ratchet_tree.root_hash()?;
    if tree_hash.as_view() != group_info.group_context.tree_hash {
        return Err(Error("Invalid ratchet tree"));
    }

    // Find our own leaf in the ratchet tree
    let Some(my_index) = ratchet_tree.find(key_package.leaf_node.clone()) else {
        return Err(Error("Joiner not present in tree"));
    };

    // Verify the signature on the GroupInfo
    let sender = group_info.signer.to_object();
    {
        // Scoped to bound the lifetime of signer_leaf
        let Some(signer_leaf) = ratchet_tree.leaf_node_at(sender) else {
            return Err(Error("GroupInfo signer not present in tree"));
        };

        group_info.verify(signer_leaf.signature_key)?;
    }

    // Update the key schedule
    let group_context = group_info.group_context.to_object();
    let group_context_bytes = serialize!(GroupContext, group_context);
    let epoch_secret = member_secret.advance(&group_context_bytes);

    let confirmation_tag = epoch_secret.confirmation_tag(&group_context.confirmed_transcript_hash);
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

    // Import the data into a GroupState
    Ok(GroupState {
        ratchet_tree,
        group_context,
        interim_transcript_hash,
        epoch_secret,
        my_index,
        my_signature_priv: key_package_priv.signature_priv.to_object(),
        my_ratchet_tree_priv,
    })
}

pub enum Operation {
    Add(KeyPackage),
    Remove(LeafIndex),
}

pub fn send_commit(
    rng: &mut (impl Rng + CryptoRngCore),
    group_state: GroupStateView,
    operation: Operation,
) -> Result<(GroupState, PrivateMessage, Option<Welcome>)> {
    let mut next = group_state.to_object();

    // Apply the operation and return the proposal that will communicate it
    let (proposal, joiner_location) = match operation {
        Operation::Add(key_package) => {
            // Verify the KeyPackage and the LeafNode
            let signature_key = key_package.tbs.leaf_node.tbs.signature_key.as_view();
            key_package.as_view().verify(signature_key)?;
            key_package.tbs.leaf_node.as_view().verify(signature_key)?;

            // Add the joiner to the tree
            let joiner_location = next.ratchet_tree.add_leaf(key_package.leaf_node.clone())?;

            (Proposal::Add(Add { key_package }), Some(joiner_location))
        }
        Operation::Remove(removed) => {
            // Remove the member from the tree
            next.ratchet_tree.remove_leaf(removed)?;
            next.my_ratchet_tree_priv.blank_path(
                next.my_index,
                removed,
                next.ratchet_tree.size().into(),
            );

            (Proposal::Remove(Remove { removed }), None)
        }
    };

    // Update the committer's direct path
    let (ratchet_tree_priv, update_path) = next.ratchet_tree.update_direct_path(
        rng,
        next.my_index,
        next.my_signature_priv.as_view(),
    )?;

    next.ratchet_tree.merge(&update_path, next.my_index);

    // Encrypt a new secret to the group, using a provisional group context
    next.group_context.epoch.0 += 1;
    next.group_context.tree_hash = next.ratchet_tree.root_hash()?;

    let update_path = next.ratchet_tree.encrypt_path_secrets(
        rng,
        next.my_index,
        &next.group_context,
        &ratchet_tree_priv,
        update_path,
    )?;

    next.my_ratchet_tree_priv = ratchet_tree_priv;

    // Form the Commit and the enclosing SignedFramedContent
    let mut commit = Commit {
        path: Some(update_path),
        proposals: Default::default(),
    };
    commit
        .proposals
        .push(ProposalOrRef::Proposal(proposal.clone()))
        .map_err(|_| Error("Too many entries"))?;

    let authenticated_data = PrivateMessageAad::default();
    let framed_content = FramedContent {
        group_id: group_state.group_context.group_id.to_object(),
        epoch: group_state.group_context.epoch.to_object(),
        sender: Sender::Member(group_state.my_index.to_object()),
        authenticated_data: authenticated_data.clone(),
        content: MessageContent::Commit(commit),
    };

    let framed_content_tbs = FramedContentTbs {
        version: protocol::consts::SUPPORTED_VERSION,
        wire_format: protocol::consts::SUPPORTED_WIRE_FORMAT,
        content: framed_content,
        binder: FramedContentBinder::Member(group_state.group_context.to_object()),
    };

    let signed_framed_content =
        SignedFramedContent::new(framed_content_tbs, group_state.my_signature_priv)?;

    // Update the confirmed transcript hash
    next.group_context.confirmed_transcript_hash = transcript_hash::confirmed(
        group_state.interim_transcript_hash,
        &signed_framed_content.content,
        &signed_framed_content.signature,
    )?;

    // Ratchet forward the key schedule
    let commit_secret = next.my_ratchet_tree_priv.commit_secret()?;
    let (epoch_secret, joiner_secret, welcome_key, welcome_nonce) = group_state
        .epoch_secret
        .advance(commit_secret.as_view(), &next.group_context)?;

    next.epoch_secret = epoch_secret;

    // Form the PrivateMessage
    let confirmation_tag = next
        .epoch_secret
        .confirmation_tag(&next.group_context.confirmed_transcript_hash);
    next.interim_transcript_hash = transcript_hash::interim(
        &next.group_context.confirmed_transcript_hash,
        &confirmation_tag,
    )?;
    let (generation, key, nonce) = group_state
        .epoch_secret
        .to_object()
        .handshake_key(next.my_index, group_state.ratchet_tree.size());

    let sender_data = SenderData {
        leaf_index: next.my_index,
        generation: Generation(generation),
        reuse_guard: ReuseGuard(rng.gen()),
    };

    let private_message = PrivateMessage::new(
        signed_framed_content,
        confirmation_tag.clone(),
        sender_data,
        key,
        nonce,
        group_state
            .epoch_secret
            .to_object()
            .sender_data_secret()
            .as_view(),
        authenticated_data,
    )?;

    // Form the Welcome if required
    let welcome = if let Proposal::Add(Add { key_package }) = &proposal {
        let joiner_location = joiner_location.unwrap();
        let path_secret = next.ratchet_tree.select_path_secret(
            &next.my_ratchet_tree_priv,
            next.my_index,
            joiner_location,
        )?;

        let group_secrets = GroupSecrets {
            joiner_secret,
            path_secret: Some(path_secret),
            psks: Default::default(),
        };

        let encrypted_group_secrets = HpkeEncryptedGroupSecrets::seal(
            rng,
            group_secrets,
            key_package.init_key.as_view(),
            &[],
        )?;
        let new_member = crypto::hash_ref(b"MLS 1.0 KeyPackage Reference", key_package)?;
        let encrypted_group_secrets = EncryptedGroupSecrets {
            new_member,
            encrypted_group_secrets,
        };

        let secrets = [encrypted_group_secrets].as_ref().try_into().unwrap();

        let ratchet_tree_data = serialize!(RatchetTree, next.ratchet_tree);
        let ratchet_tree_extension = GroupInfoExtension {
            extension_type: protocol::consts::EXTENSION_TYPE_RATCHET_TREE,
            extension_data: Opaque(ratchet_tree_data).into(),
        };
        let group_info_extensions = [ratchet_tree_extension].as_ref().try_into().unwrap();

        let group_info_tbs = GroupInfoTbs {
            group_context: next.group_context.clone(),
            extensions: group_info_extensions,
            confirmation_tag: confirmation_tag.clone(),
            signer: next.my_index,
        };

        let group_info = GroupInfo::new(group_info_tbs, next.my_signature_priv.as_view())?;
        let encrypted_group_info =
            EncryptedGroupInfo::seal(group_info, welcome_key, welcome_nonce, &[])?;

        Some(Welcome {
            cipher_suite: crypto::consts::CIPHER_SUITE,
            secrets,
            encrypted_group_info,
        })
    } else {
        None
    };

    Ok((next, private_message, welcome))
}

pub fn remove_member(
    _group_state: GroupStateView,
    _leaf_index: LeafIndex,
) -> Result<(GroupState, PrivateMessage)> {
    todo!();
}

pub fn handle_commit(
    group_state: GroupStateView,
    commit: PrivateMessageView,
) -> Result<GroupState> {
    // Take ownership of the group state
    let mut next = group_state.to_object();

    // Unwrap the PrivateMessage and verify its signature
    let sender_data_secret = next.epoch_secret.sender_data_secret();
    let (signed_framed_content, confirmation_tag_message) =
        commit.open(&sender_data_secret, &next, &next.group_context)?;

    let Sender::Member(sender) = signed_framed_content.content.sender;
    {
        let Some(signer_leaf) = next.ratchet_tree.leaf_node_at(sender) else {
            return Err(Error("Commit signer not present in tree"));
        };

        signed_framed_content
            .as_view()
            .verify(signer_leaf.signature_key)?;
    }

    // Unwrap the Commit and apply it to the ratchet tree
    let MessageContent::Commit(commit) = &signed_framed_content.content.content;

    if commit.proposals.len() != 1 {
        return Err(Error("Not implemented"));
    }

    let ProposalOrRef::Proposal(proposal) = &commit.proposals[0];

    match proposal {
        Proposal::Add(add) => {
            next.ratchet_tree
                .add_leaf(add.key_package.leaf_node.clone())?;
        }
        Proposal::Remove(remove) => {
            next.ratchet_tree.remove_leaf(remove.removed)?;
            next.my_ratchet_tree_priv.blank_path(
                next.my_index,
                remove.removed,
                next.ratchet_tree.size().into(),
            );
        }
    }

    // Merge the update path into the tree
    let update_path = commit
        .path
        .as_ref()
        .ok_or(Error("No update path in Commit"))?;
    next.ratchet_tree.merge(&update_path, sender);

    // Decapsulate the UpdatePath
    next.group_context.epoch.0 += 1;
    next.group_context.tree_hash = next.ratchet_tree.root_hash()?;

    next.ratchet_tree.decap(
        &mut next.my_ratchet_tree_priv,
        update_path.as_view(),
        sender,
        next.my_index,
        &next.group_context,
    )?;

    // Update the confirmed transcript hash
    next.group_context.confirmed_transcript_hash = transcript_hash::confirmed(
        group_state.interim_transcript_hash,
        &signed_framed_content.content,
        &signed_framed_content.signature,
    )?;

    // Ratchet forward the key schedule
    let commit_secret = next.my_ratchet_tree_priv.commit_secret()?;
    let (epoch_secret, joiner_secret, welcome_key, welcome_nonce) = group_state
        .epoch_secret
        .advance(commit_secret.as_view(), &next.group_context)?;

    next.epoch_secret = epoch_secret;

    // Verify the confirmation tag
    let confirmation_tag_computed = next
        .epoch_secret
        .confirmation_tag(&next.group_context.confirmed_transcript_hash);

    // XXX(RLB) Constant-time equality check?
    if confirmation_tag_message != confirmation_tag_computed {
        return Err(Error("Invalid confirmation tag"));
    }

    next.interim_transcript_hash = transcript_hash::interim(
        &next.group_context.confirmed_transcript_hash,
        &confirmation_tag_computed,
    )?;

    Ok(next)
}

#[cfg(test)]
mod test {
    use super::*;

    fn make_user(
        rng: &mut (impl CryptoRngCore + Rng),
        name: &[u8],
    ) -> (KeyPackagePriv, KeyPackage) {
        let (sig_priv, sig_key) = crypto::generate_sig(rng).unwrap();
        let credential = Credential::from(b"alice".as_slice());
        make_key_package(rng, sig_priv, sig_key, credential).unwrap()
    }

    struct TestGroup {
        states: Vec<Option<GroupState>, 10>,
    }

    impl TestGroup {
        fn new(group_id: &[u8], creator_name: &[u8]) -> Self {
            let mut rng = rand::thread_rng();

            let group_id = GroupId::from(Opaque::try_from(group_id).unwrap());

            let (kp_priv, kp) = make_user(&mut rng, creator_name);
            let state = create_group(&mut rng, kp_priv.as_view(), kp.as_view(), group_id).unwrap();

            let mut states = Vec::new();
            states.push(Some(state)).unwrap();
            Self { states }
        }

        fn add(&mut self, committer: usize, joiner_name: &[u8]) {
            let mut rng = rand::thread_rng();

            let (kp_priv, kp) = make_user(&mut rng, joiner_name);
            let op = Operation::Add(kp.clone());

            let committer_prev = self.states[committer].take().unwrap();
            let (committer_next, commit, welcome) =
                send_commit(&mut rng, committer_prev.as_view(), op).unwrap();
            let joiner_next =
                join_group(kp_priv.as_view(), kp.as_view(), welcome.unwrap().as_view()).unwrap();

            // Everyone in the group handles the commit (note that committer is currently None)
            for state in self.states.iter_mut().filter(|s| s.is_some()) {
                let prev = state.take().unwrap();
                let next = handle_commit(prev.as_view(), commit.as_view()).unwrap();
                *state = Some(next);
            }

            // Committer transitions to a new state
            self.states[committer] = Some(committer_next);

            // Insert the joiner at the proper location
            let joiner = match self.states.iter().position(|s| s.is_none()) {
                Some(index) => index,
                None => {
                    self.states.push(None).unwrap();
                    self.states.len() - 1
                }
            };

            self.states[joiner] = Some(joiner_next);
        }

        fn remove(&mut self, committer: usize, removed: usize) {
            let mut rng = rand::thread_rng();

            let op = Operation::Remove(LeafIndex(removed as u32));

            let committer_prev = self.states[committer].take().unwrap();
            let (committer_next, commit, welcome) =
                send_commit(&mut rng, committer_prev.as_view(), op).unwrap();

            // Remove the removed member
            self.states[removed] = None;

            // Everyone in the group handles the commit (note that committer is currently None)
            for state in self.states.iter_mut().filter(|s| s.is_some()) {
                let prev = state.take().unwrap();
                let next = handle_commit(prev.as_view(), commit.as_view()).unwrap();
                *state = Some(next);
            }

            // Committer transitions to a new state
            self.states[committer] = Some(committer_next);
        }

        fn check(&self) {
            let reference = self
                .states
                .iter()
                .find(|s| s.is_some())
                .unwrap()
                .as_ref()
                .unwrap()
                .epoch_authenticator();

            for state in self.states.iter().filter(|s| s.is_some()) {
                assert_eq!(state.as_ref().unwrap().epoch_authenticator(), reference);
            }
        }
    }

    #[test]
    fn test_create_group() {
        let _group = TestGroup::new(b"just alice", b"alice");
    }

    #[test]
    fn test_join_group() {
        let mut group = TestGroup::new(b"alice and bob", b"alice");
        group.add(0, b"bob");
        group.check();
    }

    #[test]
    fn test_three_member_group() {
        let mut group = TestGroup::new(b"alice, bob, carol", b"alice");
        group.add(0, b"bob");
        group.check();

        group.add(1, b"carol");
        group.check();
    }

    #[test]
    fn test_remove() {
        let mut group = TestGroup::new(b"alice, bob, carol", b"alice");
        group.add(0, b"bob");
        group.check();

        group.add(1, b"carol");
        group.check();

        group.remove(2, 0);
        group.check();
    }
}
