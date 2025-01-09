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
use rand::{Fill, Rng};
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
    let mut epoch_secret = EpochSecret::default();
    epoch_secret
        .0
        .resize_default(crypto::consts::HASH_OUTPUT_SIZE)
        .unwrap();
    epoch_secret.as_mut().try_fill(rng).unwrap();

    // Set the group context
    let group_context = GroupContext {
        version: protocol::consts::SUPPORTED_VERSION,
        cipher_suite: crypto::consts::CIPHER_SUITE,
        group_id,
        epoch: Epoch(0),
        tree_hash: ratchet_tree.root_hash(),
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

    let tree_hash = ratchet_tree.root_hash();
    if tree_hash.as_view() != group_info.group_context.tree_hash {
        return Err(Error("Invalid ratchet tree"));
    }

    // Find our own leaf in the ratchet tree
    let Some(my_index) = ratchet_tree.find(key_package.leaf_node.clone()) else {
        return Err(Error("Joiner not present in tree"));
    };

    // Verify the signature on the GroupInfo
    {
        // Scoped to bound the lifetime of signer_leaf
        let Some(signer_leaf) = ratchet_tree.leaf_node_at(group_info.signer.to_object()) else {
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

    // Import the data into a GroupState
    Ok(GroupState {
        ratchet_tree,
        group_context,
        interim_transcript_hash,
        epoch_secret,
        my_index,
        my_signature_priv: key_package_priv.signature_priv.to_object(),
    })
}

pub fn add_member(
    rng: &mut (impl Rng + CryptoRngCore),
    group_state: GroupStateView,
    key_package: KeyPackageView,
) -> Result<(GroupState, PrivateMessage, Welcome)> {
    let mut next = group_state.to_object();

    // Verify the KeyPackage and the LeafNode
    let joiner_signature_key = key_package.tbs.leaf_node.tbs.signature_key;
    key_package.verify(joiner_signature_key)?;
    key_package.tbs.leaf_node.verify(joiner_signature_key)?;

    // Add the new member to the ratchet tree
    next.ratchet_tree
        .add_leaf(key_package.leaf_node.to_object())?;

    // Form the Commit and the enclosing SignedFramedContent
    let add = Add {
        key_package: key_package.to_object(),
    };

    let mut commit = Commit::default();
    commit
        .proposals
        .push(ProposalOrRef::Proposal(Proposal::Add(add)))
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

    // Update the GroupContext
    next.group_context.epoch.0 += 1;
    next.group_context.tree_hash = next.ratchet_tree.root_hash();
    next.group_context.confirmed_transcript_hash = transcript_hash::confirmed(
        group_state.interim_transcript_hash,
        &signed_framed_content.content,
        &signed_framed_content.signature,
    )?;

    // Ratchet forward the key schedule
    let commit_secret = HashOutput::zero();
    let (epoch_secret, joiner_secret, welcome_key, welcome_nonce) = group_state
        .epoch_secret
        .advance(commit_secret.as_view(), &next.group_context)?;

    next.epoch_secret = epoch_secret;

    // Form the PrivateMessage
    let confirmation_tag = next
        .epoch_secret
        .confirmation_tag(&next.group_context.confirmed_transcript_hash);
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

    // Form the Welcome
    let group_secrets = GroupSecrets {
        joiner_secret,
        path_secret: None,
        psks: Default::default(),
    };

    let encrypted_group_secrets =
        HpkeEncryptedGroupSecrets::seal(rng, group_secrets, key_package.init_key, &[])?;
    let new_member = crypto::hash_ref(b"MLS 1.0 KeyPackage Reference", &key_package.to_object())?;
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

    let welcome = Welcome {
        cipher_suite: crypto::consts::CIPHER_SUITE,
        secrets,
        encrypted_group_info,
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
        Proposal::Add(add) => next
            .ratchet_tree
            .add_leaf(add.key_package.leaf_node.clone())?,
        Proposal::Remove(remove) => todo!(),
    }

    // Update the GroupContext
    next.group_context.epoch.0 += 1;
    next.group_context.tree_hash = next.ratchet_tree.root_hash();
    next.group_context.confirmed_transcript_hash = transcript_hash::confirmed(
        group_state.interim_transcript_hash,
        &signed_framed_content.content,
        &signed_framed_content.signature,
    )?;

    // Ratchet forward the key schedule
    let commit_secret = HashOutput::zero();
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

    Ok(next)
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_create_group() {
        let mut rng = rand::thread_rng();

        // Create initial state
        let (sig_priv, sig_key) = crypto::generate_sig(&mut rng).unwrap();
        let credential = Credential::from(b"alice".as_slice());
        let group_id = GroupId::from(Opaque::try_from(b"just alice".as_slice()).unwrap());

        // Initialize the group
        let (kp_priv, kp) = make_key_package(&mut rng, sig_priv, sig_key, credential).unwrap();
        let _state_a0 = create_group(&mut rng, kp_priv.as_view(), kp.as_view(), group_id).unwrap();
    }

    #[test]
    fn test_join_group() {
        let mut rng = rand::thread_rng();

        // Create initial state
        let (sig_priv_a, sig_key_a) = crypto::generate_sig(&mut rng).unwrap();
        let credential_a = Credential::from(b"alice".as_slice());

        let (sig_priv_b, sig_key_b) = crypto::generate_sig(&mut rng).unwrap();
        let credential_b = Credential::from(b"bob".as_slice());

        let group_id = GroupId::from(Opaque::try_from(b"alice and bob".as_slice()).unwrap());

        // Create key packages
        let (kp_priv_a, kp_a) =
            make_key_package(&mut rng, sig_priv_a, sig_key_a, credential_a).unwrap();
        let (kp_priv_b, kp_b) =
            make_key_package(&mut rng, sig_priv_b, sig_key_b, credential_b).unwrap();

        // Initialize the group
        let state_a0 =
            create_group(&mut rng, kp_priv_a.as_view(), kp_a.as_view(), group_id).unwrap();

        // Add the second member
        let (state_a1, _commit_a1, welcome_1) =
            add_member(&mut rng, state_a0.as_view(), kp_b.as_view()).unwrap();

        let state_b1 =
            join_group(kp_priv_b.as_view(), kp_b.as_view(), welcome_1.as_view()).unwrap();

        assert!(state_a1.epoch_authenticator() == state_b1.epoch_authenticator());
    }

    #[test]
    fn test_three_member_group() {
        let mut rng = rand::thread_rng();

        // Create initial state
        let (sig_priv_a, sig_key_a) = crypto::generate_sig(&mut rng).unwrap();
        let credential_a = Credential::from(b"alice".as_slice());

        let (sig_priv_b, sig_key_b) = crypto::generate_sig(&mut rng).unwrap();
        let credential_b = Credential::from(b"bob".as_slice());

        let (sig_priv_c, sig_key_c) = crypto::generate_sig(&mut rng).unwrap();
        let credential_c = Credential::from(b"bob".as_slice());

        let group_id = GroupId::from(Opaque::try_from(b"alice, bob, carol".as_slice()).unwrap());

        // Create key packages
        let (kp_priv_a, kp_a) =
            make_key_package(&mut rng, sig_priv_a, sig_key_a, credential_a).unwrap();
        let (kp_priv_b, kp_b) =
            make_key_package(&mut rng, sig_priv_b, sig_key_b, credential_b).unwrap();
        let (kp_priv_c, kp_c) =
            make_key_package(&mut rng, sig_priv_c, sig_key_c, credential_c).unwrap();

        // Initialize the group
        let state_a0 =
            create_group(&mut rng, kp_priv_a.as_view(), kp_a.as_view(), group_id).unwrap();

        // Add the second member
        let (state_a1, _commit_1, welcome_1) =
            add_member(&mut rng, state_a0.as_view(), kp_b.as_view()).unwrap();

        let state_b1 =
            join_group(kp_priv_b.as_view(), kp_b.as_view(), welcome_1.as_view()).unwrap();

        assert!(state_a1.epoch_authenticator() == state_b1.epoch_authenticator());

        // Add the third member
        let (state_b2, commit_2, welcome_2) =
            add_member(&mut rng, state_b1.as_view(), kp_c.as_view()).unwrap();

        let state_c2 =
            join_group(kp_priv_c.as_view(), kp_c.as_view(), welcome_2.as_view()).unwrap();

        let state_a2 = handle_commit(state_a1.as_view(), commit_2.as_view()).unwrap();

        assert!(state_b2.epoch_authenticator() == state_a2.epoch_authenticator());
        assert!(state_b2.epoch_authenticator() == state_c2.epoch_authenticator());
    }
}
