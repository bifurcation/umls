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
    ratchet_tree.add_leaf(key_package.leaf_node.to_owned())?;

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
        my_signature_priv: key_package_priv.signature_priv.to_owned(),
        ..Default::default()
    })
}

pub fn join_group(
    key_package_priv: KeyPackagePrivView,
    key_package: KeyPackageView,
    welcome: WelcomeView,
) -> Result<GroupState> {
    // Verify that the Welcome is for us
    let kp_ref = crypto::hash_ref(b"MLS 1.0 KeyPackage Reference", &key_package.to_owned())?;
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
    let ratchet_tree_extension = group_info
        .extensions
        .iter()
        .find(|ext| ext.extension_type.to_owned() == protocol::consts::EXTENSION_TYPE_RATCHET_TREE);

    let Some(ratchet_tree_extension) = ratchet_tree_extension else {
        return Err(Error("Not implemented"));
    };

    let ratchet_tree_data = ratchet_tree_extension.extension_data;
    let mut ratchet_tree_reader = SliceReader::new(ratchet_tree_data.as_ref());
    let ratchet_tree = RatchetTreeView::deserialize(&mut ratchet_tree_reader)?;
    let ratchet_tree = ratchet_tree.to_owned();

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
        let Some(signer_leaf) = ratchet_tree.leaf_node_at(group_info.signer.to_owned()) else {
            return Err(Error("GroupInfo signer not present in tree"));
        };

        group_info.verify(signer_leaf.signature_key)?;
    }

    // Update the key schedule
    let group_context = group_info.group_context.to_owned();
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
        my_signature_priv: key_package_priv.signature_priv.to_owned(),
    })
}

pub fn add_member(
    rng: &mut (impl Rng + CryptoRngCore),
    group_state: GroupStateView,
    key_package: KeyPackageView,
) -> Result<(GroupState, PrivateMessage, Welcome)> {
    let mut next = group_state.to_owned();

    // Verify the KeyPackage and the LeafNode
    let joiner_signature_key = key_package.tbs.leaf_node.tbs.signature_key;
    key_package.verify(joiner_signature_key)?;
    key_package.tbs.leaf_node.verify(joiner_signature_key)?;

    // Add the new member to the ratchet tree
    next.ratchet_tree
        .add_leaf(key_package.leaf_node.to_owned())?;

    // Form the Commit and the enclosing SignedFramedContent
    let add = Add {
        key_package: key_package.to_owned(),
    };

    let mut commit = Commit::default();
    commit
        .proposals
        .push(ProposalOrRef::Proposal(Proposal::Add(add)))
        .map_err(|_| Error("Too many entries"))?;

    let authenticated_data = PrivateMessageAad::default();
    let framed_content = FramedContent {
        group_id: group_state.group_context.group_id.to_owned(),
        epoch: group_state.group_context.epoch.to_owned(),
        sender: Sender::Member(group_state.my_index.to_owned()),
        authenticated_data: authenticated_data.clone(),
        content: MessageContent::Commit(commit),
    };

    let framed_content_tbs = FramedContentTbs {
        version: protocol::consts::SUPPORTED_VERSION,
        wire_format: protocol::consts::SUPPORTED_WIRE_FORMAT,
        content: framed_content,
        binder: FramedContentBinder::Member(group_state.group_context.to_owned()),
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
    let (generation, key, nonce) = next
        .epoch_secret
        .handshake_key(next.my_index, next.ratchet_tree.size());

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
        next.epoch_secret.sender_data_secret().as_view(),
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
    let new_member = crypto::hash_ref(b"MLS 1.0 KeyPackage Reference", &key_package.to_owned())?;
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
    _group_state: GroupStateView,
    _commit: PrivateMessageView,
) -> Result<GroupState> {
    todo!();
}
