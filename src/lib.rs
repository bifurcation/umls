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
use protocol::*;
use syntax::*;
use treekem::*;

use heapless::Vec;
use rand::Rng;

pub fn make_key_package(
    _signature_priv: SignaturePrivateKey,
    _signature_key: SignaturePublicKey,
    _credential: Credential,
) -> Result<(KeyPackagePriv, KeyPackage)> {
    // Trivial
    todo!();
}

pub fn create_group(
    _key_package_priv: KeyPackagePrivView,
    _key_package: KeyPackageView,
) -> Result<GroupState> {
    // Trivial once we know what's in a group
    todo!();
}

pub fn join_group(
    _key_package_priv: KeyPackagePrivView,
    _key_package: KeyPackageView,
    _welcome: WelcomeView,
) -> Result<GroupState> {
    // Trivial once we know what's in a group
    todo!();
}

pub fn add_member(
    rng: &mut impl Rng,
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
    next.group_context.confirmed_transcript_hash = transcript_hash::update_confirmed(
        group_state.interim_transcript_hash,
        &signed_framed_content.content,
        &signed_framed_content.signature,
    )?;

    // Ratchet forward the key schedule
    let commit_secret = HashOutput::zero();
    let (init_secret, key_schedule_epoch) = group_state
        .init_secret
        .advance(commit_secret.as_view(), &next.group_context)?;

    next.init_secret = init_secret;

    // Form the PrivateMessage
    let confirmation_tag =
        key_schedule_epoch.confirmation_tag(&next.group_context.confirmed_transcript_hash);
    let (generation, key, nonce) =
        key_schedule_epoch.handshake_key(next.my_index, next.ratchet_tree.size());

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
        key_schedule_epoch.sender_data_secret().as_view(),
        authenticated_data,
    )?;

    // Form the Welcome
    let group_secrets = GroupSecrets {
        joiner_secret: key_schedule_epoch.joiner_secret,
        path_secret: None,
        psks: Default::default(),
    };

    let encrypted_group_secrets =
        HpkeEncryptedGroupSecrets::seal(group_secrets, key_package.init_key, &[])?;
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
    let (welcome_key, welcome_nonce) =
        crypto::derive_welcome_key_nonce(key_schedule_epoch.welcome_secret.as_view());
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
