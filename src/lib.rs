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

use common::*;
use crypto::*;
use group_state::*;
use protocol::*;

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
    _group_state: GroupStateView,
    _key_package: KeyPackageView,
) -> Result<(GroupState, PrivateMessage, Welcome)> {
    // Update ratchet tree
    //
    // commit_secret = 0
    // psk_secret = 0
    // path = empty
    //
    // Commit = { proposals = Add{kp}, path = None }
    // Construct and sign FramedContent
    //
    // Update confirmed transcript hash
    // Update key schedule
    // Compute confirmation tag
    //
    // Assemble PrivateMessage
    // Assemble Welcome

    todo!();
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
