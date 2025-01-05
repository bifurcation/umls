#![no_std]
#![allow(dead_code)]
#![allow(unused_variables)]

mod common;
mod crypto;
mod io;
mod protocol;
mod syntax;

use common::*;
use crypto::*;
use protocol::*;

pub fn make_key_package(
    _signature_priv: SignaturePrivateKey,
    _signature_key: SignaturePublicKey,
    _credential: Credential,
) -> Result<(KeyPackagePriv, KeyPackage)> {
    todo!();
}

pub fn create_group(
    _key_package_priv: KeyPackagePrivView,
    _key_package: KeyPackageView,
) -> Result<GroupState> {
    todo!();
}

pub fn join_group(
    _key_package_priv: KeyPackagePrivView,
    _key_package: KeyPackageView,
    _welcome: WelcomeView,
) -> Result<GroupState> {
    todo!();
}

pub fn add_member(
    _group_state: GroupStateView,
    _key_package: KeyPackageView,
) -> Result<(GroupState, PrivateMessage, Welcome)> {
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
