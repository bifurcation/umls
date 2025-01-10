use crate::common::*;
use crate::crypto::{self, *};
use crate::io::*;
use crate::protocol::*;
use crate::syntax::*;
use crate::tree_math::*;
use crate::{make_storage, mls_newtype_opaque, serialize};

use core::ops::{Deref, DerefMut};
use heapless::Vec;

/*
                    epoch_secret[n-1]
                          |
                          |
                          V
                    DeriveSecret(., "init")
                          |
                          |
                          V
                    init_secret_[n-1]
                          |
                          |
                          V
    commit_secret --> KDF.Extract
                          |
                          |
                          V
                  ExpandWithLabel(., "joiner", GroupContext_[n], KDF.Nh)
                          |
                          |
                          V
                     joiner_secret
                          |
                          |
                          V
psk_secret (or 0) --> KDF.Extract
                          |
                          |
                          V
                    member_secret
                          |
                          |
                          +--> DeriveSecret(., "welcome")
                          |    = welcome_secret
                          |
                          V
                  ExpandWithLabel(., "epoch", GroupContext_[n], KDF.Nh)
                          |
                          |
                          V
                     epoch_secret[n]
                          |
                          |
                          +--> DeriveSecret(., <label>)
                               = <secret>

Salient paths through the graph:

epoch + commit + gc --> epoch + joiner + welcome

joiner --> member + welcome

member + gc --> epoch

*/

mls_newtype_opaque! { EpochSecret + EpochSecretView, crypto::consts::HASH_OUTPUT_SIZE }
mls_newtype_opaque! { JoinerSecret + JoinerSecretView, crypto::consts::HASH_OUTPUT_SIZE }
mls_newtype_opaque! { MemberSecret + MemberSecretView, crypto::consts::HASH_OUTPUT_SIZE }
mls_newtype_opaque! { WelcomeSecret + WelcomeSecretView, crypto::consts::HASH_OUTPUT_SIZE }

macro_rules! to_from_hash_output {
    ($owned_type:ident + $view_type:ident) => {
        impl From<$owned_type> for HashOutput {
            fn from(val: $owned_type) -> Self {
                Self::from(val.0)
            }
        }

        impl From<HashOutput> for $owned_type {
            fn from(val: HashOutput) -> Self {
                Self::from(Opaque::from(val))
            }
        }

        impl<'a> From<$view_type<'a>> for HashOutputView<'a> {
            fn from(val: $view_type<'a>) -> Self {
                Self::from(val.0)
            }
        }

        impl<'a> From<HashOutputView<'a>> for $view_type<'a> {
            fn from(val: HashOutputView<'a>) -> Self {
                Self::from(OpaqueView::from(val))
            }
        }
    };
}

to_from_hash_output! { EpochSecret + EpochSecretView }
to_from_hash_output! { JoinerSecret + JoinerSecretView }
to_from_hash_output! { MemberSecret + MemberSecretView }
to_from_hash_output! { WelcomeSecret + WelcomeSecretView }

impl<'a> EpochSecretView<'a> {
    pub fn advance(
        self,
        commit_secret: HashOutputView,
        group_context: &GroupContext,
    ) -> Result<(EpochSecret, JoinerSecret, AeadKey, AeadNonce)> {
        let group_context = serialize!(GroupContext, group_context);

        let joiner_secret = JoinerSecret::new(self, commit_secret, &group_context);
        let member_secret = joiner_secret.as_view().advance();
        let (welcome_key, welcome_nonce) = member_secret.welcome_key_nonce();
        let epoch_secret = member_secret.advance(&group_context);

        Ok((
            epoch_secret.into(),
            joiner_secret.into(),
            welcome_key,
            welcome_nonce,
        ))
    }
}

impl EpochSecret {
    pub fn confirmation_tag(&self, confirmed_transcript_hash: &HashOutput) -> HashOutput {
        let confirmation_key = crypto::derive_secret(self.as_view().into(), b"confirm");

        crypto::hmac(
            confirmation_key.as_ref(),
            confirmed_transcript_hash.as_ref(),
        )
    }

    pub fn epoch_authenticator(&self) -> HashOutput {
        crypto::derive_secret(self.as_view().into(), b"authentication")
    }

    pub fn sender_data_secret(&self) -> HashOutput {
        crypto::derive_secret(self.as_view().into(), b"sender data")
    }

    // XXX(RLB) This can be done immutably because we only ever derive one secret per epoch
    pub fn handshake_key(
        &self,
        index: LeafIndex,
        group_size: LeafCount,
    ) -> (u32, AeadKey, AeadNonce) {
        let mut parent = group_size.root();
        let mut tree_secret = crypto::derive_secret(self.as_view().into(), b"encryption");

        loop {
            let Some(next) = parent.dirpath_child(index) else {
                break;
            };

            let label: &'static [u8] = if next < parent { b"left" } else { b"right" };
            parent = next;
            tree_secret = crypto::expand_with_label(tree_secret.as_view(), b"tree", label);
        }

        let handshake_secret = crypto::expand_with_label(tree_secret.as_view(), b"handshake", &[]);

        let generation = 0;
        let (key, nonce) = crypto::tree_key_nonce(handshake_secret.as_view(), generation);
        (generation, key, nonce)
    }
}

impl JoinerSecret {
    pub fn new(
        epoch_secret: EpochSecretView,
        commit_secret: HashOutputView,
        group_context: &[u8],
    ) -> Self {
        let init_secret = crypto::derive_secret(epoch_secret.into(), b"init");
        let pre_joiner_secret = crypto::extract(init_secret.as_view().into(), commit_secret);
        crypto::expand_with_label(pre_joiner_secret.as_view(), b"joiner", &group_context).into()
    }
}

impl<'a> JoinerSecretView<'a> {
    pub fn advance(self) -> MemberSecret {
        let psk_secret = HashOutput(Opaque::zero());
        crypto::extract(self.into(), psk_secret.as_view()).into()
    }
}

impl MemberSecret {
    pub fn welcome_key_nonce(&self) -> (AeadKey, AeadNonce) {
        let welcome_secret = crypto::derive_secret(self.as_view().into(), b"welcome");
        crypto::welcome_key_nonce(welcome_secret.as_view())
    }

    pub fn advance(&self, group_context: &[u8]) -> EpochSecret {
        crypto::expand_with_label(self.as_view().into(), b"epoch", &group_context).into()
    }
}
