use crate::common::*;
use crate::crypto::{self, *};
use crate::io::*;
use crate::protocol::*;
use crate::stack::*;
use crate::syntax::*;
use crate::tree_math::*;
use crate::{make_storage, serialize, stack_ptr, tick};

use heapless::Vec;
use rand::Rng;
use rand_core::CryptoRngCore;

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

#[derive(Clone, Default, PartialEq, Debug)]
pub struct EpochSecret(HashOutput);

#[derive(Clone, Default, PartialEq, Debug)]
pub struct JoinerSecret(HashOutput);

#[derive(Clone, Default, PartialEq, Debug)]
pub struct MemberSecret(HashOutput);

#[derive(Clone, Default, PartialEq, Debug)]
pub struct WelcomeSecret(HashOutput);

impl Serialize for EpochSecret {
    const MAX_SIZE: usize = HashOutput::MAX_SIZE;

    fn serialize(&self, writer: &mut impl Write) -> Result<()> {
        self.0.serialize(writer)
    }
}

impl<'a> Deserialize<'a> for EpochSecret {
    fn deserialize(reader: &mut impl ReadRef<'a>) -> Result<Self> {
        Ok(Self(HashOutput::deserialize(reader)?))
    }
}

impl Serialize for JoinerSecret {
    const MAX_SIZE: usize = HashOutput::MAX_SIZE;

    fn serialize(&self, writer: &mut impl Write) -> Result<()> {
        self.0.serialize(writer)
    }
}

impl<'a> Deserialize<'a> for JoinerSecret {
    fn deserialize(reader: &mut impl ReadRef<'a>) -> Result<Self> {
        Ok(Self(HashOutput::deserialize(reader)?))
    }
}

impl EpochSecret {
    pub fn new(rng: &mut (impl Rng + CryptoRngCore)) -> Self {
        Self(HashOutput(Opaque::random(rng)))
    }

    pub fn advance(
        &mut self,
        commit_secret: &HashOutput,
        group_context: &GroupContext,
    ) -> Result<(JoinerSecret, AeadKey, AeadNonce)> {
        tick!();
        let group_context = serialize!(GroupContext, group_context);

        let joiner_secret = JoinerSecret::new(&self, commit_secret, &group_context);
        let member_secret = joiner_secret.advance();
        let (welcome_key, welcome_nonce) = member_secret.welcome_key_nonce();
        *self = member_secret.advance(&group_context);

        Ok((joiner_secret.into(), welcome_key, welcome_nonce))
    }

    pub fn confirmation_tag(&self, confirmed_transcript_hash: &HashOutput) -> HashOutput {
        tick!();
        let confirmation_key = crypto::derive_secret(&self.0, b"confirm");

        crypto::hmac(
            confirmation_key.as_ref(),
            confirmed_transcript_hash.as_ref(),
        )
    }

    pub fn epoch_authenticator(&self) -> HashOutput {
        tick!();
        crypto::derive_secret(&self.0, b"authentication")
    }

    pub fn sender_data_secret(&self) -> HashOutput {
        tick!();
        crypto::derive_secret(&self.0, b"sender data")
    }

    // XXX(RLB) This can be done immutably because we only ever derive one secret per epoch
    pub fn handshake_key(
        &self,
        index: LeafIndex,
        group_size: LeafCount,
    ) -> (u32, AeadKey, AeadNonce) {
        tick!();
        let mut parent = group_size.root();
        let mut tree_secret = crypto::derive_secret(&self.0, b"encryption");

        loop {
            let Some(next) = parent.dirpath_child(index) else {
                break;
            };

            let label: &'static [u8] = if next < parent { b"left" } else { b"right" };
            parent = next;
            tree_secret = crypto::expand_with_label(&tree_secret, b"tree", label);
        }

        let handshake_secret = crypto::expand_with_label(&tree_secret, b"handshake", &[]);

        let generation = 0;
        let (key, nonce) = crypto::tree_key_nonce(&handshake_secret, generation);
        (generation, key, nonce)
    }
}

impl JoinerSecret {
    pub fn new(
        epoch_secret: &EpochSecret,
        commit_secret: &HashOutput,
        group_context: &[u8],
    ) -> Self {
        tick!();
        let init_secret = crypto::derive_secret(&epoch_secret.0, b"init");
        let pre_joiner_secret = crypto::extract(&init_secret, &commit_secret);
        Self(crypto::expand_with_label(
            &pre_joiner_secret,
            b"joiner",
            &group_context,
        ))
    }

    pub fn advance(&self) -> MemberSecret {
        tick!();
        let psk_secret = HashOutput(Opaque::zero());
        MemberSecret(crypto::extract(&self.0, &psk_secret))
    }
}

impl MemberSecret {
    pub fn welcome_key_nonce(&self) -> (AeadKey, AeadNonce) {
        tick!();
        let welcome_secret = crypto::derive_secret(&self.0, b"welcome");
        crypto::welcome_key_nonce(&welcome_secret)
    }

    pub fn advance(&self, group_context: &[u8]) -> EpochSecret {
        tick!();
        EpochSecret(crypto::expand_with_label(&self.0, b"epoch", &group_context))
    }
}
