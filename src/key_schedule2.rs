use crate::common::*;
use crate::crypto2::*;
use crate::io::*;
use crate::protocol2::*;
use crate::syntax2::*;
use crate::tree_math2::*;

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

#[derive(Clone, Default, PartialEq, Debug, Serialize, Deserialize)]
pub struct EpochSecret<C: Crypto>(HashOutput<C>);

#[derive(Clone, Default, PartialEq, Debug)]
pub struct MemberSecret<C: Crypto>(HashOutput<C>);

#[derive(Clone, Default, PartialEq, Debug)]
pub struct WelcomeSecret<C: Crypto>(HashOutput<C>);

impl<C: Crypto> EpochSecret<C> {
    pub fn new(rng: &mut (impl Rng + CryptoRngCore)) -> Self {
        // TODO Self(HashOutput(Opaque::random(rng)))
        Self(C::HashOutput::default())
    }

    pub fn advance(
        &mut self,
        commit_secret: &HashOutput<C>,
        group_context: &GroupContext<C>,
    ) -> Result<(JoinerSecret<C>, AeadKey<C>, AeadNonce<C>)> {
        let group_context = group_context.materialize()?;

        let joiner_secret = JoinerSecret::new(&self, commit_secret, &group_context);
        let member_secret = joiner_secret.advance();
        let (welcome_key, welcome_nonce) = member_secret.welcome_key_nonce();
        *self = member_secret.advance(&group_context);

        Ok((joiner_secret.into(), welcome_key, welcome_nonce))
    }

    pub fn confirmation_tag(
        &self,
        confirmed_transcript_hash: &ConfirmedTranscriptHash<C>,
    ) -> HashOutput<C> {
        let confirmation_key = C::derive_secret(&self.0, b"confirm");

        C::hmac(
            confirmation_key.as_ref(),
            confirmed_transcript_hash.0.as_ref(),
        )
    }

    pub fn epoch_authenticator(&self) -> HashOutput<C> {
        C::derive_secret(&self.0, b"authentication")
    }

    pub fn sender_data_secret(&self) -> HashOutput<C> {
        C::derive_secret(&self.0, b"sender data")
    }

    // XXX(RLB) This can be done immutably because we only ever derive one secret per epoch
    pub fn handshake_key(
        &self,
        index: LeafIndex,
        group_size: LeafCount,
    ) -> (Generation, AeadKey<C>, AeadNonce<C>) {
        let mut parent = group_size.root();
        let mut tree_secret = C::derive_secret(&self.0, b"encryption");

        loop {
            let Some(next) = parent.dirpath_child(index) else {
                break;
            };

            let label: &'static [u8] = if next < parent { b"left" } else { b"right" };
            parent = next;
            tree_secret = C::expand_with_label(&tree_secret, b"tree", label);
        }

        let handshake_secret = C::expand_with_label(&tree_secret, b"handshake", &[]);

        let generation = 0;
        let (key, nonce) = C::tree_key_nonce(&handshake_secret, generation);
        (Generation(generation), key, nonce)
    }
}

impl<C: Crypto> JoinerSecret<C> {
    pub fn new(
        epoch_secret: &EpochSecret<C>,
        commit_secret: &HashOutput<C>,
        group_context: &[u8],
    ) -> Self {
        let init_secret = C::derive_secret(&epoch_secret.0, b"init");
        let pre_joiner_secret = C::extract(&init_secret, &commit_secret);
        Self(C::expand_with_label(
            &pre_joiner_secret,
            b"joiner",
            &group_context,
        ))
    }

    pub fn advance(&self) -> MemberSecret<C> {
        // TODO let psk_secret = HashOutput(Opaque::zero());
        let psk_secret = C::HashOutput::default();
        MemberSecret(C::extract(&self.0, &psk_secret))
    }
}

impl<C: Crypto> MemberSecret<C> {
    pub fn welcome_key_nonce(&self) -> (AeadKey<C>, AeadNonce<C>) {
        let welcome_secret = C::derive_secret(&self.0, b"welcome");
        C::welcome_key_nonce(&welcome_secret)
    }

    pub fn advance(&self, group_context: &[u8]) -> EpochSecret<C> {
        EpochSecret(C::expand_with_label(&self.0, b"epoch", &group_context))
    }
}
