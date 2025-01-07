use crate::common::*;
use crate::crypto::{self, *};
use crate::io::*;
use crate::protocol::*;
use crate::syntax::*;
use crate::tree_math::*;
use crate::{make_storage, serialize};

use heapless::Vec;

/*
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
                     epoch_secret
                          |
                          |
                          +--> DeriveSecret(., <label>)
                          |    = <secret>
                          |
                          V
                    DeriveSecret(., "init")
                          |
                          |
                          V
                    init_secret_[n]
*/

#[derive(Clone, Default, PartialEq, Debug)]
pub struct InitSecret(HashOutput);

impl Serialize for InitSecret {
    const MAX_SIZE: usize = HashOutput::MAX_SIZE;

    fn serialize(&self, writer: &mut impl Write) -> Result<()> {
        self.0.serialize(writer)
    }
}

impl AsView for InitSecret {
    type View<'a> = InitSecretView<'a>;

    fn as_view<'a>(&'a self) -> Self::View<'a> {
        InitSecretView(self.0.as_view())
    }
}

#[derive(Clone, PartialEq, Debug)]
pub struct InitSecretView<'a>(HashOutputView<'a>);

impl<'a> Deserialize<'a> for InitSecretView<'a> {
    fn deserialize(reader: &mut impl ReadRef<'a>) -> Result<Self> {
        Ok(Self(HashOutputView::deserialize(reader)?))
    }
}

impl<'a> ToOwned for InitSecretView<'a> {
    type Owned = InitSecret;

    fn to_owned(&self) -> Self::Owned {
        InitSecret(self.0.to_owned())
    }
}

pub struct EpochSecret(HashOutput);
pub struct EpochSecretView<'a>(HashOutputView<'a>);

pub struct KeyScheduleEpoch {
    pub joiner_secret: HashOutput,
    pub welcome_secret: HashOutput,
    epoch_secret: EpochSecret,
}

impl<'a> InitSecretView<'a> {
    pub fn advance(
        self,
        commit_secret: HashOutputView,
        group_context: &GroupContext,
    ) -> Result<(InitSecret, KeyScheduleEpoch)> {
        let group_context = serialize!(GroupContext, group_context);

        let pre_joiner_secret = crypto::extract(self.0, commit_secret);
        let joiner_secret =
            crypto::expand_with_label(pre_joiner_secret.as_view(), b"joiner", &group_context);

        let psk_secret = HashOutput::zero();
        let member_secret = crypto::extract(joiner_secret.as_view(), psk_secret.as_view());

        let welcome_secret = crypto::derive_secret(member_secret.as_view(), b"welcome");

        let epoch_secret =
            crypto::expand_with_label(member_secret.as_view(), b"epoch", &group_context);

        let init_secret = InitSecret(crypto::derive_secret(epoch_secret.as_view(), b"init"));

        let epoch = KeyScheduleEpoch {
            joiner_secret,
            welcome_secret,
            epoch_secret: EpochSecret(epoch_secret),
        };

        Ok((init_secret, epoch))
    }
}

impl KeyScheduleEpoch {
    pub fn confirmation_tag(&self, confirmed_transcript_hash: &HashOutput) -> HashOutput {
        let confirmation_key = crypto::derive_secret(self.epoch_secret.0.as_view(), b"confirm");
        crypto::hmac(
            confirmation_key.as_ref(),
            confirmed_transcript_hash.as_ref(),
        )
    }

    pub fn sender_data_secret(&self) -> HashOutput {
        crypto::derive_secret(self.epoch_secret.0.as_view(), b"sender data")
    }

    // XXX(RLB) This can be done immutably because we only ever derive one secret per epoch
    pub fn handshake_key(&self, index: LeafIndex, group_size: usize) -> (u32, AeadKey, AeadNonce) {
        let leaf = 2 * index.0 as usize;
        let mut parent = root(group_size);
        let mut tree_secret = crypto::derive_secret(self.epoch_secret.0.as_view(), b"encryption");

        loop {
            let Some(next) = step_towards(parent, leaf) else {
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
