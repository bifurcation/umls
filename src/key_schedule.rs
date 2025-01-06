use crate::common::*;
use crate::crypto::{self, *};
use crate::protocol::*;
use crate::syntax::*;
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

struct InitSecret(HashOutput);
struct InitSecretView<'a>(HashOutputView<'a>);

struct EpochSecret(HashOutput);
struct EpochSecretView<'a>(HashOutputView<'a>);

struct KeyScheduleEpoch {
    joiner_secret: HashOutput,
    welcome_secret: HashOutput,
    epoch_secret: EpochSecret,
}

impl<'a> InitSecretView<'a> {
    fn advance(
        self,
        commit_secret: HashOutputView,
        group_context: &GroupContext,
    ) -> Result<(InitSecret, KeyScheduleEpoch)> {
        let group_context = serialize!(GroupContext, group_context);

        let pre_joiner_secret = crypto::extract(self.0, commit_secret);
        let joiner_secret =
            crypto::expand_with_label(pre_joiner_secret.as_view(), b"joiner", &group_context);

        let psk_secret = {
            let mut psk_secret = HashOutput::default();
            let capacity = psk_secret.0.capacity();
            psk_secret
                .0
                .resize_default(capacity)
                .map_err(|_| Error("Resize error"))?;
            psk_secret
        };
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
