#![no_std]
#![allow(dead_code)]
#![allow(unused_variables)]
#![deny(warnings)] // We should be warnings-clear
#![warn(clippy::pedantic)] // Be pedantic by default

mod group_state;
mod key_schedule;
mod transcript_hash;

pub use group_state::*;
pub use umls_core::protocol::KeyPackage;

#[cfg(all(test, feature = "std_rng"))]
mod test {
    use super::*;

    use umls_core::{
        crypto::Crypto,
        protocol::{self, *},
        stack,
        syntax::Opaque,
    };

    use heapless::Vec;
    use rand::{seq::SliceRandom, Rng, SeedableRng};
    use rand_core::CryptoRngCore;
    use umls_rust_crypto::RustCryptoX25519;

    fn make_user(
        rng: &mut (impl CryptoRngCore + Rng),
        name: &[u8],
    ) -> (
        KeyPackagePriv<RustCryptoX25519>,
        KeyPackage<RustCryptoX25519>,
    ) {
        let (sig_priv, sig_key) = RustCryptoX25519::sig_generate(rng).unwrap();
        let credential = Credential::Basic(BasicCredential(
            Opaque::try_from(b"alice".as_slice()).unwrap(),
        ));
        KeyPackage::new(rng, sig_priv, sig_key, credential).unwrap()
    }

    struct TestGroup {
        states: Vec<Option<GroupState<RustCryptoX25519>>, 10>,
        op_count: u64,
    }

    impl TestGroup {
        fn new(group_id: &[u8], creator_name: &[u8]) -> Self {
            stack::update();
            let mut rng = rand::thread_rng();

            let group_id = GroupId(Opaque::try_from(group_id).unwrap());

            let (kp_priv, kp) = make_user(&mut rng, creator_name);
            let state = GroupState::create(&mut rng, kp_priv, kp, group_id).unwrap();

            let mut states = Vec::new();
            states.push(Some(state)).unwrap();
            Self {
                states,
                op_count: 0,
            }
        }

        fn add(&mut self, committer: usize, joiner_name: &[u8]) -> usize {
            stack::update();
            let mut rng = rand::thread_rng();

            let (kp_priv, kp) = make_user(&mut rng, joiner_name);
            let op = Operation::Add(kp.clone());

            let mut committer_state = self.states[committer].take().unwrap();
            let (commit, welcome) = committer_state.send_commit(&mut rng, op).unwrap();
            let joiner_state = GroupState::join(kp_priv, kp, welcome.unwrap()).unwrap();

            // Everyone in the group handles the commit (note that committer is currently None)
            for state in self.states.iter_mut().filter_map(|s| s.as_mut()) {
                state.handle_commit(commit.clone()).unwrap();
            }

            // Committer transitions to a new state
            self.states[committer] = Some(committer_state);

            // Insert the joiner at the proper location
            let joiner = match self.states.iter().position(|s| s.is_none()) {
                Some(index) => index,
                None => {
                    self.states.push(None).unwrap();
                    self.states.len() - 1
                }
            };

            self.states[joiner] = Some(joiner_state);

            joiner
        }

        fn remove(&mut self, committer: usize, removed: usize) {
            let mut rng = rand::thread_rng();

            let op = Operation::Remove(LeafIndex(removed as u32));

            let mut committer_state = self.states[committer].take().unwrap();
            let (commit, welcome) = committer_state.send_commit(&mut rng, op).unwrap();

            // Remove the removed member
            self.states[removed] = None;

            // Everyone in the group handles the commit (note that committer is currently None)
            for state in self.states.iter_mut().filter_map(|s| s.as_mut()) {
                state.handle_commit(commit.clone()).unwrap();
            }

            // Committer transitions to a new state
            self.states[committer] = Some(committer_state);
        }

        fn random_action(&mut self) {
            self.op_count += 1;
            let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(self.op_count);

            let roll: usize = rng.gen_range(0..protocol::consts::MAX_GROUP_SIZE);

            let members: Vec<usize, { protocol::consts::MAX_GROUP_SIZE }> = self
                .states
                .iter()
                .enumerate()
                .filter(|(i, s)| s.is_some())
                .map(|(i, s)| i)
                .collect();

            if members.contains(&roll) && members.len() != 1 {
                let mut committer = members.choose(&mut rng).unwrap();
                while *committer == roll {
                    committer = members.choose(&mut rng).unwrap();
                }

                self.remove(*committer, roll);
            } else {
                let committer = members.choose(&mut rng).unwrap();
                let joiner = self.add(*committer, b"anonymous");
            }
        }

        fn check(&self) {
            let reference = self
                .states
                .iter()
                .find(|s| s.is_some())
                .unwrap()
                .as_ref()
                .unwrap()
                .epoch_authenticator();

            for state in self.states.iter().filter(|s| s.is_some()) {
                assert_eq!(state.as_ref().unwrap().epoch_authenticator(), reference);
            }
        }
    }

    #[test]
    fn test_create_group() {
        let _group = TestGroup::new(b"just alice", b"alice");
    }

    #[test]
    fn test_join_group() {
        let mut group = TestGroup::new(b"alice and bob", b"alice");
        group.add(0, b"bob");
        group.check();
    }

    #[test]
    fn test_three_member_group() {
        let mut group = TestGroup::new(b"alice, bob, carol", b"alice");
        group.add(0, b"bob");
        group.check();

        group.add(1, b"carol");
        group.check();
    }

    #[test]
    fn test_remove() {
        let mut group = TestGroup::new(b"alice, bob, carol", b"alice");
        group.add(0, b"bob");
        group.check();

        group.add(1, b"carol");
        group.check();

        group.remove(2, 0);
        group.check();
    }

    #[test]
    fn test_large_group() {
        let mut group = TestGroup::new(b"big group", b"alice");

        for i in 1..protocol::consts::MAX_GROUP_SIZE {
            group.add(i - 1, b"bob");
            group.check();
        }
    }

    #[test]
    fn unmerged_leaves() {
        // Create a group of 4 members
        let mut group = TestGroup::new(b"big group", b"alice");

        for i in 1..5 {
            group.add(i - 1, b"bob");
            group.check();
        }

        // Remove members to cerate blanks in the tree (only the outer nodes are filled)
        group.remove(0, 1);
        group.check();

        // Add a new member at position 1.  This sets an unmerged leaf on node 3
        group.add(4, b"carol");
        group.check();

        // Add a new member at position 5.  This requires encrypting to the unmerged leaf.
        group.add(4, b"david");
        group.check();
    }

    #[test]
    fn test_random_ops() {
        const STEPS: usize = 100;

        let mut group = TestGroup::new(b"bizarro world", b"alice");
        for _i in 0..STEPS {
            group.random_action();
            group.check();
        }
    }
}
