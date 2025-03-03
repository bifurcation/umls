#[cfg(not(all(feature = "stack", feature = "thread_rng")))]
fn main() {}

#[cfg(all(feature = "stack", feature = "thread_rng"))]
fn main() {
    use umls::*;
    use umls_core::protocol::consts;
    use umls_core::{crypto::*, protocol::*, stack, syntax::*};

    #[cfg(feature = "null-crypto")]
    use umls_core::crypto::null::NullCrypto as CryptoProvider;

    #[cfg(not(feature = "null-crypto"))]
    use umls_rust_crypto::RustCryptoX25519 as CryptoProvider;

    #[no_mangle]
    fn join_group(
        kp_priv: KeyPackagePriv<CryptoProvider>,
        kp: &KeyPackage<CryptoProvider>,
        welcome: Welcome<CryptoProvider>,
    ) -> GroupState<CryptoProvider> {
        GroupState::join(kp_priv, kp, welcome).unwrap()
    }

    let mut rng = rand::rng();

    // Create the first user
    let (sig_priv, sig_key) = CryptoProvider::sig_generate(&mut rng).unwrap();
    let credential = Credential::Basic(BasicCredential(
        Opaque::try_from(b"alice".as_slice()).unwrap(),
    ));
    let ((kp_priv, kp), make_key_package_0_stack) =
        stack::usage(|| umls::KeyPackage::create(&mut rng, sig_priv, sig_key, credential).unwrap());

    // Create the group
    let group_id = GroupId(Opaque::try_from(b"group_id".as_slice()).unwrap());
    let (mut state_a, create_group_stack) = stack::usage(|| {
        GroupState::<CryptoProvider>::create(&mut rng, kp_priv, kp, group_id).unwrap()
    });

    // Create the second user
    let (sig_priv, sig_key) = CryptoProvider::sig_generate(&mut rng).unwrap();
    let credential = Credential::Basic(BasicCredential(
        Opaque::try_from(b"bob".as_slice()).unwrap(),
    ));
    let ((kp_priv, kp), make_key_package_1_stack) =
        stack::usage(|| umls::KeyPackage::create(&mut rng, sig_priv, sig_key, credential).unwrap());

    // Add the second user to the group
    let op = Operation::Add(kp.clone());
    let ((_commit_1, welcome_1), send_commit_1_stack) =
        stack::usage(|| state_a.send_commit(&mut rng, op).unwrap());

    // Second user joins the group
    let mut state_b = join_group(kp_priv, &kp, welcome_1.unwrap());
    let join_group_1_stack = 0;

    /*
    let (mut state_b, join_group_1_stack) =
        stack::usage(|| GroupState::join(kp_priv, &kp, welcome_1.unwrap()).unwrap());
    */

    println!("make_key_package_0: {:8}", make_key_package_0_stack);
    println!("create_group:       {:8}", create_group_stack);
    println!("===");
    println!("make_key_package_1: {:8}", make_key_package_1_stack);
    println!("send_commit_1:      {:8}", send_commit_1_stack);
    println!("join_group_1:       {:8}", join_group_1_stack);

    if consts::MAX_GROUP_SIZE > 2 {
        // Create the third user
        let (sig_priv, sig_key) = CryptoProvider::sig_generate(&mut rng).unwrap();
        let credential = Credential::Basic(BasicCredential(
            Opaque::try_from(b"carol".as_slice()).unwrap(),
        ));
        let ((kp_priv, kp), make_key_package_2_stack) = stack::usage(|| {
            umls::KeyPackage::create(&mut rng, sig_priv, sig_key, credential).unwrap()
        });

        // Add the third user to the group
        let op = Operation::Add(kp.clone());
        let ((commit_2, welcome_2), send_commit_2_stack) =
            stack::usage(|| state_b.send_commit(&mut rng, op).unwrap());

        // Second user joins the group
        let (_state_c, join_group_2_stack) =
            stack::usage(|| GroupState::join(kp_priv, &kp, welcome_2.unwrap()).unwrap());

        // Other member handles the commit
        let ((), handle_commit_2_stack) = stack::usage(|| state_a.handle_commit(commit_2).unwrap());

        println!("===");
        println!("make_key_package_2: {:8}", make_key_package_2_stack);
        println!("send_commit_2:      {:8}", send_commit_2_stack);
        println!("join_group_2:       {:8}", join_group_2_stack);
        println!("handle_commit_2:    {:8}", handle_commit_2_stack);
    }
}
