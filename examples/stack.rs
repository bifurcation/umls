use umls::{crypto, group_state::*, protocol::*, stack::stack_usage, syntax::*, Operation};

fn main() {
    let mut rng = rand::thread_rng();

    // Create the first user
    let (sig_priv, sig_key) = crypto::generate_sig(&mut rng).unwrap();
    let credential = Credential::from(b"creator".as_slice());
    let ((kp_priv, kp), make_key_package_0_stack) =
        stack_usage(|| umls::make_key_package(&mut rng, sig_priv, sig_key, credential).unwrap());

    // Create the group
    let group_id = GroupId::from(Opaque::try_from(b"group_id".as_slice()).unwrap());
    let (mut state_a, create_group_stack) = stack_usage(|| {
        umls::create_group(&mut rng, kp_priv.as_view(), kp.as_view(), group_id).unwrap()
    });

    // Create the second user
    let (sig_priv, sig_key) = crypto::generate_sig(&mut rng).unwrap();
    let credential = Credential::from(b"creator".as_slice());
    let ((kp_priv, kp), make_key_package_1_stack) =
        stack_usage(|| umls::make_key_package(&mut rng, sig_priv, sig_key, credential).unwrap());

    // Add the second user to the group
    let op = Operation::Add(kp.clone());
    let ((_commit_1, welcome_1), send_commit_1_stack) =
        stack_usage(|| umls::send_commit(&mut rng, &mut state_a, op).unwrap());

    // Second user joins the group
    let (mut state_b, join_group_1_stack) = stack_usage(|| {
        umls::join_group(
            kp_priv.as_view(),
            kp.as_view(),
            welcome_1.unwrap().as_view(),
        )
        .unwrap()
    });

    println!("make_key_package_0: {:8}", make_key_package_0_stack);
    println!("create_group:       {:8}", create_group_stack);
    println!("===");
    println!("make_key_package_1: {:8}", make_key_package_1_stack);
    println!("send_commit_1:      {:8}", send_commit_1_stack);
    println!("join_group_1:       {:8}", join_group_1_stack);

    if umls::protocol::consts::MAX_GROUP_SIZE > 2 {
        // Create the third user
        let (sig_priv, sig_key) = crypto::generate_sig(&mut rng).unwrap();
        let credential = Credential::from(b"creator".as_slice());
        let ((kp_priv, kp), make_key_package_2_stack) = stack_usage(|| {
            umls::make_key_package(&mut rng, sig_priv, sig_key, credential).unwrap()
        });

        // Add the third user to the group
        let op = Operation::Add(kp.clone());
        let ((commit_2, welcome_2), send_commit_2_stack) =
            stack_usage(|| umls::send_commit(&mut rng, &mut state_b, op).unwrap());

        // Second user joins the group
        let (state_c, join_group_2_stack) = stack_usage(|| {
            umls::join_group(
                kp_priv.as_view(),
                kp.as_view(),
                welcome_2.unwrap().as_view(),
            )
            .unwrap()
        });

        // Other member handles the commit
        let ((), handle_commit_2_stack) =
            stack_usage(|| umls::handle_commit(&mut state_a, commit_2.as_view()).unwrap());

        println!("===");
        println!("make_key_package_2: {:8}", make_key_package_2_stack);
        println!("send_commit_2:      {:8}", send_commit_2_stack);
        println!("join_group_2:       {:8}", join_group_2_stack);
        println!("handle_commit_2:    {:8}", handle_commit_2_stack);
    }
}
