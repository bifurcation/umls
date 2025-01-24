use umls::group_state::*;
use umls_core::{crypto::*, protocol::*, syntax::*};
use umls_rust_crypto::RustCryptoX25519 as Crypto;

use tabled::{settings::style::Style, Table, Tabled};

#[derive(Tabled)]
struct TypeInfo {
    name: &'static str,
    in_memory_size: usize,
    serialized_size: usize,
}

fn type_info<T: Serialize>() -> TypeInfo {
    let name = std::any::type_name::<T>()
        .split("<")
        .next()
        .unwrap()
        .split("::")
        .last()
        .unwrap();

    TypeInfo {
        name,
        in_memory_size: std::mem::size_of::<T>(),
        serialized_size: T::MAX_SIZE,
    }
}

fn main() {
    let data = vec![
        type_info::<SignaturePrivateKey<Crypto>>(),
        type_info::<SignaturePublicKey<Crypto>>(),
        type_info::<Credential>(),
        type_info::<LeafNode<Crypto>>(),
        type_info::<KeyPackagePriv<Crypto>>(),
        type_info::<KeyPackage<Crypto>>(),
        type_info::<GroupId>(),
        type_info::<GroupState<Crypto>>(),
        type_info::<Welcome<Crypto>>(),
        type_info::<PrivateMessage<Crypto>>(),
    ];

    let mut table = Table::new(&data);
    table.with(Style::modern());

    println!("{}", table);
}
