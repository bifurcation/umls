use umls::{crypto::*, group_state::*, protocol::*, syntax::*};

use tabled::{settings::style::Style, Table, Tabled};

#[derive(Tabled)]
struct TypeInfo {
    name: &'static str,
    in_memory_size: usize,
    serialized_size: usize,
}

fn type_info<T: Serialize>() -> TypeInfo {
    TypeInfo {
        name: std::any::type_name::<T>(),
        in_memory_size: std::mem::size_of::<T>(),
        serialized_size: T::MAX_SIZE,
    }
}

fn main() {
    let data = vec![
        type_info::<SignaturePrivateKey>(),
        type_info::<SignaturePublicKey>(),
        type_info::<Credential>(),
        type_info::<KeyPackagePriv>(),
        type_info::<KeyPackage>(),
        type_info::<GroupId>(),
        type_info::<GroupState>(),
        type_info::<Welcome>(),
        type_info::<PrivateMessage>(),
    ];

    let mut table = Table::new(&data);
    table.with(Style::modern());

    println!("{}", table);
}
