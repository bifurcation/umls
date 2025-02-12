use umls::*;
use umls_core::{crypto::*, protocol::*, syntax::*, treekem::*};

use tabled::{settings::style::Style, Table, Tabled};

#[cfg(not(feature = "null-crypto"))]
use umls_rust_crypto::RustCryptoP256 as CryptoProvider;

#[cfg(feature = "null-crypto")]
use umls_core::crypto::null::NullCrypto as CryptoProvider;

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
        type_info::<SignaturePrivateKey<CryptoProvider>>(),
        type_info::<SignaturePublicKey<CryptoProvider>>(),
        type_info::<Credential>(),
        type_info::<LeafNode<CryptoProvider>>(),
        type_info::<KeyPackagePriv<CryptoProvider>>(),
        type_info::<KeyPackage<CryptoProvider>>(),
        type_info::<GroupId>(),
        type_info::<RatchetTree<CryptoProvider>>(),
        type_info::<GroupState<CryptoProvider>>(),
        type_info::<Welcome<CryptoProvider>>(),
        type_info::<PrivateMessage<CryptoProvider>>(),
    ];

    let mut table = Table::new(&data);
    table.with(Style::modern());

    println!("{}", table);
}
