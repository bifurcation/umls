use crate::common::*;
use crate::io::*;
use crate::syntax::*;
use crate::{mls_newtype, mls_newtype_opaque};

use core::ops::Deref;

pub mod consts {
    pub const CIPHER_SUITE: [u8; 2] = [0x00, 0x01];

    pub const HASH_OUTPUT_SIZE: usize = 32;

    pub const HPKE_PRIVATE_KEY_SIZE: usize = 32;
    pub const HPKE_PUBLIC_KEY_SIZE: usize = 32;

    pub const SIGNATURE_PRIVATE_KEY_SIZE: usize = 64;
    pub const SIGNATURE_PUBLIC_KEY_SIZE: usize = 32;
    pub const SIGNATURE_SIZE: usize = 64;
}

mls_newtype_opaque! {
    HashOutput + HashOutputView,
    HashOutputData + HashOutputViewData,
    consts::HASH_OUTPUT_SIZE
}

mls_newtype_opaque! {
    HpkePrivateKey + HpkePrivateKeyView,
    HpkePrivateKeyData + HpkePrivateKeyViewData,
    consts::HPKE_PRIVATE_KEY_SIZE
}

mls_newtype_opaque! {
    HpkePublicKey + HpkePublicKeyView,
    HpkePublicKeyData + HpkePublicKeyViewData,
    consts::HPKE_PUBLIC_KEY_SIZE
}

mls_newtype_opaque! {
    SignaturePrivateKey + SignaturePrivateKeyView,
    SignaturePrivateKeyData + SignaturePrivateKeyViewData,
    consts::SIGNATURE_PRIVATE_KEY_SIZE
}

mls_newtype_opaque! {
    SignaturePublicKey + SignaturePublicKeyView,
    SignaturePublicKeyData + SignaturePublicKeyViewData,
    consts::SIGNATURE_PUBLIC_KEY_SIZE
}

mls_newtype_opaque! {
    Signature + SignatureView,
    SignatureData + SignatureViewData,
    consts::SIGNATURE_SIZE
}
