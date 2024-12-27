//#![no_std]
#![allow(dead_code)]
#![allow(unused_variables)]

mod common {
    use heapless::Vec;

    // XXX(RLB) These hold strings for the moment; we can clean them up and turn them into enums later.
    #[derive(Debug)]
    pub struct WriteError(pub &'static str);

    #[derive(Debug)]
    pub struct ReadError(pub &'static str);

    /// XXX(RLB) The `Write` trait isn't available in `core::io` for some rather silly reasons [1].  We
    /// define its equivalent here to allow for some flexibility (e.g., &[u8] vs.  Vec<u8, N>) and
    /// avoid a bunch of repetition below.
    ///
    /// [1] https://github.com/rust-lang/rust/issues/68315
    pub trait Write {
        fn write(&mut self, buf: &[u8]) -> Result<usize, WriteError>;

        /// Same as Write, but returns an error if we were unable to write the whole buffer.
        fn write_all(&mut self, buf: &[u8]) -> Result<(), WriteError> {
            let n = self.write(buf)?;
            (n == buf.len())
                .then_some(())
                .ok_or(WriteError("Insufficient data"))
        }
    }

    impl Write for &mut [u8] {
        // https://doc.rust-lang.org/src/std/io/impls.rs.html#366-374
        #[inline]
        fn write(&mut self, data: &[u8]) -> Result<usize, WriteError> {
            let amt = core::cmp::min(data.len(), self.len());
            let (a, b) = core::mem::take(self).split_at_mut(amt);
            a.copy_from_slice(&data[..amt]);
            *self = b;
            Ok(amt)
        }
    }

    /// A reader trait returns a reference to memory owned by the reader, with the specified
    /// lifetime.
    pub trait RefRead<'a> {
        /// Returns a reference to the first `n` bytes read.  Returns an error if less than `n` bytes
        /// are available.
        fn read(&mut self, n: usize) -> Result<&'a [u8], ReadError>;

        /// Returns a copy of the first byte available.  Returns n error if the reader is empty.
        fn peek(&self) -> Result<u8, ReadError>;
    }

    impl<'a> RefRead<'a> for &'a [u8] {
        #[inline]
        fn read(&mut self, n: usize) -> Result<&'a [u8], ReadError> {
            if self.len() < n {
                return Err(ReadError("Insufficient data"));
            } else {
                let (data, rest) = self.split_at(n);
                *self = rest;
                Ok(data)
            }
        }

        fn peek(&self) -> Result<u8, ReadError> {
            if self.is_empty() {
                Err(ReadError("Insufficient data"))
            } else {
                Ok(self[0])
            }
        }
    }

    /// A type that implements `ProtocolObject` is an owned representation of the object.  The trait
    /// says nothing about how the object is constructed (aside from requiring `Default`), but requires
    /// the type to be convertible to bytes, and to the non-owned `ProtocolObjectView` representation
    /// of the same object.  The idea is that types implementing this trait are used to construct new
    /// objects, which are then serialized for the application to use.
    pub trait ProtocolObject: Default {
        /// The maximum encoded size of this object.
        const MAX_SIZE: usize;

        /// The non-owned version of this type
        type View<'a>: ProtocolObjectView<'a>
        where
            Self: 'a;

        /// Get a view that references an instance of this type
        fn as_view<'a>(&'a self) -> Self::View<'a>;

        /// Serialize an object to a byte slice.
        // XXX(RLB) It would be nice to have the `data` argument have type `&mut impl Write`.  But the
        // `Write` trait isn't available in `core::io`.
        // https://github.com/rust-lang/rust/issues/68315
        fn write_to(&self, writer: &mut impl Write) -> Result<(), WriteError>;
    }

    /// A type that implements `ProtocolObjectView` is a non-owned representation of the object.  The
    /// bytes comprising the content of an object are held elsewhere.  (Thus, implementations of this
    /// trait will typically be lifetime-bound.)
    pub trait ProtocolObjectView<'a>: Sized {
        /// The maximum encoded size of this object.  Implementations should not override this
        /// constant, since it will make them inconsistent with the corresponding ProtocolObject.
        const MAX_SIZE: usize = Self::Owned::MAX_SIZE;

        /// The owned version of this type
        type Owned: ProtocolObject;

        /// Copy this object into a new owned object of this type
        fn copy_to_owned(&self) -> Self::Owned;

        /// Deserialize an object from a byte slice.  This method may panic if `data` isn't at
        /// least `MAX_SIZE` bytes long.  The value returned on success is the number of bytes read.
        fn read_from(reader: &mut impl RefRead<'a>) -> Result<Self, ReadError>;
    }

    /// A `Varint` represents a vector length, encoded as a variable-length integer.  It can act as
    /// both a protocol object and a view, the latter trivially, by just decoding and storing the
    /// integer.
    #[derive(Default, Copy, Clone, PartialEq, Debug)]
    pub struct Varint(usize);

    impl ProtocolObject for Varint {
        const MAX_SIZE: usize = 4;

        type View<'a> = Varint;

        fn as_view<'a>(&'a self) -> Self::View<'a> {
            *self
        }

        fn write_to(&self, writer: &mut impl Write) -> Result<(), WriteError> {
            let mut data = self.0.to_be_bytes();
            if self.0 < (1 << 6) {
                writer.write_all(&data[3..])?;
                Ok(())
            } else if self.0 < (1 << 14) {
                data[2] |= 0x40;
                writer.write_all(&data[2..])?;
                Ok(())
            } else if self.0 < (1 << 30) {
                data[0] |= 0x80;
                writer.write_all(&data)?;
                Ok(())
            } else {
                Err(WriteError("Invalid value"))
            }
        }
    }

    impl<'a> ProtocolObjectView<'a> for Varint {
        type Owned = Varint;

        fn copy_to_owned(&self) -> Self::Owned {
            *self
        }

        fn read_from(reader: &mut impl RefRead<'a>) -> Result<Self, ReadError> {
            let first_byte = reader.peek()?;
            let len = 1 << usize::from(first_byte >> 6);
            let data = reader.read(len)?;

            let val = match len {
                1 => usize::from(first_byte),
                2 => {
                    let val = usize::from(data[0]) & 0x3f;
                    let val = (val << 8) + usize::from(data[1]);
                    val
                }
                4 => {
                    let val = usize::from(data[0]) & 0x3f;
                    let val = (val << 8) + usize::from(data[1]);
                    let val = (val << 8) + usize::from(data[2]);
                    let val = (val << 8) + usize::from(data[3]);
                    val
                }
                _ => return Err(ReadError("Invalid encoding")),
            };

            Ok(Self(val))
        }
    }

    // Primitive integer types are trivially read/write
    macro_rules! define_primitive_protocol {
        ($int:ty) => {
            impl ProtocolObject for $int {
                const MAX_SIZE: usize = 1;

                type View<'a> = $int;

                fn as_view<'a>(&'a self) -> Self::View<'a> {
                    *self
                }

                fn write_to(&self, writer: &mut impl Write) -> Result<(), WriteError> {
                    writer.write_all(&self.to_be_bytes())
                }
            }

            impl<'a> ProtocolObjectView<'a> for $int {
                type Owned = $int;

                fn copy_to_owned(&self) -> Self::Owned {
                    *self
                }

                fn read_from(reader: &mut impl RefRead<'a>) -> Result<Self, ReadError> {
                    const N: usize = core::mem::size_of::<$int>();
                    let slice = reader.read(N)?;
                    let array: [u8; N] =
                        slice.try_into().map_err(|_| ReadError("Unknown error"))?;
                    Ok(Self::from_be_bytes(array))
                }
            }
        };
    }

    define_primitive_protocol!(u8);
    define_primitive_protocol!(u16);
    define_primitive_protocol!(u32);
    define_primitive_protocol!(u64);

    /// An `Opaque` object represents an opaque vector of bytes with a specified maximum size `N`.
    #[derive(Clone, Default, Debug, PartialEq)]
    pub struct Opaque<const N: usize> {
        pub data: Vec<u8, N>,
    }

    impl<const N: usize> ProtocolObject for Opaque<N> {
        const MAX_SIZE: usize = N;

        type View<'a> = OpaqueView<'a, N>;

        fn as_view<'a>(&'a self) -> Self::View<'a> {
            OpaqueView {
                data: self.data.as_slice(),
            }
        }

        fn write_to(&self, writer: &mut impl Write) -> Result<(), WriteError> {
            let len = Varint(self.data.len());
            len.write_to(writer)?;
            writer.write_all(&self.data)
        }
    }

    /// An `OpaqueView` object represents a reference to a slice of bytes with maximum size `N`.
    /// Attempting to read a slice with length greater than `N` will return an error.
    #[derive(Clone, Default, Debug, PartialEq)]
    pub struct OpaqueView<'a, const N: usize> {
        pub data: &'a [u8],
    }

    impl<'a, const N: usize> ProtocolObjectView<'a> for OpaqueView<'a, N> {
        type Owned = Opaque<N>;

        fn copy_to_owned(&self) -> Self::Owned {
            Opaque {
                // XXX(RLB): Safe to unwrap as long as we enforce that `data.len() < N`
                data: Vec::from_slice(self.data).unwrap(),
            }
        }

        fn read_from(reader: &mut impl RefRead<'a>) -> Result<Self, ReadError> {
            let len = Varint::read_from(reader)?.0;
            if len > N {
                return Err(ReadError("Invalid encoding"));
            }

            let data = reader.read(len)?;
            Ok(Self { data })
        }
    }

    /// A `FixedValue` type represents a type that (a) on encode, always encodes to the same value,
    /// and (b) on decode, returns an error if the encoded value isn't the fixed value.  These
    /// types are typically zero-sized, since any data content would not be reflected on the wire.
    pub trait FixedValue: Copy + Default + 'static {
        const FIXED_SELF: &'static Self;
        const FIXED_VALUE: &'static [u8];
    }

    impl<T> ProtocolObject for T
    where
        T: FixedValue,
    {
        const MAX_SIZE: usize = T::FIXED_VALUE.len();

        type View<'a>
            = &'a Self
        where
            T: 'a;

        fn as_view<'a>(&'a self) -> Self::View<'a> {
            self
        }

        fn write_to(&self, writer: &mut impl Write) -> Result<(), WriteError> {
            writer.write_all(Self::FIXED_VALUE)
        }
    }

    impl<'a, T> ProtocolObjectView<'a> for &'a T
    where
        T: FixedValue + ProtocolObject,
    {
        type Owned = T;

        fn copy_to_owned(&self) -> T {
            **self
        }

        fn read_from(reader: &mut impl RefRead<'a>) -> Result<Self, ReadError> {
            let read = reader.read(T::FIXED_VALUE.len())?;
            if read != T::FIXED_VALUE {
                Err(ReadError("Invalid encoding"))
            } else {
                Ok(T::FIXED_SELF)
            }
        }
    }

    // Allow easy instantiation of the newtype pattern
    // XXX(RLB): The lifetime label on the `$inner_view` types must be `'a`.
    // XXX(RLB): Can we synthesize the names of the view types?
    #[macro_export]
    macro_rules! newtype_opaque {
        ($owned_type:ident, $view_type:ident, $size:expr) => {
            #[derive(Clone, Default, Debug, PartialEq)]
            pub struct $owned_type(Opaque<{ $size }>);

            impl ProtocolObject for $owned_type {
                const MAX_SIZE: usize = Opaque::<{ $size }>::MAX_SIZE;

                type View<'a> = $view_type<'a>;

                fn as_view<'a>(&'a self) -> Self::View<'a> {
                    $view_type(self.0.as_view())
                }

                fn write_to(&self, writer: &mut impl Write) -> Result<(), WriteError> {
                    self.0.write_to(writer)
                }
            }

            impl From<&[u8]> for $owned_type {
                fn from(data: &[u8]) -> Self {
                    let mut out = Self::default();
                    // XXX(RLB) We should avoid this, maybe by implementing TryFrom?
                    out.0.data.extend_from_slice(data).unwrap();
                    out
                }
            }

            impl AsRef<[u8]> for $owned_type {
                fn as_ref(&self) -> &[u8] {
                    self.0.data.as_ref()
                }
            }

            #[derive(Debug, PartialEq)]
            pub struct $view_type<'a>(OpaqueView<'a, { $size }>);

            impl<'a> ProtocolObjectView<'a> for $view_type<'a> {
                type Owned = $owned_type;

                fn copy_to_owned(&self) -> Self::Owned {
                    $owned_type(self.0.copy_to_owned())
                }

                fn read_from(reader: &mut impl RefRead<'a>) -> Result<Self, ReadError> {
                    Ok(Self(OpaqueView::read_from(reader)?))
                }
            }

            impl<'a> AsRef<[u8]> for $view_type<'a> {
                fn as_ref(&self) -> &[u8] {
                    self.0.data.as_ref()
                }
            }
        };
    }
}

mod crypto {
    use crate::common::*;
    use crate::newtype_opaque;

    // XXX(RLB) In an ideal world, these constanst would be generics, so that they could be supplied by
    // the application at build time.  However, Rust's support for const generics is not complete
    // enough to support this without a bunch of hassle.  (The insanity that the `ml_kem` and `ml_dsa`
    // crates undertook [1] would be even crazier for a full protocol.) So instead we define batches
    // of constants that can be selected with feature flags, so that the application still has a degree
    // of choice, but with less hassle from dealing with generics.
    //
    // [1] https://github.com/RustCrypto/KEMs/blob/master/ml-kem/src/param.rs#L196
    //
    // Note that enabling more than one of these features will result in duplicate symbols.
    #[cfg(feature = "x25519_aes128gcm_ed25519")]
    pub mod consts {
        pub const CIPHER_SUITE: [u8; 2] = [0x00, 0x01];

        pub const HASH_OUTPUT_SIZE: usize = 32;

        pub const HPKE_PRIVATE_KEY_SIZE: usize = 32;
        pub const HPKE_PUBLIC_KEY_SIZE: usize = 32;

        pub const SIGNATURE_PRIVATE_KEY_SIZE: usize = 64;
        pub const SIGNATURE_PUBLIC_KEY_SIZE: usize = 32;
        pub const SIGNATURE_SIZE: usize = 64;
    }

    #[derive(Debug)]
    pub struct CryptoError(&'static str);

    newtype_opaque!(HashOutput, HashOutputView, consts::HASH_OUTPUT_SIZE);

    newtype_opaque!(
        HpkePrivateKey,
        HpkePrivateKeyView,
        consts::HPKE_PRIVATE_KEY_SIZE
    );
    newtype_opaque!(
        HpkePublicKey,
        HpkePublicKeyView,
        consts::HPKE_PUBLIC_KEY_SIZE
    );

    newtype_opaque!(
        SignaturePrivateKey,
        SignaturePrivateKeyView,
        consts::SIGNATURE_PRIVATE_KEY_SIZE
    );
    newtype_opaque!(
        SignaturePublicKey,
        SignaturePublicKeyView,
        consts::SIGNATURE_PUBLIC_KEY_SIZE
    );
    newtype_opaque!(Signature, SignatureView, consts::SIGNATURE_SIZE);
}

#[cfg(all(feature = "rust_crypto", feature = "x25519_aes128gcm_ed25519"))]
pub mod cipher_suite {
    use crate::common::*;
    use crate::crypto::*;

    use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
    use rand_core::CryptoRngCore;
    use sha2::{Digest, Sha256};

    pub struct Hash {
        hash: Sha256,
    }

    impl Hash {
        pub fn new() -> Self {
            Self {
                hash: Sha256::new(),
            }
        }

        pub fn finalize(self) -> HashOutput {
            let digest = self.hash.finalize();
            HashOutput::from(digest.as_slice())
        }
    }

    impl Write for Hash {
        fn write(&mut self, data: &[u8]) -> Result<usize, WriteError> {
            self.hash.update(data);
            Ok(data.len())
        }
    }

    pub fn generate_sig(
        rng: &mut impl CryptoRngCore,
    ) -> Result<(SignaturePrivateKey, SignaturePublicKey), CryptoError> {
        let raw_priv = SigningKey::generate(rng);
        let raw_pub = raw_priv.verifying_key();

        let priv_bytes = raw_priv.to_keypair_bytes();
        let pub_bytes = raw_pub.to_bytes();

        let signature_priv = SignaturePrivateKey::from(priv_bytes.as_slice());
        let signature_key = SignaturePublicKey::from(pub_bytes.as_slice());

        Ok((signature_priv, signature_key))
    }

    pub fn sign(
        message: &[u8],
        signature_priv: SignaturePrivateKeyView,
    ) -> Result<Signature, CryptoError> {
        let priv_bytes = signature_priv.as_ref().try_into().unwrap();
        let raw_priv = SigningKey::from_keypair_bytes(priv_bytes).unwrap();

        let raw_sig = raw_priv.sign(message.as_ref());
        let signature = Signature::from(raw_sig.to_bytes().as_slice());

        Ok(signature)
    }

    pub fn verify(
        message: &[u8],
        signature_key: SignaturePublicKeyView,
        signature: SignatureView,
    ) -> Result<bool, CryptoError> {
        let key_bytes = signature_key.as_ref().try_into().unwrap();
        let sig_bytes = signature.as_ref();

        let raw_key = VerifyingKey::from_bytes(key_bytes).unwrap();
        let raw_sig = ed25519_dalek::Signature::try_from(sig_bytes).unwrap();

        let ver = raw_key.verify(message, &raw_sig).is_ok();
        Ok(ver)
    }

    pub fn generate_hpke() -> Result<(HpkePrivateKey, HpkePublicKey), CryptoError> {
        todo!();
    }

    #[cfg(test)]
    mod test {
        use super::*;

        #[test]
        fn sign_verify() {
            let message = b"hello signature";
            let mut rng = rand::thread_rng();
            let (sig_priv, sig_pub) = generate_sig(&mut rng).unwrap();
            let sig = sign(message, sig_priv.as_view()).unwrap();
            let ver = verify(message, sig_pub.as_view(), sig.as_view()).unwrap();
            assert!(ver)
        }
    }
}

mod protocol {
    use crate::cipher_suite;
    use crate::common::*;
    use crate::crypto::*;
    use hex_literal::hex;

    // use hex_literal::hex;

    const fn max(a: usize, b: usize) -> usize {
        if a < b {
            a
        } else {
            b
        }
    }

    // XXX(RLB) Similar story here to the cryptographic parameters, except here the need for
    // application modification is even more acute.  We ought to define some options here, with feature
    // flags to select among them.
    mod consts {
        pub const MAX_CREDENTIAL_SIZE: usize = 128;
    }

    pub type Credential = Opaque<{ consts::MAX_CREDENTIAL_SIZE }>;
    pub type CredentialView<'a> = OpaqueView<'a, { consts::MAX_CREDENTIAL_SIZE }>;

    #[derive(Copy, Clone, Default, PartialEq, Debug)]
    pub struct Capabilities;

    type CapabilitiesView<'a> = &'a Capabilities;

    impl FixedValue for Capabilities {
        const FIXED_SELF: &Self = &Self;

        // versions      = 02 0001  // MLS 1.0
        // cipher_suites = 02 xxxx  // The one fixed cipher suite
        // extensions    = 00       // No extensions
        // proposals     = 00       // No proposals
        // credentials   = 02 0001  // Basic credentials
        const FIXED_VALUE: &[u8] = &{
            let mut value = hex!("02 0001 02 0000 00 00 02 0001");
            value[4] = crate::crypto::consts::CIPHER_SUITE[0];
            value[5] = crate::crypto::consts::CIPHER_SUITE[1];
            value
        };
    }

    // TODO(RLB) We should actually implement extension parsing, at least on deserialization, in
    // order to be compatible with other stacks.
    #[derive(Copy, Clone, Default, PartialEq, Debug)]
    pub struct LeafNodeExtensions;

    impl FixedValue for LeafNodeExtensions {
        const FIXED_SELF: &Self = &Self;
        const FIXED_VALUE: &[u8] = &[0];
    }

    type LeafNodeExtensionsView<'a> = &'a LeafNodeExtensions;

    #[derive(Clone, PartialEq, Debug)]
    pub enum LeafNodeSource {
        KeyPackage,
        Update,
        Commit(HashOutput),
    }

    impl LeafNodeSource {
        const KEY_PACKAGE: u8 = 1;
        const UPDATE: u8 = 2;
        const COMMIT: u8 = 3;
    }

    impl Default for LeafNodeSource {
        fn default() -> Self {
            Self::KeyPackage
        }
    }

    impl ProtocolObject for LeafNodeSource {
        const MAX_SIZE: usize = 1 + HashOutput::MAX_SIZE;

        type View<'a> = LeafNodeSourceView<'a>;

        fn as_view<'a>(&'a self) -> Self::View<'a> {
            match self {
                Self::KeyPackage => Self::View::KeyPackage,
                Self::Update => Self::View::Update,
                Self::Commit(parent_hash) => Self::View::Commit(parent_hash.as_view()),
            }
        }

        fn write_to(&self, writer: &mut impl Write) -> Result<(), WriteError> {
            match self {
                Self::KeyPackage => {
                    writer.write_all(&[Self::KEY_PACKAGE])?;
                    u64::MIN.write_to(writer)?;
                    u64::MAX.write_to(writer)
                }
                Self::Update => writer.write_all(&[Self::UPDATE]),
                Self::Commit(parent_hash) => {
                    writer.write_all(&[Self::KEY_PACKAGE])?;
                    parent_hash.write_to(writer)
                }
            }
        }
    }

    #[derive(PartialEq, Debug)]
    pub enum LeafNodeSourceView<'a> {
        KeyPackage,
        Update,
        Commit(HashOutputView<'a>),
    }

    impl<'a> ProtocolObjectView<'a> for LeafNodeSourceView<'a> {
        type Owned = LeafNodeSource;

        fn copy_to_owned(&self) -> Self::Owned {
            match self {
                Self::KeyPackage => Self::Owned::KeyPackage,
                Self::Update => Self::Owned::Update,
                Self::Commit(parent_hash) => Self::Owned::Commit(parent_hash.copy_to_owned()),
            }
        }

        fn read_from(reader: &mut impl RefRead<'a>) -> Result<Self, ReadError> {
            let leaf_node_source = reader.read(1)?[0];
            match leaf_node_source {
                Self::Owned::KEY_PACKAGE => {
                    // XXX(RLB) Lifetime is currently ignored; we just read past it
                    let _lifetime = reader.read(16)?;
                    Ok(Self::KeyPackage)
                }
                Self::Owned::UPDATE => Ok(Self::Update),
                Self::Owned::COMMIT => {
                    let parent_hash = HashOutputView::read_from(reader)?;
                    Ok(Self::Commit(parent_hash))
                }
                _ => Err(ReadError("Invalid encoding")),
            }
        }
    }

    // TODO(RLB) LeafNodePrivView + impl ProtocolObject
    #[derive(Default, Clone, PartialEq, Debug)]
    pub struct LeafNodePriv {
        encryption_priv: HpkePrivateKey,
        signature_priv: SignaturePrivateKey,
    }

    #[derive(Default, Clone, PartialEq, Debug)]
    pub struct LeafNode {
        encryption_key: HpkePublicKey,
        signature_key: SignaturePublicKey,
        credential: Credential,
        capabilities: Capabilities,
        leaf_node_source: LeafNodeSource,
        extensions: LeafNodeExtensions,
        signature: Signature,
    }

    impl LeafNode {
        fn new(
            leaf_node_source: LeafNodeSource,
            signature_priv: SignaturePrivateKey,
            signature_key: SignaturePublicKey,
            credential: Credential,
        ) -> Result<(LeafNodePriv, LeafNode), CryptoError> {
            // Generate the encryption key pair
            let (encryption_priv, encryption_key) = cipher_suite::generate_hpke()?;

            // Create a partial LeafNode object, with the signature blank

            let mut leaf_node = LeafNode {
                encryption_key,
                signature_key,
                credential,
                leaf_node_source,
                ..Default::default()
            };

            // Serialize the part to be signed into hash
            // XXX(RLB): Move this to a `sign()` method?
            // TODO(RLB): Replace `unwrap` with actual error handling
            let mut hash = cipher_suite::Hash::new();
            leaf_node.encryption_key.write_to(&mut hash).unwrap();
            leaf_node.signature_key.write_to(&mut hash).unwrap();
            leaf_node.credential.write_to(&mut hash).unwrap();
            leaf_node.capabilities.write_to(&mut hash).unwrap();
            leaf_node.leaf_node_source.write_to(&mut hash).unwrap();
            leaf_node.extensions.write_to(&mut hash).unwrap();
            let hash_output = hash.finalize();

            // Populate the signature
            // TODO(RLB): Actually sign serialized thing
            leaf_node.signature =
                cipher_suite::sign(hash_output.as_ref(), signature_priv.as_view())?;

            let leaf_node_priv = LeafNodePriv {
                encryption_priv,
                signature_priv,
            };
            Ok((leaf_node_priv, leaf_node))
        }
    }

    impl ProtocolObject for LeafNode {
        const MAX_SIZE: usize = HpkePublicKey::MAX_SIZE
            + SignaturePublicKey::MAX_SIZE
            + Credential::MAX_SIZE
            + Capabilities::MAX_SIZE
            + LeafNodeSource::MAX_SIZE
            + LeafNodeExtensions::MAX_SIZE
            + Signature::MAX_SIZE;

        type View<'a> = LeafNodeView<'a>;

        fn as_view<'a>(&'a self) -> Self::View<'a> {
            Self::View {
                encryption_key: self.encryption_key.as_view(),
                signature_key: self.signature_key.as_view(),
                credential: self.credential.as_view(),
                capabilities: self.capabilities.as_view(),
                leaf_node_source: self.leaf_node_source.as_view(),
                extensions: self.extensions.as_view(),
                signature: self.signature.as_view(),
            }
        }

        fn write_to(&self, writer: &mut impl Write) -> Result<(), WriteError> {
            self.encryption_key.write_to(writer)?;
            self.signature_key.write_to(writer)?;
            self.credential.write_to(writer)?;
            self.capabilities.write_to(writer)?;
            self.leaf_node_source.write_to(writer)?;
            self.extensions.write_to(writer)?;
            self.signature.write_to(writer)?;
            Ok(())
        }
    }

    #[derive(PartialEq, Debug)]
    pub struct LeafNodeView<'a> {
        encryption_key: HpkePublicKeyView<'a>,
        signature_key: SignaturePublicKeyView<'a>,
        credential: CredentialView<'a>,
        capabilities: CapabilitiesView<'a>,
        leaf_node_source: LeafNodeSourceView<'a>,
        extensions: LeafNodeExtensionsView<'a>,
        signature: SignatureView<'a>,
    }

    impl<'a> ProtocolObjectView<'a> for LeafNodeView<'a> {
        type Owned = LeafNode;

        fn copy_to_owned(&self) -> Self::Owned {
            Self::Owned {
                encryption_key: self.encryption_key.copy_to_owned(),
                signature_key: self.signature_key.copy_to_owned(),
                credential: self.credential.copy_to_owned(),
                capabilities: self.capabilities.copy_to_owned(),
                leaf_node_source: self.leaf_node_source.copy_to_owned(),
                extensions: self.extensions.copy_to_owned(),
                signature: self.signature.copy_to_owned(),
            }
        }

        fn read_from(reader: &mut impl RefRead<'a>) -> Result<Self, ReadError> {
            let encryption_key = HpkePublicKeyView::read_from(reader)?;
            let signature_key = SignaturePublicKeyView::read_from(reader)?;
            let credential = CredentialView::read_from(reader)?;
            let capabilities = CapabilitiesView::read_from(reader)?;
            let leaf_node_source = LeafNodeSourceView::read_from(reader)?;
            let extensions = LeafNodeExtensionsView::read_from(reader)?;
            let signature = SignatureView::read_from(reader)?;
            Ok(Self {
                encryption_key,
                signature_key,
                credential,
                capabilities,
                leaf_node_source,
                extensions,
                signature,
            })
        }
    }
}

/*

// API sketch

struct Error;
type Result<T> = core::result::Result<T, Error>;

struct Commit;
struct CommitView<'a> {
    _dummy: &'a [u8],
}

struct Credential;

struct GroupState;
struct GroupStateView<'a> {
    _dummy: &'a [u8],
}

struct KeyPackage;
struct KeyPackageView<'a> {
    _dummy: &'a [u8],
}

struct KeyPackagePriv;
struct KeyPackagePrivView<'a> {
    _dummy: &'a [u8],
}

struct LeafIndex(u32);

struct RatchetTree;
struct RatchetTreeView<'a> {
    _dummy: &'a [u8],
}

struct SignatureKey;

struct Welcome;
struct WelcomeView<'a> {
    _dummy: &'a [u8],
}

fn make_key_package(
    _signature_key: SignatureKey,
    _credential: Credential,
) -> Result<(KeyPackagePriv, KeyPackage)> {
    todo!();
}

fn create_group(
    _key_package_priv: KeyPackagePrivView,
    _key_package: KeyPackageView,
) -> Result<(GroupState, RatchetTree)> {
    todo!();
}

fn join_group(
    _key_package_priv: KeyPackagePrivView,
    _key_package: KeyPackageView,
    _welcome: WelcomeView,
) -> Result<(GroupState, RatchetTree)> {
    todo!();
}

fn add_member(
    _group_state: GroupStateView,
    _ratchet_tree: RatchetTreeView,
    _key_package: KeyPackageView,
) -> Result<(GroupState, RatchetTree, Commit, Welcome)> {
    todo!();
}

fn remove_member(
    _group_state: GroupStateView,
    _ratchet_tree: RatchetTreeView,
    _leaf_index: LeafIndex,
) -> Result<(GroupState, RatchetTree, Commit)> {
    todo!();
}

fn handle_commit(
    _group_state: GroupStateView,
    _ratchet_tree: RatchetTreeView,
    _commit: CommitView,
) -> Result<(GroupState, RatchetTree)> {
    todo!();
}
*/

/*
mod common {
    use core::convert::AsRef;
    use core::fmt::Debug;
    use core::ops::Deref;

    #[derive(Debug, PartialEq)]
    pub struct Error;

    pub type Result<T> = core::result::Result<T, Error>;

    pub trait Encode<'a>: Sized + PartialEq + Debug {
        const MAX_SIZE: usize;
        type Contents;

        fn build(contents: Self::Contents, data: &mut [u8]) -> Result<usize>;
        fn parse(data: &'a [u8]) -> Result<(Self, usize)>;
    }

    #[derive(Copy, Clone, PartialEq, Debug)]
    pub struct Varint(usize);

    impl<'a> Encode<'a> for Varint {
        const MAX_SIZE: usize = 4;
        type Contents = usize;

        fn build(val: usize, data: &mut [u8]) -> Result<usize> {
            if val < (1 << 6) {
                data[0] = val as u8;
                Ok(1)
            } else if val < (1 << 14) {
                data[0] = ((val >> 8) as u8) | 0x40;
                data[1] = val as u8;
                Ok(2)
            } else if val < (1 << 30) {
                data[0] = ((val >> 24) as u8) | 0x80;
                data[1] = (val >> 16) as u8;
                data[2] = (val >> 8) as u8;
                data[3] = val as u8;
                Ok(4)
            } else {
                Err(Error)
            }
        }

        fn parse(data: &'a [u8]) -> Result<(Self, usize)> {
            let length = 1 << usize::from(data[0] >> 6);

            let val = match length {
                1 => usize::from(data[0]) & 0x3f,
                2 => {
                    let val = usize::from(data[0]) & 0x3f;
                    let val = (val << 8) + usize::from(data[1]);
                    val
                }
                4 => {
                    let val = usize::from(data[0]) & 0x3f;
                    let val = (val << 8) + usize::from(data[1]);
                    let val = (val << 8) + usize::from(data[2]);
                    let val = (val << 8) + usize::from(data[3]);
                    val
                }
                _ => return Err(Error),
            };

            Ok((Self(val), length))
        }
    }

    const fn varint_size(n: usize) -> usize {
        if n < (1 << 6) {
            1
        } else if n < (1 << 14) {
            2
        } else if n < (1 << 30) {
            4
        } else {
            unreachable!();
        }
    }

    #[derive(PartialEq, Debug)]
    pub struct BoundedOpaque<'a, const N: usize>(&'a [u8]);

    impl<'a, const N: usize> BoundedOpaque<'a, N> {
        pub fn new(data: &'a [u8]) -> Result<Self> {
            if data.len() <= N {
                Ok(Self(data))
            } else {
                Err(Error)
            }
        }
    }

    impl<'a, const N: usize> Deref for BoundedOpaque<'a, N> {
        type Target = [u8];

        fn deref(&self) -> &Self::Target {
            &self.0
        }
    }

    impl<'a, const N: usize> Encode<'a> for BoundedOpaque<'a, N> {
        const MAX_SIZE: usize = varint_size(N) + N;
        type Contents = &'a [u8];

        fn build(contents: &[u8], data: &mut [u8]) -> Result<usize> {
            let n = contents.len();
            if n > N {
                return Err(Error);
            }

            let start = Varint::build(n, data)?;
            let end = start + n;
            data[start..end].copy_from_slice(contents);
            Ok(end)
        }

        fn parse(data: &'a [u8]) -> Result<(Self, usize)> {
            let (Varint(n), start) = Varint::parse(data)?;
            if n > N {
                return Err(Error);
            }

            let end = start + n;
            let contents = &data[start..end];
            Ok((Self(contents), end))
        }
    }

    #[derive(PartialEq, Debug)]
    pub struct FixedOpaque<'a, const N: usize>(&'a [u8]);

    impl<'a, const N: usize> FixedOpaque<'a, N> {
        pub fn new(data: &'a [u8]) -> Result<Self> {
            if data.len() == N {
                Ok(Self(data))
            } else {
                Err(Error)
            }
        }
    }

    impl<'a, const N: usize> Deref for FixedOpaque<'a, N> {
        type Target = [u8];

        fn deref(&self) -> &Self::Target {
            &self.0
        }
    }

    impl<'a, const N: usize> Encode<'a> for FixedOpaque<'a, N> {
        const MAX_SIZE: usize = varint_size(N) + N;
        type Contents = &'a [u8];

        fn build(contents: &[u8], data: &mut [u8]) -> Result<usize> {
            let n = contents.len();
            if n != N {
                return Err(Error);
            }

            let start = Varint::build(n, data)?;
            let end = start + n;
            data[start..end].copy_from_slice(contents);
            Ok(end)
        }

        fn parse(data: &'a [u8]) -> Result<(Self, usize)> {
            let (Varint(n), start) = Varint::parse(data)?;
            if n != N {
                return Err(Error);
            }

            let end = start + n;
            let contents = &data[start..end];
            Ok((Self(contents), end))
        }
    }

    pub trait FixedValue: Default {
        type ValueType: AsRef<[u8]>;
        const FIXED_VALUE: Self::ValueType;
        const FIXED_LEN: usize;
    }

    impl<'a, T> Encode<'a> for T
    where
        T: FixedValue + Sized + PartialEq + Debug,
    {
        const MAX_SIZE: usize = Self::FIXED_LEN;
        type Contents = ();

        fn build(_contents: (), data: &mut [u8]) -> Result<usize> {
            let end = Self::FIXED_VALUE.as_ref().len();
            data[..end].copy_from_slice(Self::FIXED_VALUE.as_ref());
            Ok(end)
        }

        fn parse(data: &'a [u8]) -> Result<(Self, usize)> {
            let end = Self::FIXED_VALUE.as_ref().len();
            if &data[..end] != Self::FIXED_VALUE.as_ref() {
                return Err(Error);
            }

            Ok((Self::default(), end))
        }
    }

    #[cfg(test)]
    mod test {
        use super::*;

        fn encode_test<'a, T: Encode<'a>>(
            val: T::Contents,
            data: &'a mut [u8],
            expected_enc: &[u8],
            expected_dec: T,
        ) {
            let len = T::build(val, data).unwrap();
            assert_eq!(len, data.len());
            assert_eq!(data, expected_enc);

            let (parsed, len) = T::parse(data).unwrap();
            assert_eq!(len, data.len());
            assert_eq!(parsed, expected_dec);
        }

        #[test]
        fn varint() {
            encode_test::<Varint>(0x3f, &mut [0u8; 1], &[0x3f], Varint(0x3f));
            encode_test::<Varint>(0x3fff, &mut [0u8; 2], &[0x7f, 0xff], Varint(0x3fff));
            encode_test::<Varint>(
                0x3fffffff,
                &mut [0u8; 4],
                &[0xbf, 0xff, 0xff, 0xff],
                Varint(0x3fffffff),
            );
        }

        #[test]
        fn bounded_opaque() {
            const SIZE: usize = 63;
            type Opaque<'a> = BoundedOpaque<'a, SIZE>;

            const BUFFER_SIZE: usize = Opaque::MAX_SIZE;

            let buffer = &mut [0u8; BUFFER_SIZE];

            let contents = &[0xa0; SIZE];
            let expected_dec = BoundedOpaque::<SIZE>(contents);

            let expected_enc = &{
                let mut expected = [0xa0; BUFFER_SIZE];
                expected[0] = SIZE as u8;
                expected
            };

            encode_test::<Opaque>(contents, buffer, expected_enc, expected_dec);

            // Test that invalid size fails
            let mut too_big = [0; SIZE + 2];
            too_big[0..2].copy_from_slice(&[0x7f, 0xff]);
            assert_eq!(Opaque::build(&too_big, &mut [0; 2]), Err(Error));
            assert_eq!(Opaque::parse(&too_big), Err(Error));
        }

        #[test]
        fn fixed_opaque() {
            const SIZE: usize = 63;
            type Opaque<'a> = FixedOpaque<'a, SIZE>;

            const BUFFER_SIZE: usize = Opaque::MAX_SIZE;

            let buffer = &mut [0u8; BUFFER_SIZE];

            let contents = &[0xa0; SIZE];
            let expected_dec = FixedOpaque::<SIZE>(contents);

            let expected_enc = &{
                let mut expected = [0xa0; BUFFER_SIZE];
                expected[0] = SIZE as u8;
                expected
            };

            encode_test::<Opaque>(contents, buffer, expected_enc, expected_dec);

            // Test that invalid size fails
            let mut too_big = [0; SIZE + 2];
            too_big[0..2].copy_from_slice(&[0x7f, 0xff]);
            assert_eq!(Opaque::build(&too_big, &mut [0; 2]), Err(Error));
            assert_eq!(Opaque::parse(&too_big), Err(Error));

            let mut too_small = [0; SIZE];
            too_small[0] = SIZE - 1;
            assert_eq!(Opaque::build(&too_big, &mut [0; 2]), Err(Error));
            assert_eq!(Opaque::parse(&too_big), Err(Error));
        }
    }
}

mod crypto {
    use crate::common::FixedOpaque;

    // XXX(RLB) In an ideal world, these constanst would be generics, so that they could be supplied by
    // the application at build time.  However, Rust's support for const generics is not complete
    // enough to support this without a bunch of hassle.  (The insanity that the `ml_kem` and `ml_dsa`
    // crates undertook [1] would be even crazier for a full protocol.) So instead we define batches
    // of constants that can be selected with feature flags, so that the application still has a degree
    // of choice, but with less hassle from dealing with generics.
    //
    // [1] https://github.com/RustCrypto/KEMs/blob/master/ml-kem/src/param.rs#L196
    //
    // Note that enabling more than one of these features will result in duplicate symbols.
    #[cfg(feature = "x25519_aes128gcm_ed25519")]
    pub mod consts {
        pub const CIPHER_SUITE: [u8; 2] = [0x00, 0x01];

        pub const HASH_OUTPUT_SIZE: usize = 32;

        pub const HPKE_PUBLIC_KEY_SIZE: usize = 32;

        pub const SIGNATURE_PUBLIC_KEY_SIZE: usize = 32;
        pub const SIGNATURE_SIZE: usize = 64;
    }

    pub type HashOutput<'a> = FixedOpaque<'a, { consts::HASH_OUTPUT_SIZE }>;

    pub type HpkePublicKey<'a> = FixedOpaque<'a, { consts::HPKE_PUBLIC_KEY_SIZE }>;

    pub type SignaturePublicKey<'a> = FixedOpaque<'a, { consts::SIGNATURE_PUBLIC_KEY_SIZE }>;

    pub type Signature<'a> = FixedOpaque<'a, { consts::SIGNATURE_SIZE }>;
}

mod protocol {
    use crate::common::*;
    use crate::crypto::*;

    use hex_literal::hex;

    const fn max(a: usize, b: usize) -> usize {
        if a < b {
            a
        } else {
            b
        }
    }

    // XXX(RLB) Similar story here to the cryptographic parameters, except here the need for
    // application modification is even more acute.  We ought to define some options here, with feature
    // flags to select among them.
    mod consts {
        pub const MAX_CREDENTIAL_SIZE: usize = 128;
    }

    pub type Credential<'a> = BoundedOpaque<'a, { consts::MAX_CREDENTIAL_SIZE }>;

    #[derive(Default, PartialEq, Debug)]
    pub struct Capabilities;

    impl FixedValue for Capabilities {
        type ValueType = [u8; 11];

        // versions      = 02 0001  // MLS 1.0
        // cipher_suites = 02 xxxx  // The one fixed cipher suite
        // extensions    = 00       // No extensions
        // proposals     = 00       // No proposals
        // credentials   = 02 0001  // Basic credentials
        const FIXED_VALUE: [u8; 11] = {
            let mut value = hex!("02 0001 02 0000 00 00 02 0001");
            value[4] = crate::crypto::consts::CIPHER_SUITE[0];
            value[5] = crate::crypto::consts::CIPHER_SUITE[1];
            value
        };

        const FIXED_LEN: usize = 11;
    }

    #[derive(Default, PartialEq, Debug)]
    pub struct LeafNodeExtensions;

    impl FixedValue for LeafNodeExtensions {
        type ValueType = [u8; 1];
        const FIXED_VALUE: [u8; 1] = [0];
        const FIXED_LEN: usize = 1;
    }

    #[derive(PartialEq, Debug)]
    pub enum LeafNodeSource<'a> {
        KeyPackage,
        Update,
        Commit(HashOutput<'a>),
    }

    impl<'a> LeafNodeSource<'a> {
        const KEY_PACKAGE: u8 = 1;
        const UPDATE: u8 = 2;
        const COMMIT: u8 = 3;
    }

    impl<'a> Encode<'a> for LeafNodeSource<'a> {
        const MAX_SIZE: usize = max(16, HashOutput::MAX_SIZE);
        type Contents = &'a Self;

        fn build(contents: &'a Self, data: &mut [u8]) -> Result<usize> {
            match contents {
                Self::KeyPackage => {
                    data[0] = Self::KEY_PACKAGE;
                    data[1..9].copy_from_slice(&0_u64.to_be_bytes());
                    data[9..17].copy_from_slice(&u64::MAX.to_be_bytes());
                    Ok(17)
                }
                Self::Update => {
                    data[0] = Self::UPDATE;
                    Ok(1)
                }
                Self::Commit(parent_hash) => {
                    data[0] = Self::COMMIT;
                    let hash_len = HashOutput::build(parent_hash, &mut data[1..])?;
                    Ok(1 + hash_len)
                }
            }
        }

        fn parse(data: &'a [u8]) -> Result<(Self, usize)> {
            let source = data[0];
            let data = &data[1..];
            match source {
                Self::KEY_PACKAGE => {
                    let mut not_before = [0u8; 8];
                    not_before.copy_from_slice(&data[0..8]);
                    let not_before = u64::from_be_bytes(not_before);

                    let mut not_after = [0u8; 8];
                    not_after.copy_from_slice(&data[8..16]);
                    let not_after = u64::from_be_bytes(not_after);

                    if not_before != 0 || not_after != u64::MAX {
                        return Err(Error);
                    }

                    Ok((Self::KeyPackage, 17))
                }
                Self::UPDATE => Ok((Self::Update, 1)),
                Self::COMMIT => {
                    let (parent_hash, hash_len) = HashOutput::parse(data)?;
                    Ok((Self::Commit(parent_hash), 1 + hash_len))
                }
                _ => Err(Error),
            }
        }
    }

    #[derive(PartialEq, Debug)]
    pub struct LeafNode<'a> {
        encryption_key: HpkePublicKey<'a>,
        signature_key: SignaturePublicKey<'a>,
        credential: Credential<'a>,
        leaf_node_source: LeafNodeSource<'a>,
        signature: Signature<'a>,
    }

    impl<'a> LeafNode<'a> {
        fn new(
            signature_key: SignaturePublicKey<'a>,
            credential: Credential<'a>,
            data: &mut [u8],
        ) -> Result<Self> {
            // Generate encryption key
            let encryption_key_storage = HpkePublicKey::make_storage();
            let encryption_key = HpkePublicKey::new(&encryption_key_storage)?;
            // TODO(RLB) CIPHER_SUITE.generate_hpke_key()
            // TODO(RLB) return private state

            // Make a temporary, blank signature
            let signature_storage = Signature::make_storage();
            let signature = Signature::new(&signature_storage)?;

            // Assemble preliminary self object
            let preliminary_leaf = LeafNode {
                encryption_key,
                signature_key,
                credential,
                leaf_node_source: LeafNodeSource::KeyPackage,
                signature,
            };

            // TODO build() / parse()
            // TODO sign()

            todo!()
        }
    }

    impl<'a> Encode<'a> for LeafNode<'a> {
        const MAX_SIZE: usize = HpkePublicKey::MAX_SIZE
            + SignaturePublicKey::MAX_SIZE
            + Credential::MAX_SIZE
            + Capabilities::MAX_SIZE
            + LeafNodeSource::MAX_SIZE
            + LeafNodeExtensions::MAX_SIZE
            + Signature::MAX_SIZE;
        type Contents = &'a Self;

        fn build(contents: &'a Self, data: &mut [u8]) -> Result<usize> {
            let mut n = 0;
            n += HpkePublicKey::build(&contents.encryption_key, &mut data[n..])?;
            n += SignaturePublicKey::build(&contents.signature_key, &mut data[n..])?;
            n += Credential::build(&contents.credential, &mut data[n..])?;
            n += Capabilities::build((), &mut data[n..])?;
            n += LeafNodeSource::build(&contents.leaf_node_source, &mut data[n..])?;
            n += LeafNodeExtensions::build((), &mut data[n..])?;
            n += Signature::build(&contents.signature, &mut data[n..])?;

            Ok(n)
        }

        fn parse(data: &'a [u8]) -> Result<(Self, usize)> {
            let mut n = 0;
            let (encryption_key, dn) = HpkePublicKey::parse(&data[n..])?;
            n += dn;

            let (signature_key, dn) = SignaturePublicKey::parse(&data[n..])?;
            n += dn;

            let (credential, dn) = Credential::parse(&data[n..])?;
            n += dn;

            let (_, dn) = Credential::parse(&data[n..])?;
            n += dn;

            let (leaf_node_source, dn) = LeafNodeSource::parse(&data[n..])?;
            n += dn;

            let (_, dn) = LeafNodeExtensions::parse(&data[n..])?;
            n += dn;

            let (signature, dn) = Signature::parse(&data[n..])?;
            n += dn;

            let leaf_node = LeafNode {
                encryption_key,
                signature_key,
                credential,
                leaf_node_source,
                signature,
            };

            Ok((leaf_node, n))
        }
    }
}
*/

/*
mod encode {
    use crate::common::*;
    use crate::crypto::*;
    use crate::protocol::*;

    const fn max(a: usize, b: usize) -> usize {
        if a < b {
            a
} else {
            b
        }
    }

    const fn varint_size(n: usize) -> usize {
        if n < (1 << 6) {
            1
        } else if n < (1 << 14) {
            2
        } else if n < (1 << 30) {
            4
        } else {
            unreachable!();
        }
    }

    trait Encode {
        const MAX_SIZE: usize;
    }

    impl<const N: usize> Encode for FixedOpaque<N> {
        const MAX_SIZE: usize = varint_size(N) + N;
    }

    impl<const N: usize> Encode for Opaque<N> {
        const MAX_SIZE: usize = varint_size(N) + N;
    }

    impl Encode for Capabilities {
        const MAX_SIZE: usize = Capabilities::FIXED_LEN;
    }

    impl Encode for LeafNodeSource {
        const MAX_SIZE: usize = max(16, HashOutput::MAX_SIZE);
    }

    impl Encode for LeafNodeExtensions {
        const MAX_SIZE: usize = 1;
    }

    impl Encode for LeafNode {
        const MAX_SIZE: usize = HpkePublicKey::MAX_SIZE
            + SignaturePublicKey::MAX_SIZE
            + Credential::MAX_SIZE
            + Capabilities::MAX_SIZE
            + LeafNodeSource::MAX_SIZE
            + LeafNodeExtensions::MAX_SIZE
            + Signature::MAX_SIZE;
    }
}
*/
