use crate::common::*;
use crate::io::{CountWriter, ReadRef, Write};
use crate::stack::*;
use crate::{stack_ptr, tick};

use core::convert::{TryFrom, TryInto};
use core::marker::PhantomData;
use heapless::Vec;

pub use derive_serialize::Serialize;

pub trait Serialize {
    /// The maximum size of a serialized value
    const MAX_SIZE: usize;

    /// Serialize the provided object to the stream.
    fn serialize(&self, writer: &mut impl Write) -> Result<()>;
}

// XXX(RLB) This can't be generic because of the limitations of const generics
#[macro_export]
macro_rules! make_storage {
    ($t:ty) => {
        Vec::<u8, { <$t as Serialize>::MAX_SIZE }>::new()
    };
}

#[macro_export]
macro_rules! serialize {
    ($t:ty, $val:expr) => {{
        let mut buf = make_storage!($t);
        $val.serialize(&mut buf)?;
        buf
    }};
}

impl<T> Serialize for &T
where
    T: Serialize,
{
    const MAX_SIZE: usize = T::MAX_SIZE;

    fn serialize(&self, writer: &mut impl Write) -> Result<()> {
        tick!();
        (**self).serialize(writer)
    }
}

pub trait Deserialize<'a>: Sized {
    fn deserialize(reader: &mut impl ReadRef<'a>) -> Result<Self>;
}

// XXX(RLB) Note that these types can only be included in structs / enums if they are first wrapped
// using the `mls_newtype_primitive!` enum.  This is because the compunding macros assume that the
// "view" type (the one that implements Deserialize) has a lifetime parameter.

pub type PhantomLifetime<'a> = PhantomData<&'a ()>;

#[derive(Default, Clone, Copy, PartialEq, Debug)]
pub struct Nil;

impl Serialize for Nil {
    const MAX_SIZE: usize = 0;

    fn serialize(&self, writer: &mut impl Write) -> Result<()> {
        tick!();
        Ok(())
    }
}

impl<'a> Deserialize<'a> for Nil {
    fn deserialize(reader: &mut impl ReadRef<'a>) -> Result<Self> {
        tick!();
        Ok(Nil)
    }
}

macro_rules! primitive_int_serde {
    ($int:ty) => {
        impl Serialize for $int {
            const MAX_SIZE: usize = core::mem::size_of::<$int>();

            fn serialize(&self, writer: &mut impl Write) -> Result<()> {
                tick!();
                writer.write(&self.to_be_bytes())
            }
        }

        impl<'a> Deserialize<'a> for $int {
            fn deserialize(reader: &mut impl ReadRef<'a>) -> Result<Self> {
                tick!();
                const N: usize = <$int>::MAX_SIZE;
                let slice = reader.read_ref(N)?;
                let array: [u8; N] = slice.try_into().map_err(|_| Error("Unknown error"))?;
                Ok(<$int>::from_be_bytes(array))
            }
        }
    };
}

primitive_int_serde!(u8);
primitive_int_serde!(u16);
primitive_int_serde!(u32);
primitive_int_serde!(u64);

#[macro_export]
macro_rules! mls_newtype_primitive {
    ($owned_type:ident => $int:ty) => {
        #[derive(Default, Clone, Copy, PartialEq, Debug)]
        pub struct $owned_type(pub $int);

        impl From<$int> for $owned_type {
            fn from(val: $int) -> Self {
                tick!();
                Self(val)
            }
        }

        impl Deref for $owned_type {
            type Target = $int;

            fn deref(&self) -> &Self::Target {
                tick!();
                &self.0
            }
        }

        impl DerefMut for $owned_type {
            fn deref_mut(&mut self) -> &mut Self::Target {
                tick!();
                &mut self.0
            }
        }

        impl Serialize for $owned_type {
            const MAX_SIZE: usize = core::mem::size_of::<$int>();

            fn serialize(&self, writer: &mut impl Write) -> Result<()> {
                tick!();
                self.0.serialize(writer)
            }
        }

        impl<'a> Deserialize<'a> for $owned_type {
            fn deserialize(reader: &mut impl ReadRef<'a>) -> Result<Self> {
                tick!();
                Ok(Self::from(<$int>::deserialize(reader)?))
            }
        }
    };
}

#[derive(Default, Copy, Clone, PartialEq, Debug)]
pub struct Varint(pub usize);

impl Varint {
    const MAX_1: usize = 1 << 6;
    const MAX_2: usize = 1 << 14;
    const MAX_4: usize = 1 << 30;

    pub const fn size(n: usize) -> usize {
        match n {
            n if n < Self::MAX_1 => 1,
            n if n < Self::MAX_2 => 2,
            n if n < Self::MAX_4 => 4,

            // XXX(RLB) This isn't technically correct, since this value will never serialize.  But
            // it saves having to return Result<usize> from a const fn.
            _ => 8,
        }
    }
}

impl Serialize for Varint {
    const MAX_SIZE: usize = 4;

    fn serialize(&self, writer: &mut impl Write) -> Result<()> {
        tick!();
        let val: u32 = self.0.try_into().map_err(|_| Error("Invalid value"))?;
        let mut data = val.to_be_bytes();

        match val {
            _ if self.0 < Self::MAX_1 => writer.write(&data[3..]),
            _ if self.0 < Self::MAX_2 => {
                data[2] |= 0x40;
                writer.write(&data[2..])
            }
            _ if self.0 < Self::MAX_4 => {
                data[0] |= 0x80;
                writer.write(&data)
            }

            _ => Err(Error("Invalid value")),
        }
    }
}

impl<'a> Deserialize<'a> for Varint {
    fn deserialize(reader: &mut impl ReadRef<'a>) -> Result<Self> {
        tick!();
        let first_byte = reader.peek()?;
        let len = 1 << usize::from(first_byte >> 6);
        let data = reader.read_ref(len)?;

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
            _ => return Err(Error("Invalid encoding")),
        };

        Ok(Self(val))
    }
}

// XXX(RLB): Note that in order to use vectors in structs / enums, you will need to alias the view
// type with fixed type and length, so that the only free parameter is the lifetime.

impl<T: Serialize, const N: usize> Serialize for Vec<T, N> {
    const MAX_SIZE: usize = Varint::size(N * T::MAX_SIZE) + N * T::MAX_SIZE;

    fn serialize(&self, writer: &mut impl Write) -> Result<()> {
        tick!();
        // First, serialize everything to a writer that just counts how much would be serialized
        let mut counter = CountWriter::default();
        for val in self.iter() {
            val.serialize(&mut counter)?;
        }

        // Then, serialize the length
        Varint(counter.len()).serialize(writer)?;

        // Then serialize the contents for real
        for val in self.iter() {
            val.serialize(writer)?;
        }
        Ok(())
    }
}

impl<'a, V: Deserialize<'a>, const N: usize> Deserialize<'a> for Vec<V, N> {
    fn deserialize(reader: &mut impl ReadRef<'a>) -> Result<Self> {
        tick!();
        let len = Varint::deserialize(reader)?;

        let mut content = reader.take(len.0)?;
        let mut vec: Vec<V, N> = Vec::new();
        while !content.is_empty() {
            vec.push(V::deserialize(&mut content)?)
                .map_err(|_| Error("Too many items"))?;
        }

        Ok(vec)
    }
}

#[derive(Clone, Default, Debug, PartialEq)]
pub struct Raw<const N: usize>(Vec<u8, N>);

impl<const N: usize> From<Vec<u8, N>> for Raw<N> {
    fn from(val: Vec<u8, N>) -> Self {
        tick!();
        Self(val)
    }
}

impl<const N: usize> TryFrom<&[u8]> for Raw<N> {
    type Error = Error;

    fn try_from(val: &[u8]) -> Result<Self> {
        tick!();
        (val.len() == N)
            .then_some(Self(Vec::try_from(val).unwrap()))
            .ok_or(Error("Invalid object"))
    }
}

impl<const N: usize> AsRef<[u8]> for Raw<N> {
    fn as_ref(&self) -> &[u8] {
        tick!();
        self.0.as_ref()
    }
}

impl<const N: usize> AsMut<[u8]> for Raw<N> {
    fn as_mut(&mut self) -> &mut [u8] {
        tick!();
        self.0.as_mut()
    }
}

impl<const N: usize> Serialize for Raw<N> {
    const MAX_SIZE: usize = N;

    fn serialize(&self, writer: &mut impl Write) -> Result<()> {
        tick!();
        if self.0.len() != N {
            return Err(Error("Invalid object"));
        }

        writer.write(&self.0)
    }
}

impl<'a, const N: usize> Deserialize<'a> for Raw<N> {
    fn deserialize(reader: &mut impl ReadRef<'a>) -> Result<Self> {
        tick!();
        let content = reader.read_ref(N)?;
        Self::try_from(content)
    }
}

#[derive(Clone, Default, Debug, PartialEq)]
pub struct Opaque<const N: usize>(pub Vec<u8, N>);

impl<const N: usize> From<Raw<N>> for Opaque<N> {
    fn from(val: Raw<N>) -> Self {
        tick!();
        Opaque(val.0)
    }
}

impl<const N: usize> From<Vec<u8, N>> for Opaque<N> {
    fn from(val: Vec<u8, N>) -> Self {
        tick!();
        Self(val)
    }
}

impl<const N: usize> TryFrom<&[u8]> for Opaque<N> {
    type Error = Error;

    fn try_from(val: &[u8]) -> Result<Self> {
        tick!();
        let vec = Vec::try_from(val).map_err(|_| Error("Too many values"))?;
        Ok(Self::from(vec))
    }
}

impl<const N: usize> AsRef<[u8]> for Opaque<N> {
    fn as_ref(&self) -> &[u8] {
        tick!();
        self.0.as_ref()
    }
}

impl<const N: usize> AsMut<[u8]> for Opaque<N> {
    fn as_mut(&mut self) -> &mut [u8] {
        tick!();
        self.0.as_mut()
    }
}

impl<const N: usize> Serialize for Opaque<N> {
    const MAX_SIZE: usize = Varint::size(N) + N;

    fn serialize(&self, writer: &mut impl Write) -> Result<()> {
        tick!();
        Varint(self.0.len()).serialize(writer)?;
        writer.write(&self.0)
    }
}

impl<'a, const N: usize> Deserialize<'a> for Opaque<N> {
    fn deserialize(reader: &mut impl ReadRef<'a>) -> Result<Self> {
        tick!();
        let len = Varint::deserialize(reader)?;
        let content = reader.read_ref(len.0)?;
        Self::try_from(content)
    }
}

pub const fn sum(array: &[usize]) -> usize {
    let mut i = 0;
    let mut sum = 0;
    while i < array.len() {
        sum += array[i];
        i += 1;
    }
    sum
}

pub const fn max(array: &[usize]) -> usize {
    let mut i = 0;
    let mut max = 0;
    while i < array.len() {
        if array[i] > max {
            max = array[i];
        }
        i += 1
    }
    max
}

#[macro_export]
macro_rules! mls_newtype_opaque {
    ($owned_type:ident, $size:expr) => {
        #[derive(Clone, Default, Debug, PartialEq)]
        pub struct $owned_type(pub Opaque<{ $size }>);

        impl From<Opaque<{ $size }>> for $owned_type {
            fn from(val: Opaque<{ $size }>) -> Self {
                tick!();
                Self(val)
            }
        }

        impl From<$owned_type> for Opaque<{ $size }> {
            fn from(val: $owned_type) -> Self {
                tick!();
                val.0
            }
        }

        impl Deref for $owned_type {
            type Target = Opaque<{ $size }>;

            fn deref(&self) -> &Self::Target {
                tick!();
                &self.0
            }
        }

        impl DerefMut for $owned_type {
            fn deref_mut(&mut self) -> &mut Self::Target {
                tick!();
                &mut self.0
            }
        }

        impl Serialize for $owned_type {
            const MAX_SIZE: usize = Opaque::<{ $size }>::MAX_SIZE;

            fn serialize(&self, writer: &mut impl Write) -> Result<()> {
                tick!();
                self.0.serialize(writer)
            }
        }

        impl<'a> Deserialize<'a> for $owned_type {
            fn deserialize(reader: &mut impl ReadRef<'a>) -> Result<Self> {
                tick!();
                Ok(Self(Opaque::deserialize(reader)?))
            }
        }

        impl TryFrom<&[u8]> for $owned_type {
            type Error = Error;

            fn try_from(val: &[u8]) -> Result<Self> {
                tick!();
                let vec = Vec::try_from(val).map_err(|_| Error("Too many values"))?;
                Ok(Self(Opaque::from(vec)))
            }
        }

        impl AsRef<[u8]> for $owned_type {
            fn as_ref(&self) -> &[u8] {
                tick!();
                self.0.as_ref()
            }
        }
    };
}

#[macro_export]
macro_rules! mls_struct {
    ($owned_type:ident, $($field_name:ident: $field_type:ident,)*) => {
        #[derive(Clone, Default, Debug, PartialEq)]
        pub struct $owned_type {
            $(pub $field_name: $field_type,)*
        }

        impl Serialize for $owned_type {
            const MAX_SIZE: usize = sum(&[$($field_type::MAX_SIZE, )*]);

            fn serialize(&self, writer: &mut impl Write) -> Result<()> {
tick!();
                $(self.$field_name.serialize(writer)?;)*
                Ok(())
            }
        }

        impl<'a> Deserialize<'a> for $owned_type {
            fn deserialize(reader: &mut impl ReadRef<'a>) -> Result<Self> {
                tick!();
                Ok(Self{
                    $($field_name: $field_type::deserialize(reader)?,)*
                })
            }
        }
    }
}

#[macro_export]
macro_rules! mls_enum {
    ($disc_type:ident => $owned_type:ident, $($variant_disc:expr => $variant_name:ident($variant_type:ident),)*) => {
        #[derive(Clone, Debug, PartialEq)]
        pub enum $owned_type {
            $($variant_name($variant_type),)*
        }

        impl Serialize for $owned_type {
            const MAX_SIZE: usize = $disc_type::MAX_SIZE + max(&[$($variant_type::MAX_SIZE, )*]);

            fn serialize(&self, writer: &mut impl Write) -> Result<()> {
                tick!();
                match self {
                    $(
                    Self::$variant_name(x) => {
                        $disc_type::serialize(&$variant_disc, writer)?;
                        x.serialize(writer)
                    }
                    )*
                }
            }
        }

        impl<'a> Deserialize<'a> for $owned_type {
            fn deserialize(reader: &mut impl ReadRef<'a>) -> Result<Self> {
                tick!();
                let disc = $disc_type::deserialize(reader)?;
                match disc {
                    $($variant_disc => Ok(Self::$variant_name($variant_type::deserialize(reader)?)),)*
                    _ => Err(Error("Invalid encoding")),
                }
            }
        }
    };
}

#[cfg(test)]
mod test {
    use super::*;

    use crate::io::SliceReader;

    use core::fmt::Debug;
    use core::ops::{Deref, DerefMut};
    use hex_literal::hex;

    fn test_serde<'a, T, const N: usize>(val: &'a T, bytes: &'a [u8], mut storage: Vec<u8, N>)
    where
        T: Serialize + Deserialize<'a> + PartialEq + Debug + 'a,
    {
        // Serialization
        val.serialize(&mut storage).unwrap();
        assert_eq!(&storage, bytes);

        // Deserialization
        let deserialized = T::deserialize(&mut SliceReader(bytes)).unwrap();
        assert_eq!(&deserialized, val);
    }

    #[test]
    fn primitives() {
        let storage = make_storage!(Nil);
        test_serde(&Nil, &hex!(""), storage);

        let storage = make_storage!(u8);
        test_serde(&0xa0_u8, &hex!("a0"), storage);

        let storage = make_storage!(u16);
        test_serde(&0xa0a1_u16, &hex!("a0a1"), storage);

        let storage = make_storage!(u32);
        test_serde(&0xa0a1a2a3_u32, &hex!("a0a1a2a3"), storage);

        let storage = make_storage!(u64);
        test_serde(&0xa0a1a2a3a4a5a6a7_u64, &hex!("a0a1a2a3a4a5a6a7"), storage);
    }

    #[test]
    fn varint() {
        let storage = make_storage!(Varint);
        test_serde(&Varint(0x3f), &hex!("3f"), storage);

        let storage = make_storage!(Varint);
        test_serde(&Varint(0x3fff), &hex!("7fff"), storage);

        let storage = make_storage!(Varint);
        test_serde(&Varint(0x3fffffff), &hex!("bfffffff"), storage);
    }

    #[test]
    fn vector() {
        const N: usize = 5;
        let storage = make_storage!(Vec<u32, N>);

        let vals = [0xa0a0a0a0_u32; N];
        let owned: Vec<u32, N> = vals.as_ref().try_into().unwrap();
        let serialized = &hex!("14a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0");

        test_serde(&owned, serialized, storage);
    }

    #[test]
    fn opaque() {
        const N: usize = 64;
        let storage = make_storage!(Opaque<N>);

        let vals = [0xa0; N];
        let owned = Vec::<u8, N>::from_slice(&vals).unwrap();

        let serialized = &hex!("4040"
            "a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0"
            "a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0"
            "a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0"
            "a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0"
        );

        test_serde(&Opaque::<N>::from(owned), serialized, storage);
    }

    mls_newtype_primitive! { TestU8 => u8 }
    mls_newtype_primitive! { TestU16 => u16 }
    mls_newtype_primitive! { TestU32 => u32 }

    mls_newtype_opaque! { TestOpaque, 5 }

    #[test]
    fn mls_newtype() {
        assert_eq!(TestU16::MAX_SIZE, u16::MAX_SIZE);
        assert_eq!(TestOpaque::MAX_SIZE, 6);

        let storage = make_storage!(TestU16);
        let value = 0x0123;

        test_serde(&TestU16::from(value), &hex!("0123"), storage);

        let storage = make_storage!(TestOpaque);
        let opaque = [1_u8, 2, 3, 4, 5];

        test_serde(
            &TestOpaque::try_from(opaque.as_ref()).unwrap(),
            &hex!("050102030405"),
            storage,
        );
    }

    mls_struct! {
        TestStruct,
        field1: TestU32,
        field2: TestU8,
        field3: TestOpaque,
    }

    #[test]
    fn mls_struct() {
        assert_eq!(TestStruct::MAX_SIZE, 11);

        let storage = make_storage!(TestStruct);

        let raw1 = 0x01234567;
        let raw2 = 0xff;
        let raw3 = [1_u8, 2, 3, 4, 5];

        let owned = TestStruct {
            field1: TestU32::from(raw1),
            field2: TestU8::from(raw2),
            field3: TestOpaque::try_from(raw3.as_ref()).unwrap(),
        };

        let serialized = &hex!("01234567ff050102030405");

        test_serde(&owned, serialized, storage);
    }

    mls_enum! {
        u8 => TestEnum,
        1 => A(TestU32),
        2 => B(TestU8),
        3 => C(TestOpaque),
    }

    #[test]
    fn mls_enum() {
        let raw = 0x01234567;
        test_serde(
            &TestEnum::A(raw.into()),
            &hex!("0101234567"),
            make_storage!(TestEnum),
        );

        let raw = 0xff;
        test_serde(
            &TestEnum::B(raw.into()),
            &hex!("02ff"),
            make_storage!(TestEnum),
        );

        let raw = [1_u8, 2, 3, 4, 5];
        test_serde(
            &TestEnum::C(raw.as_ref().try_into().unwrap()),
            &hex!("03050102030405"),
            make_storage!(TestEnum),
        );
    }
}
