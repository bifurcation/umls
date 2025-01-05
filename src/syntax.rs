use crate::common::*;
use crate::io::{CountWriter, ReadRef, Write};

use core::convert::{TryFrom, TryInto};
use core::marker::PhantomData;
use heapless::Vec;

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

pub trait Deserialize<'a>: Sized {
    /// Deserialize the provided object from the stream.  This should usually be done with "view"
    /// or reference types, via the [ReadRef] trait.
    fn deserialize(reader: &mut impl ReadRef<'a>) -> Result<Self>;
}

pub trait AsView {
    type View<'a>: Deserialize<'a>
    where
        Self: 'a;

    fn as_view<'a>(&'a self) -> Self::View<'a>;
}

pub trait ToOwned {
    type Owned: Serialize;

    fn to_owned(&self) -> Self::Owned;
}

// XXX(RLB) Note that these types can only be included in structs / enums if they are first wrapped
// using the `mls_newtype_primitive!` enum.  This is because the compunding macros assume that the
// "view" type (the one that implements Deserialize) has a lifetime parameter.

pub type PhantomLifetime<'a> = PhantomData<&'a ()>;

#[derive(Default, Clone, Copy, PartialEq, Debug)]
pub struct Nil;

#[derive(Clone, Copy, PartialEq, Debug)]
pub struct NilView<'a>(&'a ());

impl Serialize for Nil {
    const MAX_SIZE: usize = 0;

    fn serialize(&self, writer: &mut impl Write) -> Result<()> {
        Ok(())
    }
}

impl<'a> Deserialize<'a> for NilView<'a> {
    fn deserialize(reader: &mut impl ReadRef<'a>) -> Result<Self> {
        Ok(NilView(&()))
    }
}

impl AsView for Nil {
    type View<'a> = NilView<'a>;

    fn as_view<'a>(&'a self) -> Self::View<'a> {
        NilView(&())
    }
}

impl<'a> ToOwned for NilView<'a> {
    type Owned = Nil;

    fn to_owned(&self) -> Self::Owned {
        Nil
    }
}

macro_rules! primitive_int_serde {
    ($int:ty) => {
        impl Serialize for $int {
            const MAX_SIZE: usize = core::mem::size_of::<$int>();

            fn serialize(&self, writer: &mut impl Write) -> Result<()> {
                writer.write(&self.to_be_bytes())
            }
        }

        impl<'a> Deserialize<'a> for $int {
            fn deserialize(reader: &mut impl ReadRef<'a>) -> Result<Self> {
                const N: usize = <$int>::MAX_SIZE;
                let slice = reader.read_ref(N)?;
                let array: [u8; N] = slice.try_into().map_err(|_| Error("Unknown error"))?;
                Ok(<$int>::from_be_bytes(array))
            }
        }

        impl AsView for $int {
            type View<'a> = $int;

            fn as_view<'a>(&'a self) -> Self::View<'a> {
                *self
            }
        }

        impl ToOwned for $int {
            type Owned = $int;

            fn to_owned(&self) -> Self::Owned {
                *self
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
    ($owned_type:ident + $view_type:ident => $int:ty) => {
        #[derive(Default, Clone, Copy, PartialEq, Debug)]
        pub struct $owned_type($int);

        #[derive(Clone, Copy, PartialEq, Debug)]
        pub struct $view_type<'a>($int, PhantomLifetime<'a>);

        impl From<$int> for $owned_type {
            fn from(val: $int) -> Self {
                Self(val)
            }
        }

        impl Deref for $owned_type {
            type Target = $int;

            fn deref(&self) -> &Self::Target {
                &self.0
            }
        }

        impl DerefMut for $owned_type {
            fn deref_mut(&mut self) -> &mut Self::Target {
                &mut self.0
            }
        }

        impl Serialize for $owned_type {
            const MAX_SIZE: usize = core::mem::size_of::<$int>();

            fn serialize(&self, writer: &mut impl Write) -> Result<()> {
                self.0.serialize(writer)
            }
        }

        impl<'a> From<$int> for $view_type<'a> {
            fn from(val: $int) -> Self {
                Self(val, PhantomData)
            }
        }

        impl<'a> Deref for $view_type<'a> {
            type Target = $int;

            fn deref(&self) -> &Self::Target {
                &self.0
            }
        }

        impl<'a> Deserialize<'a> for $view_type<'a> {
            fn deserialize(reader: &mut impl ReadRef<'a>) -> Result<Self> {
                Ok(Self::from(<$int>::deserialize(reader)?))
            }
        }

        impl AsView for $owned_type {
            type View<'a> = $view_type<'a>;

            fn as_view<'a>(&'a self) -> Self::View<'a> {
                $view_type::from(self.0)
            }
        }

        impl<'a> ToOwned for $view_type<'a> {
            type Owned = $owned_type;

            fn to_owned(&self) -> Self::Owned {
                $owned_type::from(self.0)
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

    const fn size(n: usize) -> usize {
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

impl AsView for Varint {
    type View<'a> = Varint;

    fn as_view<'a>(&'a self) -> Self::View<'a> {
        *self
    }
}

impl<'a> ToOwned for Varint {
    type Owned = Varint;

    fn to_owned(&self) -> Self::Owned {
        *self
    }
}

// XXX(RLB): Note that in order to use vectors in structs / enums, you will need to alias the view
// type with fixed type and length, so that the only free parameter is the lifetime.

impl<T: Serialize, const N: usize> Serialize for Vec<T, N> {
    const MAX_SIZE: usize = Varint::size(N * T::MAX_SIZE) + N * T::MAX_SIZE;

    fn serialize(&self, writer: &mut impl Write) -> Result<()> {
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

impl<T: Serialize + AsView, const N: usize> AsView for Vec<T, N> {
    type View<'a>
        = Vec<T::View<'a>, N>
    where
        T: 'a;

    fn as_view<'a>(&'a self) -> Self::View<'a> {
        self.iter().map(|t| t.as_view()).collect()
    }
}

impl<'a, V: Deserialize<'a> + ToOwned, const N: usize> ToOwned for Vec<V, N> {
    type Owned = Vec<V::Owned, N>;

    fn to_owned(&self) -> Self::Owned {
        self.iter().map(|v| v.to_owned()).collect()
    }
}

#[derive(Clone, Default, Debug, PartialEq)]
pub struct Opaque<const N: usize>(pub Vec<u8, N>);

impl<const N: usize> From<Vec<u8, N>> for Opaque<N> {
    fn from(val: Vec<u8, N>) -> Self {
        Self(val)
    }
}

impl<const N: usize> TryFrom<&[u8]> for Opaque<N> {
    type Error = Error;

    fn try_from(val: &[u8]) -> Result<Self> {
                let vec = Vec::try_from(val).map_err(|_| Error("Too many values"))?;
                Ok(Self::from(vec))
    }
}

impl<const N: usize> AsRef<[u8]> for Opaque<N> {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

#[derive(Copy, Clone, Debug, PartialEq)]
pub struct OpaqueView<'a, const N: usize>(pub &'a [u8]);

impl<'a, const N: usize> TryFrom<&'a [u8]> for OpaqueView<'a, N> {
    type Error = Error;

    fn try_from(val: &'a [u8]) -> Result<Self> {
        (val.len() <= N)
            .then_some(Self(val))
            .ok_or(Error("Too many items"))
    }
}

impl<'a, const N: usize> AsRef<[u8]> for OpaqueView<'a, N> {
    fn as_ref(&self) -> &[u8] {
        self.0
    }
}

impl<const N: usize> Serialize for Opaque<N> {
    const MAX_SIZE: usize = Varint::size(N) + N;

    fn serialize(&self, writer: &mut impl Write) -> Result<()> {
        Varint(self.0.len()).serialize(writer)?;
        writer.write(&self.0)
    }
}

impl<'a, const N: usize> Deserialize<'a> for OpaqueView<'a, N> {
    fn deserialize(reader: &mut impl ReadRef<'a>) -> Result<Self> {
        let len = Varint::deserialize(reader)?;
        let content = reader.read_ref(len.0)?;
        Self::try_from(content)
    }
}

impl<const N: usize> AsView for Opaque<N> {
    type View<'a> = OpaqueView<'a, N>;

    fn as_view<'a>(&'a self) -> Self::View<'a> {
        OpaqueView(&self.0)
    }
}

impl<'a, const N: usize> ToOwned for OpaqueView<'a, N> {
    type Owned = Opaque<N>;

    fn to_owned(&self) -> Self::Owned {
        // Unwrap is safe here because OpaqueView<N> can't be constructed with more than N elements
        Opaque(self.0.try_into().unwrap())
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
    ($owned_type:ident + $view_type:ident, 
     $inner_owned_type:ident + $inner_view_type:ident, 
     $size:expr) => {
        type $inner_owned_type = Opaque<{ $size }>;
        type $inner_view_type<'a> = OpaqueView<'a, { $size }>;

        #[derive(Clone, Default, Debug, PartialEq)]
        pub struct $owned_type($inner_owned_type);

        impl From<$inner_owned_type> for $owned_type {
            fn from(val: $inner_owned_type) -> Self {
                Self(val)
            }
        }

        impl Deref for $owned_type {
            type Target = $inner_owned_type;

            fn deref(&self) -> &Self::Target {
                &self.0
            }
        }

        #[derive(Copy, Clone, Debug, PartialEq)]
        pub struct $view_type<'a>($inner_view_type<'a>);

        impl<'a> From<$inner_view_type<'a>> for $view_type<'a> {
            fn from(val: $inner_view_type<'a>) -> Self {
                Self(val)
            }
        }

        impl<'a> Deref for $view_type<'a> {
            type Target = $inner_view_type<'a>;

            fn deref(&self) -> &Self::Target {
                &self.0
            }
        }

        impl Serialize for $owned_type {
            const MAX_SIZE: usize = $inner_owned_type::MAX_SIZE;

            fn serialize(&self, writer: &mut impl Write) -> Result<()> {
                self.0.serialize(writer)
            }
        }

        impl<'a> Deserialize<'a> for $view_type<'a> {
            fn deserialize(reader: &mut impl ReadRef<'a>) -> Result<Self> {
                Ok(Self($inner_view_type::deserialize(reader)?))
            }
        }

        impl AsView for $owned_type {
            type View<'a> = $view_type<'a>;

            fn as_view<'a>(&'a self) -> Self::View<'a> {
                $view_type::from(self.0.as_view())
            }
        }

        impl<'a> ToOwned for $view_type<'a> {
            type Owned = $owned_type;

            fn to_owned(&self) -> Self::Owned {
                $owned_type::from(self.0.to_owned())
            }
        }

        impl TryFrom<&[u8]> for $owned_type {
            type Error = Error;

            fn try_from(val: &[u8]) -> Result<Self> {
                let vec = Vec::try_from(val).map_err(|_| Error("Too many values"))?;
                Ok(Self(Opaque::from(vec)))
            }
        }
        
        impl<'a> TryFrom<&'a [u8]> for $view_type<'a> {
            type Error = Error;

            fn try_from(val: &'a [u8]) -> Result<Self> {
                Ok(Self(OpaqueView::try_from(val)?))
            }
        }

        impl AsRef<[u8]> for $owned_type {
            fn as_ref(&self) -> &[u8] {
                self.0.as_ref()
            }
        }
    };
}

#[macro_export]
macro_rules! mls_struct {
    ($owned_type:ident + $view_type:ident, $($field_name:ident: $field_type:ident + $field_view_type:ident,)*) => {
        #[derive(Clone, Default, Debug, PartialEq)]
        pub struct $owned_type {
            $($field_name: $field_type,)*
        }

        #[derive(Clone, Debug, PartialEq)]
        pub struct $view_type<'a> {
            $($field_name: $field_view_type<'a>,)*
        }

        impl Serialize for $owned_type {
            const MAX_SIZE: usize = sum(&[$($field_type::MAX_SIZE, )*]);

            fn serialize(&self, writer: &mut impl Write) -> Result<()> {
                $(self.$field_name.serialize(writer)?;)*
                Ok(())
            }
        }

        impl<'a> Deserialize<'a> for $view_type<'a> {
            fn deserialize(reader: &mut impl ReadRef<'a>) -> Result<Self> {
                Ok(Self{
                    $($field_name: $field_view_type::deserialize(reader)?,)*
                })
            }
        }

        impl AsView for $owned_type {
            type View<'a> = $view_type<'a>;

            fn as_view<'a>(&'a self) -> Self::View<'a> {
                Self::View {
                    $($field_name: self.$field_name.as_view(),)*
                }
            }
        }

        impl<'a> ToOwned for $view_type<'a> {
            type Owned = $owned_type;

            fn to_owned(&self) -> Self::Owned {
                Self::Owned {
                    $($field_name: self.$field_name.to_owned(),)*
                }
            }
        }
    }
}

#[macro_export]
macro_rules! mls_enum {
    ($disc_type:ident => $owned_type:ident + $view_type:ident, $($variant_disc:expr => $variant_name:ident($variant_type:ident + $variant_view_type:ident),)*) => {
        #[derive(Clone, Debug, PartialEq)]
        pub enum $owned_type {
            $($variant_name($variant_type),)*
        }

        #[derive(Clone, Debug, PartialEq)]
        pub enum $view_type<'a> {
            $($variant_name($variant_view_type<'a>),)*
        }

        impl Serialize for $owned_type {
            const MAX_SIZE: usize = $disc_type::MAX_SIZE + max(&[$($variant_type::MAX_SIZE, )*]);

            fn serialize(&self, writer: &mut impl Write) -> Result<()> {
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

        impl<'a> Deserialize<'a> for $view_type<'a> {
            fn deserialize(reader: &mut impl ReadRef<'a>) -> Result<Self> {
                let disc = $disc_type::deserialize(reader)?;
                match disc {
                    $($variant_disc => Ok(Self::$variant_name($variant_view_type::deserialize(reader)?)),)*
                    _ => Err(Error("Invalid encoding")),
                }
            }
        }

        impl AsView for $owned_type {
            type View<'a> = $view_type<'a>;

            fn as_view<'a>(&'a self) -> Self::View<'a> {
                match self {
                    $(Self::$variant_name(x) => Self::View::$variant_name(x.as_view()),)*
                }
            }
        }

        impl<'a> ToOwned for $view_type<'a> {
            type Owned = $owned_type;

            fn to_owned(&self) -> Self::Owned {
                match self {
                    $(Self::$variant_name(x) => Self::Owned::$variant_name(x.to_owned()),)*
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

    fn test_serde<'a, T, V, const N: usize>(
        val: &'a T,
        view: &'a V,
        bytes: &'a [u8],
        mut storage: Vec<u8, N>,
    ) where
        T: Serialize + AsView<View<'a> = V> + PartialEq + Debug + 'a,
        V: Deserialize<'a> + ToOwned<Owned = T> + PartialEq + Debug,
    {
        // Serialization
        val.serialize(&mut storage).unwrap();
        assert_eq!(&storage, bytes);

        // Deserialization
        let mut reader = SliceReader::new(bytes);
        let deserialized = V::deserialize(&mut reader).unwrap();
        assert_eq!(&deserialized, view);

        // AsView + ToOwned
        assert_eq!(val.as_view(), *view);
        assert_eq!(view.to_owned(), *val);
    }

    #[test]
    fn primitives() {
        let storage = make_storage!(Nil);
        test_serde(&Nil, &NilView(&()), &hex!(""), storage);

        let storage = make_storage!(u8);
        test_serde(&0xa0_u8, &0xa0_u8, &hex!("a0"), storage);

        let storage = make_storage!(u16);
        test_serde(
            &0xa0a1_u16,
            &0xa0a1_u16,
            &hex!("a0a1"),
            storage,
        );

        let storage = make_storage!(u32);
        test_serde(
            &0xa0a1a2a3_u32,
            &0xa0a1a2a3_u32,
            &hex!("a0a1a2a3"),
            storage,
        );

        let storage = make_storage!(u64);
        test_serde(
            &0xa0a1a2a3a4a5a6a7_u64,
            &0xa0a1a2a3a4a5a6a7_u64,
            &hex!("a0a1a2a3a4a5a6a7"),
            storage,
        );
    }

    #[test]
    fn varint() {
        let storage = make_storage!(Varint);
        test_serde(&Varint(0x3f), &Varint(0x3f), &hex!("3f"), storage);

        let storage = make_storage!(Varint);
        test_serde(&Varint(0x3fff), &Varint(0x3fff), &hex!("7fff"), storage);

        let storage = make_storage!(Varint);
        test_serde(
            &Varint(0x3fffffff),
            &Varint(0x3fffffff),
            &hex!("bfffffff"),
            storage,
        );
    }

    #[test]
    fn vector() {
        const N: usize = 5;
        let storage = make_storage!(Vec<u32, N>);

        let vals = [0xa0a0a0a0_u32; N];
        let owned: Vec<u32, N> = vals.as_ref().try_into().unwrap();
        let view: Vec<u32, N> = vals.as_ref().try_into().unwrap();

        let serialized = &hex!("14a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0");

        test_serde(
            &owned,
            &view,
            serialized,
            storage,
        );
    }

    #[test]
    fn opaque() {
        const N: usize = 64;
        let storage = make_storage!(Opaque<N>);

        let vals = [0xa0; N];
        let owned = Vec::<u8, N>::from_slice(&vals).unwrap();
        let view = &vals[..];

        let serialized = &hex!("4040"
            "a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0"
            "a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0"
            "a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0"
            "a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0"
        );

        test_serde(
            &Opaque::<N>::from(owned),
            &OpaqueView::<N>::try_from(view).unwrap(),
            serialized,
            storage,
        );
    }

    mls_newtype_primitive! { TestU8 + TestU8View => u8 }
    mls_newtype_primitive! { TestU16 + TestU16View => u16 }
    mls_newtype_primitive! { TestU32 + TestU32View => u32 }

    mls_newtype_opaque! {
        TestOpaque + TestOpaqueView, 
        TestOpaqueData + TestOpaqueViewData,
        5
    }

    #[test]
    fn mls_newtype() {
        assert_eq!(TestU16::MAX_SIZE, u16::MAX_SIZE);
        assert_eq!(TestOpaque::MAX_SIZE, 6);

        let storage = make_storage!(TestU16);
        let value = 0x0123;

        test_serde(
            &TestU16::from(value),
            &TestU16View::from(value),
            &hex!("0123"),
            storage,
        );

        let storage = make_storage!(TestOpaque);
        let opaque = [1_u8,2,3,4,5];

        test_serde(
            &TestOpaque::try_from(opaque.as_ref()).unwrap(),
            &TestOpaqueView::try_from(opaque.as_ref()).unwrap(),
            &hex!("050102030405"),
            storage,
        );

    }

    mls_struct! {
        TestStruct + TestStructView,
        field1: TestU32 + TestU32View,
        field2: TestU8 + TestU8View,
        field3: TestOpaque + TestOpaqueView,
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

        let view = TestStructView {
            field1: TestU32View::from(raw1),
            field2: TestU8View::from(raw2),
            field3: TestOpaqueView::try_from(raw3.as_ref()).unwrap(),
        };

        let serialized = &hex!("01234567ff050102030405");

        test_serde(&owned, &view, serialized, storage);
    }

    mls_enum! {
        u8 => TestEnum + TestEnumView,
        1 => A(TestU32 + TestU32View),
        2 => B(TestU8 + TestU8View),
        3 => C(TestOpaque + TestOpaqueView),
    }

    #[test]
    fn mls_enum() {
        let raw = 0x01234567;
        test_serde(
            &TestEnum::A(raw.into()),
            &TestEnumView::A(raw.into()),
            &hex!("0101234567"),
            make_storage!(TestEnum),
        );

        let raw = 0xff;
        test_serde(
            &TestEnum::B(raw.into()),
            &TestEnumView::B(raw.into()),
            &hex!("02ff"),
            make_storage!(TestEnum),
        );

        let raw = [1_u8, 2, 3, 4, 5];
        test_serde(
            &TestEnum::C(raw.as_ref().try_into().unwrap()),
            &TestEnumView::C(raw.as_ref().try_into().unwrap()),
            &hex!("03050102030405"),
            make_storage!(TestEnum),
        );
    }
}
