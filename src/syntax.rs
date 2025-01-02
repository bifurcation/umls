use crate::common::*;
use crate::io::{CountWriter, ReadRef, Write};

use core::convert::{TryFrom, TryInto};
use core::marker::PhantomData;
use core::ops::{Deref, DerefMut};
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

// XXX(RLB) Note that these types can only be included in newtypes / structs / enums if they are
// first wrapped using the `primitive_newtype!` enum.  This is because the compunding macros assume
// that the "view" type (the one that implements Deserialize) has a lifetime parameter.

type PhantomLifetime<'a> = PhantomData<&'a ()>;

#[derive(Default, Clone, Copy, PartialEq, Debug)]
struct Nil;

#[derive(Clone, Copy, PartialEq, Debug)]
struct NilView<'a>(&'a ());

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

macro_rules! primitive_int_serde {
    ($int:ty => $value_type:ident + $view_type:ident) => {
        #[derive(Default, Clone, Copy, PartialEq, Debug)]
        struct $value_type($int);

        #[derive(Clone, Copy, PartialEq, Debug)]
        struct $view_type<'a>($int, PhantomLifetime<'a>);

        impl From<$int> for $value_type {
            fn from(val: $int) -> Self {
                Self(val)
            }
        }

        impl Deref for $value_type {
            type Target = $int;

            fn deref(&self) -> &Self::Target {
                &self.0
            }
        }

        impl DerefMut for $value_type {
            fn deref_mut(&mut self) -> &mut Self::Target {
                &mut self.0
            }
        }

        impl Serialize for $value_type {
            const MAX_SIZE: usize = core::mem::size_of::<$int>();

            fn serialize(&self, writer: &mut impl Write) -> Result<()> {
                writer.write(&self.0.to_be_bytes())
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
                const N: usize = <$value_type>::MAX_SIZE;
                let slice = reader.read_ref(N)?;
                let array: [u8; N] = slice.try_into().map_err(|_| Error("Unknown error"))?;
                let val = <$int>::from_be_bytes(array);
                Ok(Self::from(val))
            }
        }
    };
}

primitive_int_serde!(u8 => U8 + U8View);
primitive_int_serde!(u16 => U16 + U16View);
primitive_int_serde!(u32 => U32 + U32View);
primitive_int_serde!(u64 => U64 + U64View);

#[derive(Default, Copy, Clone, PartialEq, Debug)]
struct Varint(usize);

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

// XXX(RLB): Note that in order to use these in newtypes / enums / structs, you will need to alias
// the view type with fixed type and length, so that the only free parameter is the lifetime.

#[derive(Clone, Default, Debug, PartialEq)]
struct Vector<T: Serialize, const N: usize>(pub Vec<T, N>);

impl<T: Serialize, const N: usize> From<Vec<T, N>> for Vector<T, N> {
    fn from(val: Vec<T, N>) -> Self {
        Self(val)
    }
}

#[derive(Clone, Debug, PartialEq)]
struct VectorView<'a, V: Deserialize<'a>, const N: usize>(pub Vec<V, N>, PhantomLifetime<'a>);

impl<'a, V: Deserialize<'a>, const N: usize> From<Vec<V, N>> for VectorView<'a, V, N> {
    fn from(val: Vec<V, N>) -> Self {
        Self(val, PhantomData)
    }
}

impl<T: Serialize, const N: usize> Serialize for Vector<T, N> {
    const MAX_SIZE: usize = Varint::size(N * T::MAX_SIZE) + N * T::MAX_SIZE;

    fn serialize(&self, writer: &mut impl Write) -> Result<()> {
        // First, serialize everything to a writer that just counts how much would be serialized
        let mut counter = CountWriter::default();
        for val in self.0.iter() {
            val.serialize(&mut counter)?;
        }

        // Then, serialize the length
        Varint(counter.len()).serialize(writer)?;

        // Then serialize the contents for real
        for val in self.0.iter() {
            val.serialize(writer)?;
        }
        Ok(())
    }
}

impl<'a, V: Deserialize<'a>, const N: usize> Deserialize<'a> for VectorView<'a, V, N> {
    fn deserialize(reader: &mut impl ReadRef<'a>) -> Result<Self> {
        let len = Varint::deserialize(reader)?;

        let mut content = reader.take(len.0)?;
        let mut vec: Vec<V, N> = Vec::new();
        while !content.is_empty() {
            vec.push(V::deserialize(&mut content)?)
                .map_err(|_| Error("Too many items"))?;
        }

        Ok(Self(vec, PhantomData))
    }
}

#[derive(Clone, Default, Debug, PartialEq)]
struct Opaque<const N: usize>(pub Vec<u8, N>);

impl<const N: usize> From<Vec<u8, N>> for Opaque<N> {
    fn from(val: Vec<u8, N>) -> Self {
        Self(val)
    }
}

#[derive(Clone, Debug, PartialEq)]
struct OpaqueView<'a, const N: usize>(pub &'a [u8]);

impl<'a, const N: usize> TryFrom<&'a [u8]> for OpaqueView<'a, N> {
    type Error = Error;

    fn try_from(val: &'a [u8]) -> Result<Self> {
        (val.len() <= N)
            .then_some(Self(val))
            .ok_or(Error("Too many items"))
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

#[cfg(test)]
mod test {
    use super::*;
    use crate::io::SliceReader;

    use core::fmt::Debug;
    use hex_literal::hex;

    fn test_serde<'a, T, V, const N: usize>(
        val: T,
        view: V,
        bytes: &'a [u8],
        mut storage: Vec<u8, N>,
    ) where
        T: Serialize,
        V: Deserialize<'a> + PartialEq + Debug,
    {
        // Serialization
        val.serialize(&mut storage).unwrap();
        assert_eq!(&storage, bytes);

        // Deserialization
        let mut reader = SliceReader::new(bytes);
        let deserialized = V::deserialize(&mut reader).unwrap();
        assert_eq!(view, deserialized);
    }

    #[test]
    fn primitives() {
        let storage = make_storage!(Nil);
        test_serde(Nil, NilView(&()), &hex!(""), storage);

        let storage = make_storage!(U8);
        test_serde(U8::from(0xa0), U8View::from(0xa0), &hex!("a0"), storage);

        let storage = make_storage!(U16);
        test_serde(
            U16::from(0xa0a1),
            U16View::from(0xa0a1),
            &hex!("a0a1"),
            storage,
        );

        let storage = make_storage!(U32);
        test_serde(
            U32::from(0xa0a1a2a3),
            U32View::from(0xa0a1a2a3),
            &hex!("a0a1a2a3"),
            storage,
        );

        let storage = make_storage!(U64);
        test_serde(
            U64::from(0xa0a1a2a3a4a5a6a7),
            U64View::from(0xa0a1a2a3a4a5a6a7),
            &hex!("a0a1a2a3a4a5a6a7"),
            storage,
        );
    }

    #[test]
    fn varint() {
        let storage = make_storage!(Varint);
        test_serde(Varint(0x3f), Varint(0x3f), &hex!("3f"), storage);

        let storage = make_storage!(Varint);
        test_serde(Varint(0x3fff), Varint(0x3fff), &hex!("7fff"), storage);

        let storage = make_storage!(Varint);
        test_serde(
            Varint(0x3fffffff),
            Varint(0x3fffffff),
            &hex!("bfffffff"),
            storage,
        );
    }

    #[test]
    fn vector() {
        const N: usize = 5;
        let storage = make_storage!(Vector<U32, N>);

        let vals = [0xa0a0a0a0_u32; N];
        let owned: Vec<U32, N> = vals.iter().cloned().map(U32::from).collect();
        let views: Vec<U32View, N> = vals.iter().cloned().map(U32View::from).collect();

        let serialized = &hex!("14a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0");

        test_serde(
            Vector::from(owned),
            VectorView::from(views),
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
            Opaque::<N>::from(owned),
            OpaqueView::<N>::try_from(view).unwrap(),
            serialized,
            storage,
        );
    }
}
