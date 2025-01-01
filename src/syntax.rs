use crate::common::*;
use crate::io::{ReadRef, Write};

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

// Primitives

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

// Varint and Vector

#[derive(Default, Copy, Clone, PartialEq, Debug)]
struct Varint(usize);

impl Serialize for Varint {
    const MAX_SIZE: usize = 4;

    fn serialize(&self, writer: &mut impl Write) -> Result<()> {
        let data = &mut self.0.to_be_bytes()[4..];
        if self.0 < (1 << 6) {
            writer.write(&data[3..4])?;
            Ok(())
        } else if self.0 < (1 << 14) {
            data[2] |= 0x40;
            writer.write(&data[2..4])?;
            Ok(())
        } else if self.0 < (1 << 30) {
            data[0] |= 0x80;
            writer.write(&data[..4])?;
            Ok(())
        } else {
            Err(Error("Invalid value"))
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
    const MAX_SIZE: usize = N * T::MAX_SIZE;

    fn serialize(&self, writer: &mut impl Write) -> Result<()> {
        for val in self.0.iter() {
            val.serialize(writer)?;
        }
        Ok(())
    }
}

impl<'a, V: Deserialize<'a>, const N: usize> Deserialize<'a> for VectorView<'a, V, N> {
    fn deserialize(reader: &mut impl ReadRef<'a>) -> Result<Self> {
        let vec: Result<Vec<V, N>> = (0..N).map(|_| V::deserialize(reader)).collect();
        Ok(Self(vec?, PhantomData))
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

        let serialized = &hex!("a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0");

        test_serde(
            Vector::from(owned),
            VectorView::from(views),
            serialized,
            storage,
        );
    }
}
