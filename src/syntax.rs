use crate::common::*;
use crate::io::{ReadRef, Write};

use core::marker::PhantomData;
use core::ops::{Deref, DerefMut};
use heapless::Vec;

pub trait Serialize {
    /// The maximum size of a serialized value
    const MAX_SIZE: usize;

    // This should be Vec<u8, Self::MAX_SIZE>, but the limitations of const generics don't allow
    // it.  Instead, use the storage!() macro below:
    //
    //     type Storage = storage!(MyTypeName);
    type Storage: Default + Write + AsRef<[u8]> + AsMut<[u8]> + Deref<Target = [u8]>;

    /// Serialize the provided object to the stream.
    fn serialize(&self, writer: &mut impl Write) -> Result<()>;
}

// XXX(RLB) This can't be generic because of the limitations of const generics
#[macro_export]
macro_rules! storage {
    ($t:ty) => {
        Vec<u8, { <$t as Serialize>::MAX_SIZE }>
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

    type Storage = storage!(Nil);

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

            type Storage = storage!($value_type);

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

// Arrays

// XXX(RLB): Note that in order to use these in newtypes / enums / structs, you will need to alias
// the view type with fixed type and length, so that the only free parameter is the lifetime.

struct Array<T: Serialize, const N: usize>(pub [T; N]);

struct ArrayView<'a, V: Deserialize<'a>, const N: usize>([V; N], PhantomLifetime<'a>);

impl<T: Serialize, const N: usize> Serialize for Array<T, N> {
    const MAX_SIZE: usize = N * T::MAX_SIZE;

    type Storage = Vec<u8, 0>; // XXX(RLB) This is wrong, but it can't be fixed.

    fn serialize(&self, writer: &mut impl Write) -> Result<()> {
        for val in self.0.iter() {
            val.serialize(writer)?;
        }
        Ok(())
    }
}

impl<'a, V: Deserialize<'a>, const N: usize> Deserialize<'a> for ArrayView<'a, V, N> {
    fn deserialize(reader: &mut impl ReadRef<'a>) -> Result<Self> {
        let vec: Result<Vec<V, N>> = (0..N).map(|_| V::deserialize(reader)).collect();
        let arr = vec.and_then(|v| v.into_array().map_err(|_| Error("Unknown error")))?;
        Ok(Self(arr, PhantomData))
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::io::SliceReader;

    use core::fmt::Debug;

    fn test_serde<'a, T, V>(val: &T, view: &V, bytes: &'a [u8])
    where
        T: Serialize,
        V: Deserialize<'a> + PartialEq + Debug,
    {
        // Serialization
        let mut serialized = T::Storage::default();
        val.serialize(&mut serialized).unwrap();
        assert_eq!(serialized.as_ref(), bytes);

        // Deserialization
        let mut reader = SliceReader::new(bytes);
        let deserialized = V::deserialize(&mut reader).unwrap();
        assert_eq!(view, &deserialized);
    }

    #[test]
    fn primitives() {
        test_serde(&Nil, &NilView(&()), &[]);
        test_serde(&U8::from(0xa0), &U8View::from(0xa0), &[0xa0]);
        test_serde(&U16::from(0xa0a1), &U16View::from(0xa0a1), &[0xa0, 0xa1]);
        test_serde(
            &U32::from(0xa0a1a2a3),
            &U32View::from(0xa0a1a2a3),
            &[0xa0, 0xa1, 0xa2, 0xa3],
        );
        test_serde(
            &U64::from(0xa0a1a2a3a4a5a6a7),
            &U64View::from(0xa0a1a2a3a4a5a6a7),
            &[0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7],
        );
    }
}
