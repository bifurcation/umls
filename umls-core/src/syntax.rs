use crate::common::{Error, Result};
use crate::io::{BorrowRead, CountWriter, Read, Write};
use crate::stack;

use aead::Buffer;
use core::fmt::Debug;
use heapless::Vec;

pub use derive_serialize::{Deserialize, Materialize, Serialize, View};

pub trait Serialize {
    /// The maximum size of a serialized value
    const MAX_SIZE: usize;

    /// Serialize the provided object to the stream.
    fn serialize(&self, writer: &mut impl Write) -> Result<()>;
}

pub trait View {
    type View<'a>: Parse<'a> + Debug + PartialEq
    where
        Self: 'a;

    fn as_view<'a>(&'a self) -> Self::View<'a>
    where
        Self: 'a;

    fn from_view<'a>(view: Self::View<'a>) -> Self;
}

pub trait Materialize: Serialize {
    /// A storage type that can hold a serialized object
    type Storage: Default + Write + AsRef<[u8]>;

    /// Create an owned object containing a serialized version of this object
    fn materialize(&self) -> Result<Self::Storage> {
        stack::update();
        let mut storage = Self::Storage::default();
        self.serialize(&mut storage)?;
        Ok(storage)
    }
}

pub trait Deserialize: Sized {
    /// Read an object of this type from the stream.
    fn deserialize(reader: &mut impl Read) -> Result<Self>;
}

pub trait Parse<'a>: Sized {
    /// Read an object of this type from the stream.
    fn parse(reader: &mut impl BorrowRead<'a>) -> Result<Self>;
}

// Serialization by reference
impl<T> Serialize for &T
where
    T: Serialize,
{
    const MAX_SIZE: usize = T::MAX_SIZE;

    fn serialize(&self, writer: &mut impl Write) -> Result<()> {
        stack::update();
        Serialize::serialize(*self, writer)
    }
}

// Primitives
#[derive(Copy, Clone, PartialEq, Debug, Default, Serialize, Deserialize)]
pub struct Nil;

impl<'a> TryFrom<&'a [u8]> for Nil {
    type Error = Error;

    fn try_from(data: &'a [u8]) -> Result<Self> {
        data.is_empty().then_some(Nil).ok_or(Error("Size error"))
    }
}

impl AsRef<[u8]> for Nil {
    fn as_ref(&self) -> &[u8] {
        &[]
    }
}

impl AsMut<[u8]> for Nil {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut []
    }
}

impl<'a> Parse<'a> for Nil {
    fn parse(_reader: &mut impl BorrowRead<'a>) -> Result<Self> {
        Ok(Nil)
    }
}

impl View for Nil {
    type View<'a> = Nil;

    fn as_view<'a>(&'a self) -> Self::View<'a>
    where
        Self: 'a,
    {
        stack::update();
        *self
    }

    fn from_view<'a>(view: Self::View<'a>) -> Self {
        stack::update();
        view
    }
}

macro_rules! impl_primitive_serde {
    ($t:ty) => {
        impl Serialize for $t {
            const MAX_SIZE: usize = core::mem::size_of::<$t>();

            fn serialize(&self, writer: &mut impl Write) -> Result<()> {
                stack::update();
                writer.write(&self.to_be_bytes())
            }
        }

        impl View for $t {
            type View<'a> = $t;

            fn as_view<'a>(&'a self) -> Self::View<'a>
            where
                Self: 'a,
            {
                stack::update();
                *self
            }

            fn from_view<'a>(view: Self::View<'a>) -> Self {
                view
            }
        }

        impl Deserialize for $t {
            fn deserialize(reader: &mut impl Read) -> Result<Self> {
                const N: usize = core::mem::size_of::<$t>();

                stack::update();
                let mut bytes = [0; N];
                bytes.copy_from_slice(reader.read(N)?);
                Ok(Self::from_be_bytes(bytes))
            }
        }

        impl<'a> Parse<'a> for $t {
            fn parse(reader: &mut impl BorrowRead<'a>) -> Result<Self> {
                <$t>::deserialize(reader)
            }
        }
    };
}

impl_primitive_serde!(u8);
impl_primitive_serde!(u16);
impl_primitive_serde!(u32);
impl_primitive_serde!(u64);

// Option
impl<T> Serialize for Option<T>
where
    T: Serialize,
{
    const MAX_SIZE: usize = 1 + T::MAX_SIZE;

    fn serialize(&self, writer: &mut impl Write) -> Result<()> {
        stack::update();
        match self {
            Some(val) => {
                writer.write(&[1])?;
                val.serialize(writer)
            }
            None => writer.write(&[0]),
        }
    }
}

impl<T> View for Option<T>
where
    T: View,
{
    type View<'a>
        = Option<T::View<'a>>
    where
        T: 'a;

    fn as_view<'a>(&'a self) -> Self::View<'a>
    where
        T: 'a,
    {
        stack::update();
        self.as_ref().map(View::as_view)
    }

    fn from_view<'a>(view: Self::View<'a>) -> Self {
        view.map(View::from_view)
    }
}

impl<T> Deserialize for Option<T>
where
    T: Deserialize,
{
    fn deserialize(reader: &mut impl Read) -> Result<Self> {
        stack::update();
        match u8::deserialize(reader)? {
            0 => Ok(None),
            1 => Ok(Some(T::deserialize(reader)?)),
            _ => Err(Error("Invalid encoding")),
        }
    }
}

impl<'a, T> Parse<'a> for Option<T>
where
    T: Parse<'a>,
{
    fn parse(reader: &mut impl BorrowRead<'a>) -> Result<Self> {
        stack::update();
        match u8::deserialize(reader)? {
            0 => Ok(None),
            1 => Ok(Some(T::parse(reader)?)),
            _ => Err(Error("Invalid encoding")),
        }
    }
}

// Byte arrays
impl<const N: usize> Serialize for [u8; N] {
    const MAX_SIZE: usize = N;

    fn serialize(&self, writer: &mut impl Write) -> Result<()> {
        stack::update();
        writer.write(self)
    }
}

impl<const N: usize> View for [u8; N] {
    type View<'a> = &'a [u8; N];

    fn as_view<'a>(&'a self) -> Self::View<'a>
    where
        Self: 'a,
    {
        stack::update();
        self
    }

    fn from_view<'a>(view: Self::View<'a>) -> Self {
        stack::update();
        view.clone()
    }
}

impl<const N: usize> Deserialize for [u8; N] {
    fn deserialize(reader: &mut impl Read) -> Result<Self> {
        stack::update();
        let mut arr = [0; N];
        arr.copy_from_slice(reader.read(N)?);
        Ok(arr)
    }
}

impl<'a, const N: usize> Parse<'a> for &'a [u8; N] {
    fn parse(reader: &mut impl BorrowRead<'a>) -> Result<Self> {
        stack::update();
        let slice = reader.borrow_read(N)?;
        Self::try_from(slice).map_err(move |_| Error("Size error"))
    }
}

// Varint
#[derive(Copy, Clone, PartialEq, Debug, Default)]
pub struct Varint(pub usize);

impl Varint {
    #[must_use]
    pub const fn size(x: usize) -> usize {
        match x.checked_ilog2() {
            None | Some(0..6) => 1,
            Some(..14) => 2,
            Some(..30) => 4,
            _ => panic!("invalid"),
        }
    }
}

impl Serialize for Varint {
    const MAX_SIZE: usize = 4;

    fn serialize(&self, writer: &mut impl Write) -> Result<()> {
        stack::update();
        match Self::size(self.0) {
            1 => (self.0 as u8).serialize(writer),
            2 => (0x4000 | self.0 as u16).serialize(writer),
            4 => (0x8000_0000 | self.0 as u32).serialize(writer),
            _ => Err(Error("Invalid value")),
        }
    }
}

impl View for Varint {
    type View<'a> = Varint;

    fn as_view<'a>(&'a self) -> Self::View<'a>
    where
        Self: 'a,
    {
        stack::update();
        *self
    }

    fn from_view<'a>(view: Self::View<'a>) -> Self {
        stack::update();
        view
    }
}

impl Deserialize for Varint {
    fn deserialize(reader: &mut impl Read) -> Result<Self> {
        stack::update();
        let first_byte = reader.peek()?;
        let len = 1 << usize::from(first_byte >> 6);

        let val = match len {
            1 => usize::from(u8::deserialize(reader)?),
            2 => usize::from(u16::deserialize(reader)?) & 0x3fff,
            4 => {
                let val = u32::deserialize(reader)?;
                let val = usize::try_from(val).map_err(|_| Error("usize too small"))?;
                val & 0x3fff_ffff
            }
            _ => return Err(Error("Invalid encoding")),
        };

        Ok(Self(val))
    }
}

impl<'a> Parse<'a> for Varint {
    fn parse(reader: &mut impl BorrowRead<'a>) -> Result<Self> {
        Varint::deserialize(reader)
    }
}

// Vec
impl<T: Serialize, const N: usize> Serialize for Vec<T, N> {
    const MAX_SIZE: usize = Varint::size(N * T::MAX_SIZE) + (N * T::MAX_SIZE);

    fn serialize(&self, writer: &mut impl Write) -> Result<()> {
        stack::update();
        let mut count = CountWriter::default();
        for val in self {
            val.serialize(&mut count)?;
        }

        Varint(count.len()).serialize(writer)?;
        for val in self {
            val.serialize(writer)?;
        }

        Ok(())
    }
}

impl<T, const N: usize> View for Vec<T, N>
where
    T: View,
{
    type View<'a>
        = Vec<T::View<'a>, N>
    where
        T: 'a;

    fn as_view<'a>(&'a self) -> Self::View<'a>
    where
        Self: 'a,
    {
        stack::update();
        self.iter().map(View::as_view).collect()
    }

    fn from_view<'a>(view: Self::View<'a>) -> Self {
        stack::update();
        view.into_iter().map(View::from_view).collect()
    }
}

impl<T: Deserialize, const N: usize> Deserialize for Vec<T, N> {
    fn deserialize(reader: &mut impl Read) -> Result<Self> {
        stack::update();
        let len = Varint::deserialize(reader)?;
        let mut sub_reader = reader.take(len.0)?;

        let mut vec = Vec::new();
        while !sub_reader.is_empty() {
            vec.push(T::deserialize(&mut sub_reader)?)
                .map_err(|_| Error("Too many elements"))?;
        }

        Ok(vec)
    }
}

impl<'a, T, const N: usize> Parse<'a> for Vec<T, N>
where
    T: Parse<'a>,
{
    fn parse(reader: &mut impl BorrowRead<'a>) -> Result<Self> {
        stack::update();
        let len = Varint::deserialize(reader)?;
        let mut sub_reader = reader.take(len.0)?;

        let mut vec = Vec::new();
        let mut empty = sub_reader.is_empty();
        while !empty {
            vec.push(T::parse(&mut sub_reader)?)
                .map_err(|_| Error("Too many elements"))?;
            empty = sub_reader.is_empty();
        }

        Ok(vec)
    }
}

// Raw
#[derive(Clone, PartialEq, Debug)]
pub struct Raw<const N: usize>(pub [u8; N]);

#[derive(Clone, PartialEq, Debug)]
pub struct RawView<'a, const N: usize>(pub &'a [u8; N]);

impl<const N: usize> Default for Raw<N> {
    fn default() -> Self {
        Self([0; N])
    }
}

impl<const N: usize> AsRef<[u8]> for Raw<N> {
    fn as_ref(&self) -> &[u8] {
        stack::update();
        self.0.as_ref()
    }
}

impl<const N: usize> TryFrom<&[u8]> for Raw<N> {
    type Error = Error;

    fn try_from(val: &[u8]) -> Result<Self> {
        stack::update();
        let arr = <[u8; N]>::try_from(val).map_err(|_| Error("Size error"))?;
        Ok(Self(arr))
    }
}

impl<const N: usize> Serialize for Raw<N> {
    const MAX_SIZE: usize = N;

    fn serialize(&self, writer: &mut impl Write) -> Result<()> {
        stack::update();
        writer.write(&self.0)
    }
}

impl<const N: usize> View for Raw<N> {
    type View<'a> = RawView<'a, N>;

    fn as_view<'a>(&'a self) -> Self::View<'a>
    where
        Self: 'a,
    {
        stack::update();
        let slice_view: &[u8] = self.0.as_ref();
        RawView(slice_view.try_into().unwrap())
    }

    fn from_view<'a>(view: Self::View<'a>) -> Self {
        Self(*view.0)
    }
}

impl<const N: usize> Deserialize for Raw<N> {
    fn deserialize(reader: &mut impl Read) -> Result<Self> {
        stack::update();
        let slice = reader.read(N)?;
        let arr = <[u8; N]>::try_from(slice).map_err(|_| Error("Size error"))?;
        Ok(Self(arr))
    }
}

impl<'a, const N: usize> Parse<'a> for RawView<'a, N> {
    fn parse(reader: &mut impl BorrowRead<'a>) -> Result<Self> {
        stack::update();
        let array_ref = <&[u8; N]>::parse(reader)?;
        Ok(Self(array_ref))
    }
}

// Opaque
#[derive(Clone, PartialEq, Debug, Default)]
pub struct Opaque<const N: usize>(pub Vec<u8, N>);

#[derive(Clone, PartialEq, Debug, Default)]
pub struct OpaqueView<'a, const N: usize>(pub &'a [u8]);

impl<const N: usize> AsRef<[u8]> for Opaque<N> {
    fn as_ref(&self) -> &[u8] {
        stack::update();
        self.0.as_ref()
    }
}

impl<const N: usize> AsMut<[u8]> for Opaque<N> {
    fn as_mut(&mut self) -> &mut [u8] {
        stack::update();
        self.0.as_mut()
    }
}

impl<const N: usize> TryFrom<&[u8]> for Opaque<N> {
    type Error = Error;

    fn try_from(val: &[u8]) -> Result<Self> {
        stack::update();
        let vec = Vec::try_from(val).map_err(|()| Error("Size error"))?;
        Ok(Self(vec))
    }
}

impl<const N: usize> Serialize for Opaque<N> {
    const MAX_SIZE: usize = Varint::size(N) + N;

    fn serialize(&self, writer: &mut impl Write) -> Result<()> {
        stack::update();
        Varint(self.0.len()).serialize(writer)?;
        writer.write(&self.0)
    }
}

impl<const N: usize> View for Opaque<N> {
    type View<'a> = OpaqueView<'a, N>;

    fn as_view<'a>(&'a self) -> Self::View<'a>
    where
        Self: 'a,
    {
        stack::update();
        OpaqueView(self.0.as_ref())
    }

    fn from_view<'a>(view: Self::View<'a>) -> Self {
        stack::update();
        Self::try_from(view.0).unwrap()
    }
}

impl<const N: usize> Deserialize for Opaque<N> {
    fn deserialize(reader: &mut impl Read) -> Result<Self> {
        stack::update();
        let len = Varint::deserialize(reader)?;

        let vec = Vec::from_slice(reader.read(len.0)?).map_err(|()| Error("Too many elements"))?;

        Ok(Self(vec))
    }
}

impl<'a, const N: usize> Parse<'a> for OpaqueView<'a, N> {
    fn parse(reader: &mut impl BorrowRead<'a>) -> Result<Self> {
        stack::update();
        let len = Varint::deserialize(reader)?;
        let slice = reader.borrow_read(len.0)?;
        Ok(Self(slice))
    }
}

impl<const N: usize> Buffer for Opaque<N> {
    fn extend_from_slice(&mut self, other: &[u8]) -> aead::Result<()> {
        self.0.extend_from_slice(other).map_err(|()| aead::Error)
    }

    fn truncate(&mut self, len: usize) {
        self.0.truncate(len);
    }
}

impl<const N: usize> Write for Opaque<N> {
    fn write(&mut self, data: &[u8]) -> Result<()> {
        self.0.write(data)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    use heapless::Vec;

    use hex_literal::hex;

    fn serde_test<T>(val: T, max_size: usize, enc: &[u8])
    where
        T: Serialize + Deserialize + PartialEq + core::fmt::Debug,
    {
        let mut storage = Vec::<u8, 100>::new();

        assert_eq!(T::MAX_SIZE, max_size);

        val.serialize(&mut storage).unwrap();
        assert_eq!(storage.as_slice(), enc);

        let val2 = T::deserialize(&mut storage.as_slice()).unwrap();
        assert_eq!(val, val2);
    }

    #[test]
    fn primitive() {
        let val = Nil;
        let enc = &hex!("");
        serde_test(val, 0, enc);

        let val = 0xa0_u8;
        let enc = &hex!("a0");
        serde_test(val, 1, enc);

        let val = 0xa0a0_u16;
        let enc = &hex!("a0a0");
        serde_test(val, 2, enc);

        let val = 0xa0a0a0a0_u32;
        let enc = &hex!("a0a0a0a0");
        serde_test(val, 4, enc);

        let val = 0xa0a0a0a0a0a0a0a0_u64;
        let enc = &hex!("a0a0a0a0a0a0a0a0");
        serde_test(val, 8, enc);
    }

    #[derive(PartialEq, Debug, Serialize, Deserialize)]
    struct Normal {
        f1: u8,
        f2: u16,
    }

    #[derive(PartialEq, Debug, Serialize, Deserialize)]
    struct Tuple(u8, u16);

    #[derive(PartialEq, Debug, Serialize, Deserialize)]
    struct Unit;

    #[derive(PartialEq, Debug, Serialize, Deserialize)]
    #[discriminant = "u32"]
    enum Enum {
        #[discriminant = "1"]
        V1(Normal),

        #[discriminant = "2"]
        V2(Tuple),
    }

    #[test]
    fn compound() {
        let val: Option<u32> = Some(0xa0a0a0a0);
        let enc = &hex!("01a0a0a0a0");
        serde_test(val, 5, enc);

        let val: Option<u32> = None;
        let enc = &hex!("00");
        serde_test(val, 5, enc);

        let val = Normal { f1: 1, f2: 2 };
        let enc = &hex!("010002");
        serde_test(val, 3, enc);

        let val = Tuple(3, 4);
        let enc = &hex!("030004");
        serde_test(val, 3, enc);

        let val = Unit;
        let enc = &hex!("");
        serde_test(val, 0, enc);

        let val = Enum::V1(Normal { f1: 1, f2: 2 });
        let enc = &hex!("00000001010002");
        serde_test(val, 7, enc);

        let val = Enum::V2(Tuple(3, 4));
        let enc = &hex!("00000002030004");
        serde_test(val, 7, enc);
    }

    #[test]
    fn varint() {
        let val = Varint(0x3f);
        let enc = &hex!("3f");
        serde_test(val, 4, enc);
    }

    #[test]
    fn vec() {
        let val: Vec<Varint, 5> =
            Vec::from_slice(&[Varint(0x3f), Varint(0x3fff), Varint(0x3fffffff)]).unwrap();
        let enc = &hex!("073f7fffbfffffff");
        serde_test(val, 21, enc);
    }

    #[test]
    fn opaque() {
        let val: Opaque<32> =
            Opaque(Vec::from_slice(&hex!("000102030405060708090a0b0c0d0e0f")).unwrap());
        let enc = &hex!("10000102030405060708090a0b0c0d0e0f");
        serde_test(val, 33, enc);
    }
}
