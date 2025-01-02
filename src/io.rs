use crate::common::*;

use heapless::Vec;

pub trait Write {
    /// Write a buffer to the stream.  Return an error if it was not possible to write the whole
    /// buffer.
    fn write(&mut self, buf: &[u8]) -> Result<()>;
}

pub trait ReadRef<'a>: Sized {
    /// Returns a reference to the first `n` bytes read.  Returns an error if less than `n` bytes
    /// are available.
    fn read_ref(&mut self, n: usize) -> Result<&'a [u8]>;

    /// How many bytes have been read from this reader
    fn position(&self) -> usize;

    /// Are there more bytes to be read?
    fn is_empty(&self) -> bool;

    /// Create a new reader on the same data stream, starting at the current position but
    /// reading and advancing independently.
    fn fork(&self) -> Self;

    /// Create a new reader for the next `n` bytes, and advance this reader past those `n` bytes.
    fn take(&mut self, n: usize) -> Result<Self>;

    /// Returns a copy of the first byte available.  Returns n error if the reader is empty.
    fn peek(&self) -> Result<u8>;
}

impl<const N: usize> Write for Vec<u8, N> {
    fn write(&mut self, data: &[u8]) -> Result<()> {
        self.extend_from_slice(data)
            .map_err(|_| Error("Insufficient capacity"))
    }
}

pub struct CountWriter {
    len: usize,
}

impl Default for CountWriter {
    fn default() -> Self {
        Self { len: 0 }
    }
}

impl CountWriter {
    pub fn len(&self) -> usize {
        self.len
    }
}

impl Write for CountWriter {
    fn write(&mut self, data: &[u8]) -> Result<()> {
        self.len += data.len();
        Ok(())
    }
}

#[derive(Clone)]
pub struct SliceReader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> SliceReader<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }
}

impl<'a> ReadRef<'a> for SliceReader<'a> {
    #[inline]
    fn read_ref(&mut self, n: usize) -> Result<&'a [u8]> {
        if self.pos + n > self.data.len() {
            return Err(Error("Insufficient data"));
        }

        let start = self.pos;
        self.pos += n;
        Ok(&self.data[start..self.pos])
    }

    fn position(&self) -> usize {
        self.pos
    }

    fn is_empty(&self) -> bool {
        self.pos >= self.data.len()
    }

    fn fork(&self) -> Self {
        Self {
            data: &self.data[self.pos..],
            pos: 0,
        }
    }

    fn take(&mut self, n: usize) -> Result<Self> {
        self.read_ref(n).map(Self::new)
    }

    fn peek(&self) -> Result<u8> {
        if self.pos >= self.data.len() {
            Err(Error("Insufficient data"))
        } else {
            Ok(self.data[self.pos])
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn write() {
        // Successful write
        const MSG: &[u8] = b"hello";
        let mut writer: Vec<u8, { MSG.len() }> = Vec::new();
        writer.write(MSG).unwrap();
        assert_eq!(MSG, &writer);

        // Failed write
        let mut writer: Vec<u8, { MSG.len() - 1 }> = Vec::new();
        assert!(writer.write(MSG).is_err());
    }

    #[test]
    fn count_write() {
        // Successful write
        const MSG: &[u8] = b"hello";
        const N: usize = 50;

        let mut writer = CountWriter::default();
        for i in 0..N {
            writer.write(MSG).unwrap();
            assert_eq!(writer.len(), (i + 1) * MSG.len());
        }
    }

    #[test]
    fn read() {
        // Successful raed
        const DATA: &[u8] = &[0, 2, 4, 6, 8, 10, 12, 14];
        let mut reader = SliceReader::new(DATA);
        assert_eq!(reader.position(), 0);
        assert_eq!(reader.peek().unwrap(), 0);

        let view = reader.read_ref(3).unwrap();
        assert_eq!(view, &DATA[0..3]);
        assert_eq!(reader.position(), 3);
        assert_eq!(reader.peek().unwrap(), 6);

        let mut sub = reader.fork();
        let view = sub.read_ref(4).unwrap();
        assert_eq!(view, &DATA[3..7]);
        assert_eq!(sub.position(), 4);
        assert_eq!(sub.peek().unwrap(), 14);
        assert_eq!(reader.position(), 3);
        assert_eq!(reader.peek().unwrap(), 6);

        // Failed read
        assert!(reader.read_ref(6).is_err());

        let view = reader.read_ref(5).unwrap();
        assert_eq!(view, &DATA[3..]);
        assert_eq!(reader.position(), 8);
        assert!(reader.peek().is_err());
    }
}
