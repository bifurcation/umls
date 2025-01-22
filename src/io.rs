use crate::common::*;

use heapless::Vec;

pub trait Write {
    /// Write a buffer to the stream.  Return an error if it was not possible to write the whole
    /// buffer.
    fn write(&mut self, data: &[u8]) -> Result<()>;
}

pub trait Read {
    fn read(&mut self, buf: &mut [u8]) -> Result<()>;
}

pub trait ReadRef<'a>: Sized {
    /// Returns a reference to the first `n` bytes read.  Returns an error if less than `n` bytes
    /// are available.
    fn read_ref(&mut self, n: usize) -> Result<&'a [u8]>;

    /// Are there more bytes to be read?
    fn is_empty(&self) -> bool;

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

impl<'a> Read for &'a [u8] {
    fn read(&mut self, buf: &mut [u8]) -> Result<()> {
        if buf.len() > self.len() {
            return Err(Error("Insufficient data"));
        }

        let (data, rest) = self.split_at(buf.len());
        buf.copy_from_slice(data);
        *self = rest;
        Ok(())
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

pub struct SliceReader<'a>(pub &'a [u8]);

impl<'a> ReadRef<'a> for SliceReader<'a> {
    fn read_ref(&mut self, n: usize) -> Result<&'a [u8]> {
        if self.0.len() < n {
            return Err(Error("Insufficient data"));
        }

        let (data, rest) = self.0.split_at(n);
        self.0 = rest;
        Ok(data)
    }

    fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    fn take(&mut self, n: usize) -> Result<Self> {
        Ok(Self(self.read_ref(n)?))
    }

    fn peek(&self) -> Result<u8> {
        if self.is_empty() {
            Err(Error("Insufficient data"))
        } else {
            Ok(self.0[0])
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
        let mut reader = SliceReader(DATA);
        assert_eq!(reader.peek().unwrap(), 0);

        let view = reader.read_ref(3).unwrap();
        assert_eq!(view, &DATA[0..3]);
        assert_eq!(reader.peek().unwrap(), 6);

        // Failed read
        assert!(reader.read_ref(6).is_err());

        let view = reader.read_ref(5).unwrap();
        assert_eq!(view, &DATA[3..]);
        assert!(reader.peek().is_err());
    }
}
