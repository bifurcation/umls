use crate::common::{Error, Result};
use crate::stack;

use heapless::Vec;

pub trait Write {
    /// Write a buffer to the stream.  Return an error if it was not possible to write the whole
    /// buffer.
    fn write(&mut self, data: &[u8]) -> Result<()>;
}

pub trait Read: Sized {
    /// Returns a reference to the first `n` bytes read.  Returns an error if less than `n` bytes
    /// are available.
    fn read(&mut self, n: usize) -> Result<&[u8]>;

    /// Are there more bytes to be read?
    fn is_empty(&self) -> bool;

    /// Create a new reader for the next `n` bytes, and advance this reader past those `n` bytes.
    fn take(&mut self, n: usize) -> Result<Self>;

    /// Look at the next byte without changing the stream
    fn peek(&self) -> Result<u8>;
}

impl<const N: usize> Write for Vec<u8, N> {
    fn write(&mut self, data: &[u8]) -> Result<()> {
        stack::update();
        stack::update();
        self.extend_from_slice(data)
            .map_err(|()| Error("Insufficient capacity"))
    }
}

impl Read for &[u8] {
    fn read(&mut self, n: usize) -> Result<&[u8]> {
        stack::update();
        stack::update();
        if self.len() < n {
            return Err(Error("Insufficient data"));
        }

        let (data, rest) = self.split_at(n);
        *self = rest;
        Ok(data)
    }

    fn is_empty(&self) -> bool {
        stack::update();
        stack::update();
        <[u8]>::is_empty(self)
    }

    // XXX(RLB) This overlaps with read(), but can't be shared because of some lifetime issues
    fn take(&mut self, n: usize) -> Result<Self> {
        stack::update();
        stack::update();
        if self.len() < n {
            return Err(Error("Insufficient data"));
        }

        let (data, rest) = self.split_at(n);
        *self = rest;
        Ok(data)
    }

    fn peek(&self) -> Result<u8> {
        stack::update();
        stack::update();
        if self.is_empty() {
            return Err(Error("Insufficient data"));
        }

        Ok(self[0])
    }
}

pub struct CountWriter {
    len: usize,
}

impl Default for CountWriter {
    fn default() -> Self {
        stack::update();
        Self { len: 0 }
    }
}

impl CountWriter {
    #[must_use]
    pub fn len(&self) -> usize {
        stack::update();
        self.len
    }
}

impl Write for CountWriter {
    fn write(&mut self, data: &[u8]) -> Result<()> {
        stack::update();
        self.len += data.len();
        Ok(())
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
        let mut reader = DATA;
        assert_eq!(reader.peek().unwrap(), 0);

        let view = reader.read(3).unwrap();
        assert_eq!(view, &DATA[0..3]);
        assert_eq!(reader.peek().unwrap(), 6);

        // Failed read
        assert!(reader.read(6).is_err());

        let view = reader.read(5).unwrap();
        assert_eq!(view, &DATA[3..]);
        assert!(reader.peek().is_err());
    }
}
