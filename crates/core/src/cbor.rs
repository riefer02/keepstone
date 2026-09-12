//! A minimal **canonical** CBOR codec.
//!
//! We implement only the subset Keepstone needs, and we enforce canonical form
//! on decode:
//!
//! - shortest-form integer heads (RFC 8949 §4.2.1)
//! - definite lengths only (no indefinite strings/arrays/maps)
//! - no trailing bytes
//!
//! This gives us a deterministic byte representation for *locally constructed*
//! signed objects. It does **not** change the rule that received objects are
//! identified by their exact transmitted bytes.
//!
//! > ADR note: the plan selected `cbor2`/`cose2`; M0 ships this small, auditable
//! > subset instead so the exact framing is under our control and dependency
//! > surface stays minimal. Revisit in M1/M2 if richer CBOR is needed.

use crate::error::CoreError;

const MAJOR_UINT: u8 = 0;
const MAJOR_BYTES: u8 = 2;
const MAJOR_TEXT: u8 = 3;
const MAJOR_ARRAY: u8 = 4;
const MAJOR_MAP: u8 = 5;
#[allow(dead_code)]
const MAJOR_SIMPLE: u8 = 7;

/// Canonical CBOR encoder.
#[derive(Debug, Default)]
pub struct Encoder {
    buf: Vec<u8>,
}

impl Encoder {
    /// Create an empty encoder.
    #[must_use]
    pub fn new() -> Self {
        Self { buf: Vec::new() }
    }

    /// Finish and return the encoded bytes.
    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.buf
    }

    fn head(&mut self, major: u8, value: u64) {
        let major_bits = major << 5;
        if value < 24 {
            self.buf
                .push(major_bits | u8::try_from(value).unwrap_or(23));
        } else if value <= u64::from(u8::MAX) {
            self.buf.push(major_bits | 24);
            self.buf.push(u8::try_from(value).unwrap_or(u8::MAX));
        } else if value <= u64::from(u16::MAX) {
            self.buf.push(major_bits | 25);
            self.buf
                .extend_from_slice(&u16::try_from(value).unwrap_or(u16::MAX).to_be_bytes());
        } else if value <= u64::from(u32::MAX) {
            self.buf.push(major_bits | 26);
            self.buf
                .extend_from_slice(&u32::try_from(value).unwrap_or(u32::MAX).to_be_bytes());
        } else {
            self.buf.push(major_bits | 27);
            self.buf.extend_from_slice(&value.to_be_bytes());
        }
    }

    /// Encode an unsigned integer.
    pub fn uint(&mut self, value: u64) {
        self.head(MAJOR_UINT, value);
    }

    /// Encode a byte string.
    pub fn bytes(&mut self, value: &[u8]) {
        self.head(MAJOR_BYTES, u64::try_from(value.len()).unwrap_or(u64::MAX));
        self.buf.extend_from_slice(value);
    }

    /// Encode a UTF-8 text string.
    pub fn text(&mut self, value: &str) {
        self.head(MAJOR_TEXT, u64::try_from(value.len()).unwrap_or(u64::MAX));
        self.buf.extend_from_slice(value.as_bytes());
    }

    /// Begin an array of `len` elements.
    pub fn array(&mut self, len: usize) {
        self.head(MAJOR_ARRAY, u64::try_from(len).unwrap_or(u64::MAX));
    }

    /// Begin a map of `len` entries.
    pub fn map(&mut self, len: usize) {
        self.head(MAJOR_MAP, u64::try_from(len).unwrap_or(u64::MAX));
    }

    /// Encode a boolean.
    pub fn bool(&mut self, value: bool) {
        self.buf.push(if value { 0xF5 } else { 0xF4 });
    }
}

/// Canonical CBOR decoder that rejects non-canonical input.
#[derive(Debug)]
pub struct Decoder<'a> {
    input: &'a [u8],
    pos: usize,
}

impl<'a> Decoder<'a> {
    /// Create a decoder over `input`.
    #[must_use]
    pub fn new(input: &'a [u8]) -> Self {
        Self { input, pos: 0 }
    }

    /// Whether all input has been consumed.
    #[must_use]
    pub fn is_finished(&self) -> bool {
        self.pos == self.input.len()
    }

    /// Assert that the whole input was consumed.
    ///
    /// # Errors
    /// Returns [`CoreError::Cbor`] on trailing bytes.
    pub fn finish(self) -> Result<(), CoreError> {
        if self.is_finished() {
            Ok(())
        } else {
            Err(CoreError::Cbor("trailing bytes"))
        }
    }

    fn read_u8(&mut self) -> Result<u8, CoreError> {
        let byte = *self
            .input
            .get(self.pos)
            .ok_or(CoreError::Cbor("unexpected end"))?;
        self.pos += 1;
        Ok(byte)
    }

    fn read_exact(&mut self, len: usize) -> Result<&'a [u8], CoreError> {
        let end = self
            .pos
            .checked_add(len)
            .ok_or(CoreError::Cbor("length overflow"))?;
        let slice = self
            .input
            .get(self.pos..end)
            .ok_or(CoreError::Cbor("unexpected end"))?;
        self.pos = end;
        Ok(slice)
    }

    fn read_head(&mut self) -> Result<(u8, u64), CoreError> {
        let initial = self.read_u8()?;
        let major = initial >> 5;
        let additional = initial & 0x1F;
        let value = match additional {
            0..=23 => u64::from(additional),
            24 => {
                let v = u64::from(self.read_u8()?);
                if v < 24 {
                    return Err(CoreError::Cbor("non-canonical integer"));
                }
                v
            }
            25 => {
                let bytes = self.read_exact(2)?;
                let mut arr = [0u8; 2];
                arr.copy_from_slice(bytes);
                let v = u64::from(u16::from_be_bytes(arr));
                if v <= u64::from(u8::MAX) {
                    return Err(CoreError::Cbor("non-canonical integer"));
                }
                v
            }
            26 => {
                let bytes = self.read_exact(4)?;
                let mut arr = [0u8; 4];
                arr.copy_from_slice(bytes);
                let v = u64::from(u32::from_be_bytes(arr));
                if v <= u64::from(u16::MAX) {
                    return Err(CoreError::Cbor("non-canonical integer"));
                }
                v
            }
            27 => {
                let bytes = self.read_exact(8)?;
                let mut arr = [0u8; 8];
                arr.copy_from_slice(bytes);
                let v = u64::from_be_bytes(arr);
                if v <= u64::from(u32::MAX) {
                    return Err(CoreError::Cbor("non-canonical integer"));
                }
                v
            }
            _ => return Err(CoreError::Cbor("indefinite or reserved length")),
        };
        Ok((major, value))
    }

    fn expect(&mut self, major: u8) -> Result<u64, CoreError> {
        let (found, value) = self.read_head()?;
        if found != major {
            return Err(CoreError::Cbor("unexpected major type"));
        }
        Ok(value)
    }

    /// Decode an unsigned integer.
    ///
    /// # Errors
    /// Returns [`CoreError::Cbor`] on malformed input.
    pub fn uint(&mut self) -> Result<u64, CoreError> {
        self.expect(MAJOR_UINT)
    }

    /// Decode a byte string.
    ///
    /// # Errors
    /// Returns [`CoreError::Cbor`] on malformed input.
    pub fn bytes(&mut self) -> Result<&'a [u8], CoreError> {
        let len = self.expect(MAJOR_BYTES)?;
        let len = usize::try_from(len).map_err(|_| CoreError::Cbor("length overflow"))?;
        self.read_exact(len)
    }

    /// Decode a fixed-size byte string.
    ///
    /// # Errors
    /// Returns [`CoreError::Cbor`] on malformed input or length mismatch.
    pub fn bytes_fixed<const N: usize>(&mut self) -> Result<[u8; N], CoreError> {
        let slice = self.bytes()?;
        let mut out = [0u8; N];
        if slice.len() != N {
            return Err(CoreError::Cbor("fixed length mismatch"));
        }
        out.copy_from_slice(slice);
        Ok(out)
    }

    /// Decode a UTF-8 text string.
    ///
    /// # Errors
    /// Returns [`CoreError::Cbor`] on malformed input.
    pub fn text(&mut self) -> Result<&'a str, CoreError> {
        let len = self.expect(MAJOR_TEXT)?;
        let len = usize::try_from(len).map_err(|_| CoreError::Cbor("length overflow"))?;
        let slice = self.read_exact(len)?;
        core::str::from_utf8(slice).map_err(|_| CoreError::Cbor("invalid utf-8"))
    }

    /// Decode an array header, returning its length.
    ///
    /// # Errors
    /// Returns [`CoreError::Cbor`] on malformed input.
    pub fn array(&mut self) -> Result<usize, CoreError> {
        let len = self.expect(MAJOR_ARRAY)?;
        usize::try_from(len).map_err(|_| CoreError::Cbor("length overflow"))
    }

    /// Decode a map header, returning its entry count.
    ///
    /// # Errors
    /// Returns [`CoreError::Cbor`] on malformed input.
    pub fn map(&mut self) -> Result<usize, CoreError> {
        let len = self.expect(MAJOR_MAP)?;
        usize::try_from(len).map_err(|_| CoreError::Cbor("length overflow"))
    }

    /// Decode a boolean.
    ///
    /// # Errors
    /// Returns [`CoreError::Cbor`] on malformed input.
    pub fn bool(&mut self) -> Result<bool, CoreError> {
        let byte = self.read_u8()?;
        match byte {
            0xF4 => Ok(false),
            0xF5 => Ok(true),
            _ => Err(CoreError::Cbor("expected boolean")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn enc(f: impl FnOnce(&mut Encoder)) -> Vec<u8> {
        let mut e = Encoder::new();
        f(&mut e);
        e.into_bytes()
    }

    #[test]
    fn integers_use_shortest_form() {
        assert_eq!(enc(|e| e.uint(0)), vec![0x00]);
        assert_eq!(enc(|e| e.uint(23)), vec![0x17]);
        assert_eq!(enc(|e| e.uint(24)), vec![0x18, 0x18]);
        assert_eq!(enc(|e| e.uint(255)), vec![0x18, 0xFF]);
        assert_eq!(enc(|e| e.uint(256)), vec![0x19, 0x01, 0x00]);
        assert_eq!(enc(|e| e.uint(65535)), vec![0x19, 0xFF, 0xFF]);
        assert_eq!(enc(|e| e.uint(65536)), vec![0x1A, 0x00, 0x01, 0x00, 0x00]);
    }

    #[test]
    fn round_trips_strings() {
        let bytes = enc(|e| {
            e.array(2);
            e.text("hi");
            e.bytes(&[1, 2, 3]);
        });
        assert_eq!(bytes, vec![0x82, 0x62, b'h', b'i', 0x43, 1, 2, 3]);

        let mut d = Decoder::new(&bytes);
        assert_eq!(d.array().unwrap(), 2);
        assert_eq!(d.text().unwrap(), "hi");
        assert_eq!(d.bytes().unwrap(), &[1, 2, 3]);
        d.finish().unwrap();
    }

    #[test]
    fn rejects_non_canonical_integer() {
        // 0 encoded as 0x18 0x00 is valid CBOR but not canonical.
        let mut d = Decoder::new(&[0x18, 0x00]);
        assert!(d.uint().is_err());
    }

    #[test]
    fn rejects_indefinite_length() {
        let mut d = Decoder::new(&[0x5F]);
        assert!(d.bytes().is_err());
    }

    #[test]
    fn rejects_trailing_bytes() {
        let d = Decoder::new(&[0x00, 0x00]);
        assert!(d.finish().is_err());
    }
}
