//! Secret byte buffers that zeroize on drop and never print their contents.

use core::fmt;

use zeroize::{Zeroize, ZeroizeOnDrop};

/// An owned byte buffer holding secret material.
///
/// - Zeroizes its contents on drop.
/// - Implements [`fmt::Debug`] with a redacted representation.
/// - Deliberately does **not** implement `Clone` (avoid uncontrolled copies).
pub struct SecretBytes(Vec<u8>);

impl SecretBytes {
    /// Wrap a vector of secret bytes.
    #[must_use]
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// View the secret bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Mutably view the secret bytes.
    pub fn as_mut_bytes(&mut self) -> &mut [u8] {
        &mut self.0
    }

    /// Number of bytes held.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether the buffer is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl ZeroizeOnDrop for SecretBytes {}

impl fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecretBytes([REDACTED; {} bytes])", self.0.len())
    }
}

// Ensure the buffer is actually zeroized on drop.
impl Drop for SecretBytes {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_is_redacted() {
        let secret = SecretBytes::new(vec![0xAB; 42]);
        let rendered = format!("{secret:?}");
        assert!(rendered.contains("REDACTED"));
        assert!(!rendered.contains("AB"));
        assert!(!rendered.contains("171"));
    }

    #[test]
    fn exposes_bytes_to_callers() {
        let mut secret = SecretBytes::new(vec![1, 2, 3]);
        assert_eq!(secret.as_bytes(), &[1, 2, 3]);
        secret.as_mut_bytes()[0] = 9;
        assert_eq!(secret.as_bytes()[0], 9);
        assert_eq!(secret.len(), 3);
    }
}
