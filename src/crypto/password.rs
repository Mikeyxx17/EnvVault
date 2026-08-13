use zeroize::Zeroizing;

/// Master password bytes with zeroization on drop.
///
/// The password does not implement `Clone`, `Debug`, `Display`, or
/// serialization. Production callers must obtain it from a protected input
/// channel rather than command-line arguments or environment variables.
pub struct MasterPassword(Zeroizing<Vec<u8>>);

impl MasterPassword {
    /// Creates a protected master password from owned bytes.
    #[must_use]
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(Zeroizing::new(bytes))
    }

    /// Exposes password bytes only to the key-derivation boundary.
    pub(crate) fn expose_secret(&self) -> &[u8] {
        self.0.as_slice()
    }

    /// Returns whether the password has zero bytes.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl From<Vec<u8>> for MasterPassword {
    fn from(value: Vec<u8>) -> Self {
        Self::new(value)
    }
}
