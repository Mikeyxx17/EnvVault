use sha2::{Digest as _, Sha256};
use subtle::ConstantTimeEq as _;
use zeroize::Zeroizing;

/// Computes the fixed SHA-256 digest used by public integrity records.
pub(crate) fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

/// Compares two sensitive byte strings through fixed-length digests.
///
/// No reusable verifier is persisted; both digests exist only for this call.
pub(crate) fn sensitive_values_equal(left: &[u8], right: &[u8]) -> bool {
    let left_digest = Zeroizing::new(sha256(left));
    let right_digest = Zeroizing::new(sha256(right));
    bool::from(left_digest.as_slice().ct_eq(right_digest.as_slice()))
}

#[cfg(test)]
mod tests {
    use super::{sensitive_values_equal, sha256};

    #[test]
    fn matches_the_sha256_abc_vector() {
        assert_eq!(
            sha256(b"abc"),
            [
                0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae,
                0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61,
                0xf2, 0x00, 0x15, 0xad,
            ]
        );
    }

    #[test]
    fn compares_sensitive_values_without_length_dependent_equality() {
        assert!(sensitive_values_equal(b"same", b"same"));
        assert!(!sensitive_values_equal(b"same", b"different-length"));
    }
}
