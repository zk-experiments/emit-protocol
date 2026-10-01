//! The protocol's 32-byte values, one newtype each so a note commitment can never be passed where a
//! chain commitment is expected. As text they are `0x`-hex; as bytes, exactly 32 — both entry
//! points check the length, nothing is padded or truncated.
//!
//! [`bytes32!`](crate::bytes32) is exported so a consumer defines its own 32-byte values (a block
//! hash, a capability token) the same way.

use ark_ff::PrimeField;
use zk_encryption::Fr;
use zk_encryption::poseidon::FieldHex;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ParseError {
    #[error("expected 32 bytes, got {0}")]
    Length(usize),
    #[error("not 0x-prefixed hex")]
    Hex,
}

/// Defines a 32-byte newtype with `from_slice`, `parse_hex`, `to_hex` and `as_bytes`.
#[macro_export]
macro_rules! bytes32 {
    ($(#[$doc:meta])* $name:ident) => {
        $(#[$doc])*
        #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub struct $name(pub [u8; 32]);

        impl $name {
            /// Exactly 32 bytes, or an error — never padded or truncated.
            pub fn from_slice(bytes: &[u8]) -> Result<Self, $crate::ParseError> {
                <[u8; 32]>::try_from(bytes)
                    .map(Self)
                    .map_err(|_| $crate::ParseError::Length(bytes.len()))
            }

            /// `0x`-prefixed hex of exactly 32 bytes.
            pub fn parse_hex(value: &str) -> Result<Self, $crate::ParseError> {
                let digits = value
                    .trim()
                    .strip_prefix("0x")
                    .ok_or($crate::ParseError::Hex)?;
                let bytes = $crate::__hex::decode(digits).map_err(|_| $crate::ParseError::Hex)?;
                Self::from_slice(&bytes)
            }

            pub fn to_hex(&self) -> String {
                format!("0x{}", $crate::__hex::encode(self.0))
            }

            pub fn as_bytes(&self) -> &[u8; 32] {
                &self.0
            }
        }
    };
}

bytes32!(
    /// `C_t`: a transfer's chain commitment `H(COMMIT, S_t)`, a public output of its proof and the
    /// key its off-chain envelope travels under.
    ChainCommitment
);
bytes32!(
    /// `C₀`: the escrowed recipient note. The pool keys escrows by it.
    NoteCommitment
);
bytes32!(
    /// `H("emit-v2/envelope", ct_commitment, cid_commit)`: what the off-chain envelope must hash to
    /// ([`crate::Envelope::commit`]); the pool emits it in `Escrowed`.
    EnvCommit
);

macro_rules! field_valued {
    ($($name:ident),*) => {$(
        impl From<Fr> for $name {
            /// The field element's 32 big-endian bytes.
            fn from(f: Fr) -> Self {
                Self(f.to_be32())
            }
        }

        impl $name {
            /// The field element these bytes encode (reduced mod p: the pool and the circuits only
            /// ever produce canonical encodings).
            pub fn to_fr(&self) -> Fr {
                Fr::from_be_bytes_mod_order(&self.0)
            }
        }
    )*};
}

field_valued!(ChainCommitment, NoteCommitment, EnvCommit);

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn hex_round_trips_and_lengths_are_exact() {
        let value = ChainCommitment([0xab; 32]);
        assert_eq!(ChainCommitment::parse_hex(&value.to_hex()).unwrap(), value);
        assert_eq!(
            ChainCommitment::parse_hex("0x00"),
            Err(ParseError::Length(1))
        );
        assert_eq!(
            ChainCommitment::parse_hex(&"ab".repeat(32)),
            Err(ParseError::Hex),
            "unprefixed hex is refused"
        );
        assert_eq!(
            NoteCommitment::from_slice(&[0; 33]),
            Err(ParseError::Length(33))
        );
    }

    #[test]
    fn field_elements_round_trip() {
        let f = Fr::from(123_456_789u64);
        assert_eq!(NoteCommitment::from(f).to_fr(), f);
        assert_eq!(NoteCommitment::from(f).0[31], 0x15);
    }
}
