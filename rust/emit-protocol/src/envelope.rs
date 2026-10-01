//! The off-chain envelope of a transfer and its commitment.
//!
//! Layout, 1,728 bytes: the lattice ciphertext `u ‖ v` (ByteEncode₁₂, 1,536 bytes), then the DG1
//! envelope's six ciphertext fields `c_id0..c_id5`, each a 32-byte big-endian field element. The
//! chain never carries them: the transfer proof publishes the session's `ct_commitment` and the
//! DG1 envelope's `cid_commit`, and the pool emits
//!
//! ```text
//! env_commit = Poseidon2(D_ENV, ct_commitment, cid_commit)
//! cid_commit = Poseidon2(D_DG1, c_id0, …, c_id5)
//! ```
//!
//! with the domains ASCII strings read as big-endian integers. [`Envelope::commit`] recomputes it
//! from the bytes with the same Poseidon2 the circuits use, so whoever holds an envelope (the
//! receiver, an inbox) can check it is byte for byte the one the proof committed to.

use ark_ff::PrimeField;
use zk_encryption::Fr;
use zk_encryption::lattice::Ciphertext;
use zk_encryption::poseidon::{FieldHex, Poseidon};

use crate::EnvCommit;

/// Bytes of the lattice ciphertext `u ‖ v`.
pub const CIPHERTEXT_BYTES: usize = 1536;
/// Field elements of the DG1 envelope's ciphertext.
pub const CID_FIELDS: usize = 6;
/// Whole envelope: ciphertext, then `c_id` as 32-byte big-endian fields.
pub const ENVELOPE_BYTES: usize = CIPHERTEXT_BYTES + CID_FIELDS * 32;

const ENV_DOMAIN: &str = "emit-v2/envelope";
const DG1_DOMAIN: &str = "emit-v2/dg1-envelope";

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum EnvelopeError {
    #[error("envelope must be exactly {ENVELOPE_BYTES} bytes, got {0}")]
    Length(usize),
    #[error("lattice ciphertext has a coefficient ≥ q")]
    Ciphertext,
    #[error("c_id{0} is not a canonical field element")]
    Field(usize),
}

/// An envelope: exactly [`ENVELOPE_BYTES`] bytes, parsed into its parts only on demand.
#[derive(Clone, PartialEq, Eq)]
pub struct Envelope(Box<[u8; ENVELOPE_BYTES]>);

impl std::fmt::Debug for Envelope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never the bytes: an envelope is personal data, even sealed.
        write!(f, "Envelope({ENVELOPE_BYTES} bytes)")
    }
}

impl Envelope {
    /// The envelope of a lattice ciphertext and a sealed DG1, as a sender writes it.
    pub fn from_parts(ct: &Ciphertext, c_id: &[Fr; CID_FIELDS]) -> Self {
        let mut bytes = [0u8; ENVELOPE_BYTES];
        bytes[..CIPHERTEXT_BYTES].copy_from_slice(&ct.to_bytes());
        for (i, f) in c_id.iter().enumerate() {
            let at = CIPHERTEXT_BYTES + 32 * i;
            bytes[at..at + 32].copy_from_slice(&f.to_be32());
        }
        Self(Box::new(bytes))
    }

    pub fn from_slice(bytes: &[u8]) -> Result<Self, EnvelopeError> {
        let array: [u8; ENVELOPE_BYTES] = bytes
            .try_into()
            .map_err(|_| EnvelopeError::Length(bytes.len()))?;
        Ok(Self(Box::new(array)))
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_slice()
    }

    /// The lattice ciphertext `(u, v)`, refusing a coefficient ≥ q.
    pub fn ciphertext(&self) -> Result<Ciphertext, EnvelopeError> {
        Ciphertext::from_bytes(&self.0[..CIPHERTEXT_BYTES]).map_err(|_| EnvelopeError::Ciphertext)
    }

    /// The sealed DG1 `c_id`, refusing a non-canonical field element (reduction would let two
    /// byte strings share a commitment).
    pub fn c_id(&self) -> Result<[Fr; CID_FIELDS], EnvelopeError> {
        let mut out = [Fr::from(0u64); CID_FIELDS];
        for (i, chunk) in self.0[CIPHERTEXT_BYTES..]
            .as_chunks::<32>()
            .0
            .iter()
            .enumerate()
        {
            let field = Fr::from_be_bytes_mod_order(chunk);
            if field.to_be32() != *chunk {
                return Err(EnvelopeError::Field(i));
            }
            out[i] = field;
        }
        Ok(out)
    }

    /// `cid_commit = H(D_DG1, c_id)`, as the DG1 envelope app publishes it.
    pub fn cid_commit(c_id: &[Fr; CID_FIELDS]) -> Fr {
        let mut inputs = vec![Poseidon::domain(DG1_DOMAIN)];
        inputs.extend(c_id);
        Poseidon::hash(&inputs)
    }

    /// `env_commit` of these bytes — see the module docs. Fails on bytes no honest sender can
    /// produce (a non-canonical coefficient or field).
    pub fn commit(&self) -> Result<EnvCommit, EnvelopeError> {
        let ct_commitment = self.ciphertext()?.commitment();
        let cid_commit = Self::cid_commit(&self.c_id()?);
        let env = Poseidon::hash(&[Poseidon::domain(ENV_DOMAIN), ct_commitment, cid_commit]);
        Ok(EnvCommit(env.to_be32()))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn zeros() -> Envelope {
        Envelope::from_slice(&[0u8; ENVELOPE_BYTES]).unwrap()
    }

    #[test]
    fn length_is_exact() {
        assert_eq!(
            Envelope::from_slice(&[0u8; ENVELOPE_BYTES - 1]),
            Err(EnvelopeError::Length(ENVELOPE_BYTES - 1))
        );
        assert_eq!(
            Envelope::from_slice(&[0u8; ENVELOPE_BYTES + 1]),
            Err(EnvelopeError::Length(ENVELOPE_BYTES + 1))
        );
        assert_eq!(ENVELOPE_BYTES, 1728);
    }

    #[test]
    fn parts_round_trip() {
        let mut u = [[0u16; 256]; 3];
        u[1][7] = 3328;
        let ct = Ciphertext { u, v: [17u16; 256] };
        let c_id = [1u64, 2, 3, 4, 5, 6].map(Fr::from);
        let e = Envelope::from_parts(&ct, &c_id);
        assert_eq!(e.ciphertext().unwrap(), ct);
        assert_eq!(e.c_id().unwrap(), c_id);
        assert_eq!(Envelope::from_slice(e.as_bytes()).unwrap(), e);
    }

    #[test]
    fn commitment_is_deterministic_and_binds_every_part() {
        let base = zeros().commit().unwrap();
        assert_eq!(zeros().commit().unwrap(), base);

        // A change in the lattice ciphertext moves it.
        let mut bytes = [0u8; ENVELOPE_BYTES];
        bytes[0] = 1;
        assert_ne!(
            Envelope::from_slice(&bytes).unwrap().commit().unwrap(),
            base
        );

        // So does a change in any c_id field.
        let mut bytes = [0u8; ENVELOPE_BYTES];
        bytes[ENVELOPE_BYTES - 1] = 1;
        assert_ne!(
            Envelope::from_slice(&bytes).unwrap().commit().unwrap(),
            base
        );
    }

    #[test]
    fn non_canonical_parts_are_malformed() {
        // A 12-bit coefficient of 0xfff ≥ q = 3329.
        let mut bytes = [0u8; ENVELOPE_BYTES];
        bytes[0] = 0xff;
        bytes[1] = 0x0f;
        assert_eq!(
            Envelope::from_slice(&bytes).unwrap().commit(),
            Err(EnvelopeError::Ciphertext)
        );

        // c_id2 = 2^256 − 1, far above the BN254 modulus.
        let mut bytes = [0u8; ENVELOPE_BYTES];
        let start = CIPHERTEXT_BYTES + 2 * 32;
        bytes[start..start + 32].fill(0xff);
        assert_eq!(
            Envelope::from_slice(&bytes).unwrap().commit(),
            Err(EnvelopeError::Field(2))
        );
    }

    /// The golden vector: emit-devnet's end-to-end test checks this formula against the pool's
    /// `Escrowed.envCommit`, which the contract computes from the circuits' outputs.
    #[test]
    fn env_commit_golden_vector() {
        let mut coeffs = Vec::with_capacity(1024);
        coeffs.extend((0..256u32).map(|i| i * 13 % 3329));
        coeffs.extend((0..256u32).map(|i| i * 7 % 3329));
        coeffs.extend((0..256u32).map(|i| 3328 - i));
        coeffs.extend((0..256u32).map(|i| i * i % 3329));
        let mut bytes = Vec::with_capacity(ENVELOPE_BYTES);
        for pair in coeffs.chunks(2) {
            let (a, c) = (pair[0], pair[1]);
            bytes.extend([a as u8, ((a >> 8) | (c << 4)) as u8, (c >> 4) as u8]);
        }
        for x in [11u8, 22, 33, 44, 55, 66] {
            let mut field = [0u8; 32];
            field[31] = x;
            bytes.extend(field);
        }
        let commit = Envelope::from_slice(&bytes).unwrap().commit().unwrap();
        assert_eq!(
            hex::encode(commit.0),
            "009da8b357bab4e5c7438ed751880232ee84dbc18c4447ec5f4d9a29372d32e1"
        );
    }
}
