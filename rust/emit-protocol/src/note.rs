//! The note math the circuits constrain, beyond zk-encryption's [`Emit`] (commitments,
//! nullifiers, the transfer's rhos and ctx): the refund note of an escrowed output, and the
//! resolve of an escrowed note by its owner (`emit::resolve` in `noir/lib/emit`).

use ark_ff::Zero;
use zk_encryption::Fr;
use zk_encryption::emit::{Emit, NoteOpening};
use zk_encryption::poseidon::Poseidon;

/// The smallest note a transfer or a resolve may create: 1/3 of the native coin in wei, rounded
/// down (`emit::MIN_NOTE_VALUE`). A note is this much or more, or 0.
pub const MIN_NOTE_VALUE: u128 = 333_333_333_333_333_333;

/// The refund note of an escrowed output 0: its `value` back to the sender's key `pk`, with
/// `rho = H(RHO, N0, 2)` (outputs 0 and 1 take j = 0 and 1, so the three never share a nullifier).
pub fn refund(cid: Fr, pk: Fr, value: u128, n0: Fr, r: Fr) -> Fr {
    Emit::commitment(cid, pk, value, Emit::rho(n0, 2), r)
}

/// The refund note's opening, for its sender to spend it.
pub fn refund_opening(value: u128, n0: Fr, r: Fr) -> NoteOpening {
    NoteOpening {
        value,
        rho: Emit::rho(n0, 2),
        r,
    }
}

/// A resolve's action (`emit::ACCEPT`, `emit::REJECT`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action {
    Accept,
    Reject,
}

impl Action {
    pub fn field(self) -> Fr {
        Fr::from(match self {
            Action::Accept => 0u64,
            Action::Reject => 1,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ResolveError {
    #[error("the fee exceeds the note")]
    FeeExceedsNote,
    #[error("the note less the fee is below the minimum of 1/3 of the native coin")]
    BelowMinimum,
}

/// The resolve of an escrowed note C0 by its owner, as `emit::resolve` constrains it.
#[derive(Clone, Debug)]
pub struct Resolve {
    pub cid: Fr,
    pub sk: Fr,
    pub note: NoteOpening,
    pub c0: Fr,
    pub action: Action,
    pub fee: u128,
    pub r_out: Fr,
    /// Accept: the note less the fee, for the same key (0 on a reject).
    pub c_out: Fr,
    /// `H(RESOLVE, cid, C0, action, c_out, fee)`: the context of the holder tag.
    pub ctx: Fr,
}

impl Resolve {
    /// A reject pays no fee: `fee` is ignored for it. `r_out` is the accepted note's blinding,
    /// fresh randomness the caller draws (this crate draws none: everything here is deterministic).
    pub fn build(
        cid: Fr,
        sk: Fr,
        note: NoteOpening,
        action: Action,
        fee: u128,
        r_out: Fr,
    ) -> Result<Self, ResolveError> {
        let pk = Emit::pk(sk);
        let c0 = note.commitment(cid, pk);
        let (fee, c_out) = match action {
            Action::Accept => {
                let kept = note
                    .value
                    .checked_sub(fee)
                    .ok_or(ResolveError::FeeExceedsNote)?;
                if kept != 0 && kept < MIN_NOTE_VALUE {
                    return Err(ResolveError::BelowMinimum);
                }
                (fee, Emit::commitment(cid, pk, kept, Self::rho(c0), r_out))
            }
            Action::Reject => (0, Fr::zero()),
        };
        let ctx = Poseidon::hash(&[
            Poseidon::domain("emit-v2/resolve"),
            cid,
            c0,
            action.field(),
            c_out,
            Fr::from(fee),
        ]);
        Ok(Self {
            cid,
            sk,
            note,
            c0,
            action,
            fee,
            r_out,
            c_out,
            ctx,
        })
    }

    /// The accepted note's rho: `H(RHO_RESOLVE, C0)` (C0 is unique, so its nullifier is too).
    pub fn rho(c0: Fr) -> Fr {
        Poseidon::hash(&[Poseidon::domain("emit-v2/rho-resolve"), c0])
    }

    /// The accepted note's opening.
    pub fn kept(&self) -> NoteOpening {
        NoteOpening {
            value: self.note.value - self.fee,
            rho: Self::rho(self.c0),
            r: self.r_out,
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use zk_encryption::poseidon::FieldHex;

    /// The domains are the circuit's (`emit::RESOLVE`, `emit::RHO_RESOLVE`), and a reject pays no
    /// fee.
    #[test]
    fn resolve_matches_the_circuit_rules() {
        assert_eq!(
            Poseidon::domain("emit-v2/resolve").hex(),
            "0x0000000000000000000000000000000000656d69742d76322f7265736f6c7665"
        );
        let note = NoteOpening {
            value: MIN_NOTE_VALUE + 10,
            rho: Fr::from(3u64),
            r: Fr::from(4u64),
        };
        let sk = Fr::from(7u64);
        let cid = Fr::from(1u64);
        let a = Resolve::build(cid, sk, note.clone(), Action::Accept, 10, Fr::from(5u64)).unwrap();
        assert_eq!(a.c0, note.commitment(cid, Emit::pk(sk)));
        assert_eq!(a.kept().commitment(cid, Emit::pk(sk)), a.c_out);
        assert_eq!(
            Resolve::build(cid, sk, note.clone(), Action::Accept, 11, Fr::from(5u64)).unwrap_err(),
            ResolveError::BelowMinimum
        );
        let r = Resolve::build(cid, sk, note, Action::Reject, 10, Fr::from(5u64)).unwrap();
        assert_eq!((r.fee, r.c_out), (0, Fr::zero()));
    }

    #[test]
    fn the_refund_is_output_0_for_the_sender() {
        let (cid, pk, n0, r) = (
            Fr::from(1u64),
            Fr::from(2u64),
            Fr::from(3u64),
            Fr::from(4u64),
        );
        assert_eq!(
            refund(cid, pk, 50, n0, r),
            refund_opening(50, n0, r).commitment(cid, pk)
        );
        assert_ne!(Emit::rho(n0, 2), Emit::rho(n0, 0));
    }
}
