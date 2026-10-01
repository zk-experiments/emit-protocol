//! The escrow events as the pool emits them (`Escrowed`, `EscrowClosed`).
//!
//! `seq` is one counter shared by both events, starting at 1 — the pool's `escrowEventSeq()` — so
//! a reader can prove it saw every event of a block range.

use crate::{ChainCommitment, EnvCommit, NoteCommitment};

/// One escrow event: its sequence number and what it says.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EscrowLog {
    pub seq: u64,
    pub kind: EscrowEventKind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EscrowEventKind {
    /// `Escrowed`: a transfer's recipient note went into escrow.
    Opened {
        note_commitment: NoteCommitment,
        chain_commitment: ChainCommitment,
        env_commit: EnvCommit,
        /// The last second the owner may accept it (unix seconds).
        deadline: u64,
    },
    /// `EscrowClosed`: resolved (accept or reject) or refunded — one event for all three, so the
    /// outcome stays hidden.
    Closed { note_commitment: NoteCommitment },
}
