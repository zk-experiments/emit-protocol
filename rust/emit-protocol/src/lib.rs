//! The Emit V2 protocol's values: **what** a transfer carries between its sender and its receiver,
//! and the commitments that bind it — shared by everything that speaks the protocol (a wallet, a
//! node, a delivery service).
//!
//! Pure by construction: no I/O, no async, no network or filesystem, no randomness drawn (callers
//! pass blindings in) — only types, their byte encodings, commitments and the note math, all
//! deterministic and covered by plain unit tests. CI fails if a transport crate (tokio, alloy,
//! reqwest, hyper, volo, tokio-postgres) enters its dependency tree.
//!
//! The layers around it:
//! * **what** is carried: this crate — the commitments, the note math the circuits constrain, the
//!   off-chain envelope and its `env_commit`, the escrow events. No delivery mechanism here: no
//!   mailbox, no inbox client, no tokens, no admission rules.
//! * **delivery** of the envelope from sender to receiver: a service such as envelope-inbox (or,
//!   on emit-devnet, a shared directory), built on these types.
//! * **enforcement**: the chain. The pool contract (`contracts/`, bound for alloy by
//!   `emit-protocol-abi`) verifies each transfer's proof against the protocol's rules and that
//!   delivery happened: the escrow lets only the note's owner, who opened it, resolve it, and
//!   refunds it otherwise. `emit-circuits` is the prover side of those rules.
//!
//! * [`bytes`]: the 32-byte values the protocol names (note and chain commitments, `env_commit`),
//!   parsed and length-checked at the edge, with their field-element conversions.
//! * [`note`]: the note math the circuits constrain: commitments and nullifiers (zk-encryption's
//!   [`Emit`]), the refund note of an escrowed output, and the resolve.
//! * [`envelope`]: the off-chain envelope `(u ‖ v, c_id)` and its `env_commit`, the commitment the
//!   pool emits in `Escrowed`.
//! * [`escrow`]: the escrow events as the pool emits them.

pub mod bytes;
pub mod envelope;
pub mod escrow;
pub mod note;

pub use bytes::{ChainCommitment, EnvCommit, NoteCommitment, ParseError};
pub use envelope::{Envelope, EnvelopeError};
pub use escrow::{EscrowEventKind, EscrowLog};
pub use note::{Action, MIN_NOTE_VALUE, Resolve, ResolveError};
/// The channel and wallet library this protocol is built on, re-exported so consumers use the
/// exact version the protocol's types come from.
pub use zk_encryption;
pub use zk_encryption::Fr;
pub use zk_encryption::emit::{Emit, NoteOpening};

#[doc(hidden)]
pub use hex as __hex;
