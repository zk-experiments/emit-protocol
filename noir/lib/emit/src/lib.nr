//! Emit V2 private transfer (2-in / 2-out JoinSplit, shielded keys), with
//! the note opening for the recipient committed to as a channel payload for
//! the note envelope app to seal. The channel itself (the KEM, C_t) is the
//! session app's (channel::session). Reference: reference/src/emit.rs.
//! Specification: README.md.
//!
//! Output 0 (the recipient's note) is escrowed by the pool: it enters the note tree only when its
//! owner resolves it (`resolve`), and otherwise the refund note C_r, the same value for the
//! sender's key, does. DG1 is sealed by `dg1_envelope`, which keeps its ciphertext private and
//! publishes only a commitment to it: the ciphertext travels off-chain.

mod tests;
mod vectors;

use channel::payload::commit;
use channel::ratchet::{KEY_PAYLOAD_DOMAIN, seal_keyed};
use poseidon::poseidon2::Poseidon2;

/// Domain tags ("emit-v2/<label>") as big-endian integers.
pub global NK: Field = 0x656d69742d76322f6e6b;
pub global PK: Field = 0x656d69742d76322f706b;
pub global NULLIFIER: Field = 0x656d69742d76322f6e756c6c6966696572;
pub global COMMITMENT: Field = 0x656d69742d76322f636f6d6d69746d656e74;
pub global RHO: Field = 0x656d69742d76322f72686f;
pub global CTX: Field = 0x656d69742d76322f637478;
pub global HOLDER: Field = 0x656d69742d76322f686f6c646572;
pub global DG1_ENVELOPE: Field = 0x656d69742d76322f6467312d656e76656c6f7065;
pub global RESOLVE: Field = 0x656d69742d76322f7265736f6c7665;
pub global RHO_RESOLVE: Field = 0x656d69742d76322f72686f2d7265736f6c7665;

pub global TREE_DEPTH: u32 = 32;
/// Values are single fields range-checked to 128 bits.
pub global VALUE_BITS: u32 = 128;

/// Transfer's databus output (`Transfer::flatten`): 12 public fields, then
/// the note payload's commitment (the link to the note envelope app).
pub global TRANSFER_FIELDS: u32 = 13;
/// The smallest note a transfer may create: 1/3 of the native coin (wei, rounded down). An output is
/// either this much or more, or 0 (a dummy).
pub global MIN_NOTE_VALUE: u128 = 333333333333333333;
/// `transfer_holder`'s databus output: ctx, the holder tag, then as `Transfer::flatten` from cid.
pub global TRANSFER_HOLDER_FIELDS: u32 = 14;
/// `dg1_envelope`'s databus output: `[payload_commitment, ctx, C_t, cid_commit]`.
pub global DG1_ENVELOPE_FIELDS: u32 = 4;
/// `escrow_resolve`'s databus output: `[holder_tag, cid, C0, action, c_out, fee]`.
pub global RESOLVE_FIELDS: u32 = 6;
/// A resolve's action: the owner takes the note, or hands it back to the sender.
pub global ACCEPT: Field = 0;
pub global REJECT: Field = 1;

pub fn h<let N: u32>(x: [Field; N]) -> Field {
    Poseidon2::hash(x, N)
}

pub fn commitment(cid: Field, pk: Field, value: Field, rho: Field, r: Field) -> Field {
    h([COMMITMENT, cid, pk, value, rho, r])
}

/// Depth-32 Poseidon2 Merkle root: node = H(left, right).
pub fn merkle_root(leaf: Field, index: Field, path: [Field; TREE_DEPTH]) -> Field {
    let bits: [bool; TREE_DEPTH] = index.to_le_bits();
    let mut node = leaf;
    for l in 0..TREE_DEPTH {
        node = if bits[l] {
            h([path[l], node])
        } else {
            h([node, path[l]])
        };
    }
    node
}

/// A note being spent. `value = 0` marks a dummy input (deposits), which
/// skips the membership check but still needs a unique nullifier.
pub struct InNote {
    pub sk: Field,
    pub value: Field,
    pub rho: Field,
    pub r: Field,
    pub index: Field,
    pub path: [Field; TREE_DEPTH],
}

/// A note being created for `pk`; its rho is derived from the first nullifier.
pub struct OutNote {
    pub pk: Field,
    pub value: Field,
    pub r: Field,
}

pub struct Transfer {
    pub ctx: Field,
    pub cid: Field,
    pub root: Field,
    pub nullifiers: [Field; 2],
    pub commitments: [Field; 2],
    /// The refund note C_r: output 0's value for the sender's key.
    pub refund: Field,
    pub v_in: Field,
    pub v_out: Field,
    pub fee: Field,
    pub payout_recipient: Field,
    pub note_commitment: Field,
}

impl Transfer {
    /// `[ctx, cid, root, N0, N1, C0, C1, C_r, v_in, v_out, fee, payout_recipient, note_commitment]`.
    pub fn flatten(self) -> [Field; TRANSFER_FIELDS] {
        [
            self.ctx,
            self.cid,
            self.root,
            self.nullifiers[0],
            self.nullifiers[1],
            self.commitments[0],
            self.commitments[1],
            self.refund,
            self.v_in,
            self.v_out,
            self.fee,
            self.payout_recipient,
            self.note_commitment,
        ]
    }
}

/// The JoinSplit: returns (nullifiers, commitments, output rhos, ctx).
/// - inputs: C = H(COMMITMENT, cid, H(PK, sk), value, rho, r) is in the tree
///   under `root` unless value = 0; N = H(NULLIFIER, H(NK, sk), rho); N0 ≠ N1;
/// - outputs: rho'_j = H(RHO, N0, j), C'_j = H(COMMITMENT, cid, pk_j, v'_j, rho'_j, r'_j);
/// - v0 + v1 + v_in = v'0 + v'1 + v_out + fee, every value < 2^128;
/// - ctx = H(CTX, cid, N0, N1, C'0, C'1).
pub fn joinsplit(
    cid: Field,
    root: Field,
    v_in: Field,
    v_out: Field,
    fee: Field,
    ins: [InNote; 2],
    outs: [OutNote; 2],
) -> ([Field; 2], [Field; 2], [Field; 2], Field) {
    let mut nullifiers: [Field; 2] = [0; 2];
    let mut total_in = v_in;
    v_in.assert_max_bit_size::<VALUE_BITS>();
    for i in 0..2 {
        let n = ins[i];
        n.value.assert_max_bit_size::<VALUE_BITS>();
        let c = commitment(cid, h([PK, n.sk]), n.value, n.rho, n.r);
        let member = merkle_root(c, n.index, n.path) == root;
        assert(member | (n.value == 0), "input note is not in the tree");
        nullifiers[i] = h([NULLIFIER, h([NK, n.sk]), n.rho]);
        total_in += n.value;
    }
    assert(nullifiers[0] != nullifiers[1], "input nullifiers must differ");

    let mut commitments: [Field; 2] = [0; 2];
    let mut rhos: [Field; 2] = [0; 2];
    let mut total_out = v_out + fee;
    v_out.assert_max_bit_size::<VALUE_BITS>();
    fee.assert_max_bit_size::<VALUE_BITS>();
    for j in 0..2 {
        let o = outs[j];
        o.value.assert_max_bit_size::<VALUE_BITS>();
        rhos[j] = h([RHO, nullifiers[0], j as Field]);
        commitments[j] = commitment(cid, o.pk, o.value, rhos[j], o.r);
        total_out += o.value;
    }
    assert(total_in == total_out, "value is not conserved");
    let ctx = h(
        [CTX, cid, nullifiers[0], nullifiers[1], commitments[0], commitments[1]],
    );
    (nullifiers, commitments, rhos, ctx)
}

/// The refund note of an escrowed output: `value` back to the sender's key `pk`, with
/// rho = H(RHO, N0, 2) (outputs 0 and 1 take j = 0 and 1, so the three never share a nullifier).
pub fn refund(cid: Field, pk: Field, value: Field, n0: Field, r: Field) -> Field {
    commitment(cid, pk, value, h([RHO, n0, 2]), r)
}

/// The transfer: the JoinSplit, with the opening of C'0 for pk_0's owner as
/// the payload (v'0, rho'0, r'0, 0, 0, 0), committed with `note_salt` for the
/// note envelope app (which seals it under KEY_NOTE on the session's chain
/// key), and the refund note C_r of the escrowed C'0 for the key of input 0.
/// `payout_recipient` is published as it is. ctx stays H(CTX, cid, N0, N1,
/// C'0, C'1): C_r is bound by being a public output of the same proof.
pub fn transfer(
    cid: Field,
    root: Field,
    v_in: Field,
    v_out: Field,
    fee: Field,
    payout_recipient: Field,
    ins: [InNote; 2],
    outs: [OutNote; 2],
    note_salt: Field,
    refund_r: Field,
) -> Transfer {
    let (nullifiers, commitments, rhos, ctx) = joinsplit(cid, root, v_in, v_out, fee, ins, outs);
    Transfer {
        ctx,
        cid,
        root,
        nullifiers,
        commitments,
        refund: refund(
            cid,
            h([PK, ins[0].sk]),
            outs[0].value,
            nullifiers[0],
            refund_r,
        ),
        v_in,
        v_out,
        fee,
        payout_recipient,
        note_commitment: commit(note_salt, [outs[0].value, rhos[0], outs[0].r, 0, 0, 0]),
    }
}

/// The holder tag `H(HOLDER, sk, ctx)`: proves, without revealing `sk`, that the spender is the
/// identity cache's registered holder (`identity_member` publishes the same tag; the kernel binds
/// the two). ctx is unique per transfer, so tags don't link transfers.
pub fn holder_tag(sk: Field, ctx: Field) -> Field {
    h([HOLDER, sk, ctx])
}

/// The transfer of the `member_transfer` pipeline: `transfer`, with both inputs (dummies too) held
/// by one key, every output 0 or at least `MIN_NOTE_VALUE`, whose holder tag in this transfer's ctx is
/// the record's second field:
/// `[ctx, holder_tag, cid, root, N0, N1, C0, C1, C_r, v_in, v_out, fee, payout_recipient,
/// note_commitment]`.
pub fn transfer_holder(
    cid: Field,
    root: Field,
    v_in: Field,
    v_out: Field,
    fee: Field,
    payout_recipient: Field,
    ins: [InNote; 2],
    outs: [OutNote; 2],
    note_salt: Field,
    refund_r: Field,
) -> [Field; TRANSFER_HOLDER_FIELDS] {
    assert(ins[0].sk == ins[1].sk, "the inputs have two holders");
    for j in 0..2 {
        // `transfer` range-checks the value to 128 bits, so the cast is exact.
        let v = outs[j].value as u128;
        assert((v == 0) | (v >= MIN_NOTE_VALUE), "output note below the minimum value");
    }
    let t = transfer(
        cid,
        root,
        v_in,
        v_out,
        fee,
        payout_recipient,
        ins,
        outs,
        note_salt,
        refund_r,
    )
        .flatten();
    let mut out: [Field; TRANSFER_HOLDER_FIELDS] = [0; TRANSFER_HOLDER_FIELDS];
    out[0] = t[0];
    out[1] = holder_tag(ins[0].sk, t[0]);
    for i in 1..TRANSFER_FIELDS {
        out[i + 1] = t[i];
    }
    out
}

/// `cid_commit = H(DG1_ENVELOPE, c_id)`: what the chain sees of a sealed DG1. The pool combines it
/// with the session's ct_commitment into `env_commit = H("emit-v2/envelope", ct_commitment,
/// cid_commit)`, which the off-chain envelope (u, v, c_id) must open. Hiding: c_id is the duplex's
/// output under a fresh key.
pub fn cid_commit(c_id: [Field; 6]) -> Field {
    h(
        [DG1_ENVELOPE, c_id[0], c_id[1], c_id[2], c_id[3], c_id[4], c_id[5]],
    )
}

/// The DG1 envelope of the `member_transfer` pipeline: DG1 (opened from the commitment the
/// membership app linked out) sealed under KEY_PAYLOAD on the chain key `s` in context `ctx`,
/// exactly as channel::payload::envelope seals it, but publishing only `cid_commit` of the
/// ciphertext: `[payload_commitment, ctx, C_t, cid_commit]`.
pub fn dg1_envelope(
    payload: [Field; 6],
    salt: Field,
    context: Field,
    s: Field,
) -> [Field; DG1_ENVELOPE_FIELDS] {
    let env = seal_keyed(KEY_PAYLOAD_DOMAIN, s, context, payload);
    [commit(salt, payload), context, env.commitment, cid_commit(env.ciphertext)]
}

/// Resolves an escrowed note, by its owner (the key `sk` whose `pk` the note is for), in the
/// `member_resolve` pipeline: `[holder_tag, cid, C0, action, c_out, fee]`.
/// - C0 = H(COMMITMENT, cid, H(PK, sk), value, rho, r): only the owner knows the opening and `sk`;
/// - ACCEPT: c_out = the note, less `fee`, for the same key, with rho' = H(RHO_RESOLVE, C0) (C0 is
///   unique, so c_out's nullifier is too); 0 or at least `MIN_NOTE_VALUE`, like every note;
/// - REJECT: c_out = 0 and no fee (the pool appends the refund note instead);
/// - the holder tag is taken in ctx = H(RESOLVE, cid, C0, action, c_out, fee), so the membership
///   app's key is the owner's and the tag differs per resolve.
pub fn resolve(
    cid: Field,
    sk: Field,
    value: Field,
    rho: Field,
    r: Field,
    action: Field,
    fee: Field,
    r_out: Field,
) -> [Field; RESOLVE_FIELDS] {
    value.assert_max_bit_size::<VALUE_BITS>();
    fee.assert_max_bit_size::<VALUE_BITS>();
    let pk = h([PK, sk]);
    let c0 = commitment(cid, pk, value, rho, r);
    let accept = action == ACCEPT;
    assert(accept | (action == REJECT), "unknown action");
    assert(accept | (fee == 0), "a reject pays no fee");
    // Every constraint below holds on both branches (a select, not a branch), so nothing depends
    // on how conditional range checks are predicated.
    let kept = if accept { value - fee } else { 0 };
    kept.assert_max_bit_size::<VALUE_BITS>();
    let v = kept as u128;
    assert((v == 0) | (v >= MIN_NOTE_VALUE), "output note below the minimum value");
    let c_kept = commitment(cid, pk, kept, h([RHO_RESOLVE, c0]), r_out);
    let c_out = if accept { c_kept } else { 0 };
    let ctx = h([RESOLVE, cid, c0, action, c_out, fee]);
    [holder_tag(sk, ctx), cid, c0, action, c_out, fee]
}
