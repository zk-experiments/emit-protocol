//! Parity with the Rust reference (reference/src/bin/gen.rs writes
//! vectors.nr): the same witness gives the same ctx, nullifiers,
//! commitments and note commitment, and the note envelope app seals the
//! note payload as the reference does.

use crate::transfer;
use crate::vectors::{
    CID, COMMITMENTS, CTX, FEE, INS, NOTE_COMMITMENT, NOTE_ENVELOPE, NOTE_PAYLOAD, NOTE_SALT,
    NULLIFIERS, OUTS, PAYOUT, ROOT, S,
};
use channel::payload::envelope;
use channel::ratchet::{KEY_NOTE_DOMAIN, KEY_PAYLOAD_DOMAIN};

/// The refund note's blinding in these tests (any field: it is the sender's secret).
global REFUND_R: Field = 0x1234;

/// C_r is output 0's value for input 0's key, with the third rho of N0.
#[test]
fn refund_is_output_0_for_the_sender() {
    let t = transfer(CID, ROOT, 0, 0, FEE, PAYOUT, INS, OUTS, NOTE_SALT, REFUND_R);
    let pk = crate::h([crate::PK, INS[0].sk]);
    let rho = crate::h([crate::RHO, NULLIFIERS[0], 2]);
    assert_eq(t.refund, crate::commitment(CID, pk, OUTS[0].value, rho, REFUND_R));
    assert(t.refund != t.commitments[0]);
    assert(t.refund != t.commitments[1]);
}

/// The DG1 envelope seals exactly what the channel's payload envelope seals (so the receiver
/// opens it unchanged) and publishes only the commitment to that ciphertext.
#[test]
fn dg1_envelope_seals_as_the_channel_envelope() {
    let payload = [1, 2, 3, 4, 5, 6];
    let salt = 7;
    let full = envelope(KEY_PAYLOAD_DOMAIN, payload, salt, CTX, S);
    let dg1 = crate::dg1_envelope(payload, salt, CTX, S);
    assert_eq([dg1[0], dg1[1], dg1[2]], [full[0], full[1], full[2]]);
    let c_id = [full[4], full[5], full[6], full[7], full[8], full[9]];
    assert_eq(dg1[3], crate::cid_commit(c_id));
}

/// The owner's note of these tests: C0 of the transfer, for `sk`.
fn owned() -> (Field, Field, Field, Field, Field) {
    let sk = INS[0].sk;
    let value = crate::MIN_NOTE_VALUE as Field + 10;
    let (rho, r) = (NULLIFIERS[0], 99);
    let c0 = crate::commitment(CID, crate::h([crate::PK, sk]), value, rho, r);
    (sk, value, rho, r, c0)
}

#[test]
fn resolve_accept_keeps_the_note_less_the_fee() {
    let (sk, value, rho, r, c0) = owned();
    let out = crate::resolve(CID, sk, value, rho, r, crate::ACCEPT, 10, 5);
    let pk = crate::h([crate::PK, sk]);
    let kept = crate::commitment(CID, pk, value - 10, crate::h([crate::RHO_RESOLVE, c0]), 5);
    assert_eq([out[1], out[2], out[3], out[4], out[5]], [CID, c0, crate::ACCEPT, kept, 10]);
    let ctx = crate::h([crate::RESOLVE, CID, c0, crate::ACCEPT, kept, 10]);
    assert_eq(out[0], crate::holder_tag(sk, ctx));
}

#[test]
fn resolve_reject_hands_back() {
    let (sk, value, rho, r, c0) = owned();
    let out = crate::resolve(CID, sk, value, rho, r, crate::REJECT, 0, 5);
    assert_eq([out[2], out[3], out[4], out[5]], [c0, crate::REJECT, 0, 0]);
}

#[test(should_fail_with = "a reject pays no fee")]
fn resolve_reject_with_a_fee_fails() {
    let (sk, value, rho, r, _) = owned();
    let _ = crate::resolve(CID, sk, value, rho, r, crate::REJECT, 1, 5);
}

#[test(should_fail_with = "unknown action")]
fn resolve_unknown_action_fails() {
    let (sk, value, rho, r, _) = owned();
    let _ = crate::resolve(CID, sk, value, rho, r, 2, 0, 5);
}

#[test(should_fail_with = "output note below the minimum value")]
fn resolve_accept_below_the_minimum_fails() {
    let (sk, value, rho, r, _) = owned();
    let _ = crate::resolve(CID, sk, value, rho, r, crate::ACCEPT, 11, 5);
}

/// A fee above the value would wrap the field: the range check refuses it.
#[test(should_fail)]
fn resolve_fee_above_the_value_fails() {
    let (sk, value, rho, r, _) = owned();
    let _ = crate::resolve(CID, sk, value, rho, r, crate::ACCEPT, value + 1, 5);
}

/// Another key opens a different C0: a resolve can only name its owner's note.
#[test]
fn resolve_by_another_key_names_another_note() {
    let (sk, value, rho, r, c0) = owned();
    let out = crate::resolve(CID, sk + 1, value, rho, r, crate::REJECT, 0, 5);
    assert(out[2] != c0);
}

#[test]
fn transfer_matches_reference() {
    let t = transfer(CID, ROOT, 0, 0, FEE, PAYOUT, INS, OUTS, NOTE_SALT, REFUND_R);
    assert_eq(t.ctx, CTX);
    assert_eq(t.nullifiers, NULLIFIERS);
    assert_eq(t.commitments, COMMITMENTS);
    assert_eq(t.note_commitment, NOTE_COMMITMENT);
    assert_eq(
        [t.cid, t.root, t.v_in, t.v_out, t.fee, t.payout_recipient],
        [CID, ROOT, 0, 0, FEE, PAYOUT],
    );
}

/// The note envelope app (under the session's chain key S) continues the
/// transfer's link and seals the opening the reference seals.
#[test]
fn note_envelope_matches_reference() {
    let t = transfer(CID, ROOT, 0, 0, FEE, PAYOUT, INS, OUTS, NOTE_SALT, REFUND_R);
    let env = envelope(KEY_NOTE_DOMAIN, NOTE_PAYLOAD, NOTE_SALT, CTX, S);
    assert_eq(env[0], t.note_commitment);
    assert_eq(env, NOTE_ENVELOPE);
}

#[test(should_fail_with = "input note is not in the tree")]
fn rejects_wrong_root() {
    let _ = transfer(
        CID,
        ROOT + 1,
        0,
        0,
        FEE,
        PAYOUT,
        INS,
        OUTS,
        NOTE_SALT,
        REFUND_R,
    );
}

#[test(should_fail_with = "value is not conserved")]
fn rejects_wrong_fee() {
    let _ = transfer(
        CID,
        ROOT,
        0,
        0,
        FEE + 1,
        PAYOUT,
        INS,
        OUTS,
        NOTE_SALT,
        REFUND_R,
    );
}

#[test]
fn transfer_holder_publishes_the_tag_of_its_inputs_key() {
    let min = crate::MIN_NOTE_VALUE as Field;
    let (ins, outs) = holder_notes(min, min);
    let v_in = 2 * min + FEE;
    let t = crate::transfer(
        CID,
        ROOT,
        v_in,
        0,
        FEE,
        PAYOUT,
        ins,
        outs,
        NOTE_SALT,
        REFUND_R,
    )
        .flatten();
    let r = deposit(min, min);
    assert_eq(r[0], t[0]);
    assert_eq(r[1], crate::holder_tag(ins[0].sk, t[0]));
    for i in 1..13 {
        assert_eq(r[i + 1], t[i]);
    }
}

#[test(should_fail_with = "the inputs have two holders")]
fn transfer_holder_rejects_two_keys() {
    let min = crate::MIN_NOTE_VALUE as Field;
    let (mut ins, outs) = holder_notes(min, 0);
    ins[1].sk = ins[0].sk + 1;
    let _ = crate::transfer_holder(
        CID,
        ROOT,
        min + FEE,
        0,
        FEE,
        PAYOUT,
        ins,
        outs,
        NOTE_SALT,
        REFUND_R,
    );
}

/// One holder's dummy inputs and outputs worth `a` and `b`.
fn holder_notes(a: Field, b: Field) -> ([crate::InNote; 2], [crate::OutNote; 2]) {
    let mut ins = INS;
    ins[1].sk = ins[0].sk;
    ins[0].value = 0;
    ins[1].value = 0;
    let mut outs = OUTS;
    outs[0].value = a;
    outs[1].value = b;
    (ins, outs)
}

/// A deposit of `a` and `b` into one holder's notes.
fn deposit(a: Field, b: Field) -> [Field; crate::TRANSFER_HOLDER_FIELDS] {
    let (ins, outs) = holder_notes(a, b);
    crate::transfer_holder(
        CID,
        ROOT,
        a + b + FEE,
        0,
        FEE,
        PAYOUT,
        ins,
        outs,
        NOTE_SALT,
        REFUND_R,
    )
}

#[test]
fn transfer_holder_accepts_the_minimum_and_dummies() {
    let min = crate::MIN_NOTE_VALUE as Field;
    let _ = deposit(min, 0);
    let _ = deposit(min, min + 1);
}

#[test(should_fail_with = "output note below the minimum value")]
fn transfer_holder_rejects_a_note_below_the_minimum() {
    let _ = deposit(
        crate::MIN_NOTE_VALUE as Field,
        crate::MIN_NOTE_VALUE as Field - 1,
    );
}
