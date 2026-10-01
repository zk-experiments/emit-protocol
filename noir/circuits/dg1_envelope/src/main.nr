//! DG1 sealed on the channel as a Chonk app of the `member_transfer` pipeline
//! (`emit::dg1_envelope`): the payload the membership app linked out, sealed under KEY_PAYLOAD on
//! the session's chain key in its ctx, publishing only a commitment to the ciphertext:
//! `[payload_commitment, ctx, C_t, cid_commit]`. The ciphertext itself travels off-chain.
use emit::{dg1_envelope, DG1_ENVELOPE_FIELDS};

fn main(
    payload: [Field; 6],
    salt: Field,
    context: Field,
    s: Field,
) -> return_data [Field; DG1_ENVELOPE_FIELDS] {
    dg1_envelope(payload, salt, context, s)
}
