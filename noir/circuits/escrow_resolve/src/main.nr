//! An escrowed note resolved by its owner as a Chonk app of the `member_resolve` pipeline
//! (`emit::resolve`): accept (the note, less the fee, for the owner's key) or reject (the pool
//! appends the sender's refund note): `[holder_tag, cid, C0, action, c_out, fee]`.
use emit::{resolve, RESOLVE_FIELDS};

fn main(
    cid: Field,
    sk: Field,
    value: Field,
    rho: Field,
    r: Field,
    action: Field,
    fee: Field,
    r_out: Field,
) -> return_data [Field; RESOLVE_FIELDS] {
    resolve(cid, sk, value, rho, r, action, fee, r_out)
}
