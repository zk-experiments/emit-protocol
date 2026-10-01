# emit-protocol

The Emit V2 private transfer protocol: its circuits, its pool contract, and the Rust crates every
participant shares. A holder proves their passport once (eid's DSC, SOD and document steps, then a
registration in the pool's identity cache); every transfer after that is one folded proof of
membership, the post-quantum channel session (zk-encryption), DG1 sealed for the receiver, the
2-in / 2-out JoinSplit and its note opening sealed. The receiver's note is escrowed until its
owner resolves it.

Deployments and services build on it: [emit-devnet](https://github.com/zk-experiments/emit-devnet)
runs it on a local chain with a console wallet, and envelope-inbox delivers the envelopes.

## Layers

| Layer | What it is | Where |
|---|---|---|
| **What** is carried | The data a transfer carries between sender and receiver and the commitments that bind it: note and chain commitments, the note opening, the off-chain envelope `(u ‖ v, c_id)` and its `env_commit`, the escrow events, the note math the circuits constrain | `emit-protocol` (crate) |
| **Delivery** | Getting the envelope from sender to receiver: deposit, capability tokens, admission against the escrow, push, retention | not here: envelope-inbox (or emit-devnet's shared directory) |
| **Enforcement** | The chain verifies each transfer's proof against the protocol's rules, and that delivery happened: only the note's owner, who opened it, can resolve its escrow; otherwise it is refunded | `contracts/` (Solidity), bound for alloy by `emit-protocol-abi`; the prover side of the rules is `emit-circuits` |

## Layout

```
noir/                     the emit and identity_cache libraries and their five apps (nargo 1.0.0-rc.3)
contracts/                EmitV2Pool.sol, IMT.sol, their forge tests (forge-std as a submodule)
rust/emit-protocol/       the protocol's values (no prover, no chain client)
rust/emit-protocol-abi/   EmitV2Pool for alloy: abi/EmitV2Pool.json (the forge artifact's ABI and bytecode)
rust/emit-circuits/       the frozen registry emit-protocol@0.1.0 (circuits/manifest.toml, resources/, assets/),
                          eid-circuits and zk-encryption-circuits wrapped, the pipelines, pins.toml, the loaders
scripts/srs.sh            the SRS noir-zk pins, into ~/.bb-crs
```

| Crate | Depends on | Contents |
|---|---|---|
| `emit-protocol` | zk-encryption | `ChainCommitment`, `NoteCommitment`, `EnvCommit` (32 bytes, ↔ `Fr`) and the `bytes32!` macro; `note`: the refund note, the resolve (`Resolve`, `Action`), `MIN_NOTE_VALUE`, zk-encryption's `Emit` re-exported; `Envelope` with `cid_commit` / `commit` (the golden vector lives here); `EscrowLog` / `EscrowEventKind` |
| `emit-protocol-abi` | emit-protocol, alloy | `EmitV2Pool` (every call and event, `deploy` from the bytecode), `escrow_log` (a pool log as an `EscrowLog`), `ESCROW_TOPICS` |
| `emit-circuits` | noir-zk 0.3.0, eid-circuits 0.8.0, zk-encryption-circuits 0.1.1 | `circuits::{pipelines, FAMILIES, DEPLOYMENT, DEPLOYMENT_ROOT}` (fold and verify `identity_register`, `member_transfer`, `member_resolve`), `pins` (`pins.toml` and its check), `setup` (the artifacts a fold draws from, from the registries' CDNs), `verify`, the `catalog` binary |

## Roots (`rust/emit-circuits/pins.toml`)

| what | root |
|---|---|
| library | `emit-protocol@0.1.0` |
| families | `transfer_holder` `0x18ee3ff5…efc7`, `dg1_envelope` `0x0b7d4c28…3119`, `escrow_resolve` `0x04c880b8…2757`, `register` `0x1d0042a0…c1eb`, `member` `0x00f3d510…0a75` |
| deployment | `0x11c8461a…59bd` |
| pipelines | `identity_register` `0x22c5c874…63c1` (4), `member_transfer` `0x2d8c95fc…1aef` (5), `member_resolve` `0x0001d424…2ac4` (2) |

## Building and checking

```sh
mise install && mise run install:zk-toolchain   # foundry, nargo 1.0.0-rc.3, noir-zk 0.3.0
mise run test                                   # nargo test, forge test, cargo test
mise run compile && mise run srs && mise run freeze:check   # the circuits against their frozen keys
mise run abi:check                              # abi/EmitV2Pool.json against forge build
```

Changing a circuit: `mise run compile`, `mise run freeze` (a changed ABI needs `--abi-change`), then
update the roots in `rust/emit-circuits/pins.toml` (the crate's test prints the mismatch).
Changing the contract: `mise run abi` rewrites the artifact the ABI crate is generated from.

## Releasing

CI (`.github/workflows/ci.yml`) bumps the version from conventional commits (cog) and tags it; then,
before the GitHub release exists, publishes the crates to crates.io in dependency order
(`emit-protocol`, `emit-protocol-abi`, `emit-circuits`) and the circuit assets (`manifest.toml`,
`resources.tar.gz`, `catalog.json`) to `https://circuits.zk-experiments.dev/emit-protocol/<version>/`.
The GitHub release comes last, with the assets attached. Secrets: `CARGO_REGISTRY_TOKEN`,
`R2_ZK_EXPERIMENTS_TOKEN` (with the `R2_CIRCUITS_ZK_EXPERIMENTS_BUCKET` and `R2_ACCOUNT_ID` variables).

**Not publishable yet.** crates.io refuses git dependencies, and these are git tags today:
`zk-encryption` and `zk-encryption-circuits` (v0.1.1) and `eid-circuits` (v0.8.0). `emit-protocol` and
`emit-protocol-abi` can publish once `zk-encryption` is on crates.io (`cargo publish --dry-run`
fails only on that); `emit-circuits` needs `zk-encryption-circuits` and `eid-circuits` there too.
The wallet crate must come from the same release as the circuits crate that re-exports it
(`zk_encryption_circuits::wallet`), or the two copies' types differ: switch them together.

Until then releases are off: the `tag` job runs only when the repository variable
`RELEASE_ENABLED` is `true`. Set it once the dependencies are on crates.io; every push to `main`
still runs the checks.

## The contract

`EmitV2Pool` (inherits `IMT`), constructor `(bytes32 deploymentRoot, bytes32 registerPipeline, bytes32 memberPipeline, bytes32 resolvePipeline, uint256 escrowWindow)` (the roots of `identity_register`, `member_transfer`, `member_resolve`, and how long an escrow waits for its owner); it deploys its `IdentityTree` (an `IMT` only the pool appends to).

- `register(bytes proof)`: calls `ZK_VERIFY` with `registerPipeline`; the registry root is accepted; `|date − block.timestamp| ≤ 1 day`; `scope = registrationScope(epoch)` with `epoch = date / IDENTITY_EPOCH`, or, when `date` is in the epoch's last `RENEWAL_WINDOW` (1 day), `registrationScope(epoch + 1)` (then `epoch` is the next one); the document's nullifier (in that scope) is unused, then marked used; `date ≤ expiry < (epoch + 1) · IDENTITY_EPOCH`. Appends the leaf to the identity tree and emits `IdentityRegistered(bytes32 leaf, uint256 index, uint256 expiry)`.
- `transact(bytes32 pipeline, bytes32 root, bytes32[2] nullifiers, bytes32[2] commitments, uint256 vPubIn, uint256 vPubOut, uint256 fee, address payout, bytes proof) payable`: `pipeline` must be `memberPipeline` (anything else reverts `UnknownPipeline`; the argument leaves room for another pipeline); calls `ZK_VERIFY`; the identity root is one the identity tree had; compares the public fields with the calldata (`cid = block.chainid`, root, N₀, N₁, C₀, C₁, vPubIn, vPubOut, fee, payout) and the deployment and pipeline roots; recomputes `ctx = H("emit-v2/ctx", cid, N₀, N₁, C₀, C₁)`; the root is one the note tree had; the nullifiers are unspent and distinct; `|date − block.timestamp| ≤ 1 day`; `msg.value = vPubIn`. Then marks both nullifiers spent, inserts **C₁**, escrows **C₀** with its refund note C_r (the proof's `c_r`) until `block.timestamp + escrowWindow`, and emits `NewNullifier(bytes32)` ×2, `NewCommitment(bytes32 commitment, uint256 leafIndex)`, `Escrowed(uint64 indexed seq, bytes32 noteCommitment, bytes32 chainCommitment, bytes32 envCommit, uint64 deadline)` (with `envCommit = H("emit-v2/envelope", ct_commitment, cid_commit)`, the session's and the DG1 envelope's public outputs) and `Envelope(bytes32 cT, bytes32[2] e, bytes32 tag, bytes32 ct, bytes32[6] cNote)`; pays `fee` to `block.coinbase` and `vPubOut` to `payout`. No ciphertext is in the calldata or the logs.
- `resolve(bytes proof)`: calls `ZK_VERIFY` with `resolvePipeline` (a proof of `member_resolve`); the identity root is one the identity tree had, the date within a day, `cid = block.chainid`; the proof's C₀ is escrowed. Closes the escrow (`EscrowClosed(uint64 indexed seq, bytes32 noteCommitment)`), then on **accept** (before the deadline) inserts the proof's `c_out` (the note less the fee, for the same key) and pays `fee` to `block.coinbase`, on **reject** (any time) inserts the refund note.
- `refund(bytes32 noteCommitment)`: after the deadline, by anyone: closes the escrow and inserts its refund note.
- `Escrowed` and `EscrowClosed` share one counter (`escrowEventSeq()`, the first is 1), so an indexer can prove it read every escrow event of a block range.
- Owner: `addRegistryRoot(uint256)` (a ring of 8), `setDateTolerance(uint256)`, `transferOwnership(address)`.
- Views: `currentRoot()`, `isKnownRoot(uint256)`, `nextIndex()`, `zeros(uint256)`, `EMPTY_ROOT`, `nullifierSpent(uint256)`, `escrows(uint256 c0)` (`refund`, `deadline`), `escrowEventSeq()`, `escrowWindow()`, `isKnownRegistryRoot(uint256)`, `registryRoots(uint256)`, `deploymentRoot()`, `registerPipeline()`, `memberPipeline()`, `resolvePipeline()`, `identities()` (the `IdentityTree`: `currentRoot()`, `isKnownRoot(uint256)`, `nextIndex()`, …), `registrationScope(uint256 epoch)`, `IDENTITY_EPOCH` (7 days), `RENEWAL_WINDOW` (1 day), `documentRegistered(uint256)`, `owner()`.
- Errors: `InvalidProof(bytes)`, `OutputMismatch(string field)`, `UnknownPipeline`, `UnknownRoot`, `UnknownIdentityRoot`, `NullifierSpent`, `UnknownEscrow`, `EscrowExists`, `EscrowExpired`, `EscrowOpen`, `UnknownAction`, `UnknownRegistryRoot`, `DateOutOfRange`, `WrongScope`, `AlreadyRegistered`, `ExpiryOutOfRange`, `ValueMismatch`, `PaymentFailed`, `NotOwner`, `TreeFull` (`IdentityTree`: `NotPool`).

`IMT`: an append-only depth-32 tree over `POSEIDON2` (node `H(left, right)`, empty leaf 0, the empty subtrees' roots as constants), filled-subtree inserts, and every root it ever had kept as known (a mapping). A leaf is never removed, so a proof against an older root is as sound as one against the latest (the nullifiers stop double spends), and a proof can't go stale while other transactions land; the lookup is one storage read instead of a scan of a ring. A wallet's tree must compute the same roots (emit-devnet's `crates/cli/src/tree.rs` does, with a test of the empty root).

## The escrow

A transfer's output 0 (the recipient's note) doesn't enter the note tree when the transfer lands: the pool escrows it with its refund note C_r until the escrow window (`escrowWindow`, a day by default) passes.

- **Off-chain envelope.** The sealed DG1 `c_id` and the lattice ciphertext `(u, v)` are not in the calldata or the logs. The sender hands them to the delivery layer under the transfer's `C_t` (`Envelope`: `u ‖ v` then `c_id`, 1,728 bytes) before sending; `Escrowed` carries `env_commit = H("emit-v2/envelope", ct_commitment, cid_commit)`, which the receiver checks the envelope against before scanning it. What the chain keeps is a commitment to a ciphertext: once the delivery layer deletes its copy (when the escrow closes), nothing on-chain relates to the sender's MRZ.
- **Screen, then resolve.** The receiver scans the envelope as before (the DG1 is the one whose signature chain the sender's registration proved), reads the sender's MRZ, and then resolves: `accept` within the window (the note less a fee enters the tree for the same key), or `reject` at any time (the refund note enters it). Only the note's owner can resolve (the proof opens C₀ with the owner's `sk`), and they must be a registered holder.
- **Refund.** After the window, anyone may call `refund(C₀)`: the refund note enters the tree, and the sender's wallet finds it among its pending notes.
- **Self-transfers** (a wallet's convention, not the protocol's). A deposit, merge or withdrawal puts the kept note in output 1 (appended at once) and leaves output 0 empty; a split, which keeps both outputs, accepts its own escrow at once (a second proof).
- **Sequence.** `Escrowed` and `EscrowClosed` carry one shared, gap-free sequence number (`escrowEventSeq`), so an indexer (the envelope-inbox's) proves each log range complete and deletes an envelope when its escrow closes.

## The circuits

The passport is proved once per registration (eid's DSC, SOD and document steps: about 1 s for an RSA passport, 3.3 s for the German brainpool one). Every transaction proves membership in the on-chain identity tree instead, bound to the registered key; the receiver gets the sender's MRZ through the DG1 envelope. The pool accepts no transfer without a registration.

**Apps** (`emit-protocol@0.1.0`; `noir/lib/identity_cache`, `noir/lib/emit`, the apps in `noir/circuits`):

| app | family (layout) | record | gates |
|---|---|---|---:|
| `register` | `identity_cache/register`: link in 0 (`PayloadCommitment`), public `leaf`, `expiry` | `[payload_commitment, leaf, expiry]` | 4,202 |
| `identity_member` | `identity_cache/member`: link out 0 (`PayloadCommitment`), public `identity_root`, `date`, `holder_tag` | `[payload_commitment, identity_root, date, holder_tag]` | 4,729 |
| `transfer_holder` | `emit/transfer_holder`: binds `ctx` (0) and `holder_tag` (1), link out 13, the rest public | `[ctx, holder_tag, cid, root, N₀, N₁, C₀, C₁, C_r, v_in, v_out, fee, payout, note_commitment]` | 6,926 |
| `dg1_envelope` | `emit/dg1_envelope`: link in 0 (`PayloadCommitment`), binds `ctx` (1) and `c_t` (2), public `cid_commit` | `[payload_commitment, ctx, C_t, cid_commit]` | 339 |
| `escrow_resolve` | `emit/escrow_resolve`: binds `holder_tag` (0), public `cid`, `c0`, `action`, `c_out`, `fee` | `[holder_tag, cid, C₀, action, c_out, fee]` | 3,025 |

- `register(payload_salt, dg1, sk, expiry, r)` parses the DG1 bytes with eid's own `parse_dg1` (eid-circuits v0.8.0's `eid_steps`), rebuilds the payload with eid's `plaintext` and recomputes `commit(payload_salt, payload)`, which the kernel checks equals the document step's link; asserts `expiry ≤` the passport's date of expiry (the MRZ's, last second, UTC); publishes the leaf `L = H(IDENTITY, H(PK, sk), H(payload), expiry, r)` (`IDENTITY = "emit-v2/identity/v2"`; the holder's shielded address, the six-field DG1 payload hashed, the expiry, and `r`, a uniform random blinding the wallet draws and keeps) and `expiry`. The blinding is what keeps the registration private: the holder hands the shielded address to anyone who pays them, and a payee reads the MRZ from their envelopes, so without `r` either could recompute `L` and find the registration. It is the fifth input, which costs one gate: Poseidon2 absorbs three per permutation, so four inputs and five both take two.
- `identity_member(identity_root, date, sk, payload, payload_salt, expiry, r, index, path, ctx)` recomputes the leaf (a wrong `r` gives another leaf, not in the tree), checks its depth-32 path to `identity_root` and `date ≤ expiry`, and returns a fresh `commit(payload_salt, payload)` as its link (the DG1 envelope continues it unchanged) and the holder tag `H(HOLDER, sk, ctx)` (`HOLDER = "emit-v2/holder"`).
- `transfer_holder` is the JoinSplit (`emit::transfer`) with `ins[0].sk = ins[1].sk` (dummies included), every output value 0 or at least `MIN_NOTE_VALUE` (1/3 ETH in wei, 104 gates), and `holder_tag = H(HOLDER, ins[0].sk, ctx)` in its record; the kernel binds it to the member's published tag, and `ctx` to the session's. It also publishes the refund note of the escrowed C₀: `C_r = H(COMMITMENT, cid, H(PK, ins[0].sk), v'₀, H(RHO, N₀, 2), r_r)` (output 0's value for the sender's key; the third rho of N₀, so it never shares a nullifier with C₀ or C₁). `ctx` stays `H(CTX, cid, N₀, N₁, C₀, C₁)`: C_r is bound by being a public output of the same proof.
- `dg1_envelope(payload, salt, context, s)` seals DG1 exactly as the channel's payload envelope does (`seal_keyed` under `KEY_PAYLOAD`, so the receiver opens it unchanged) and publishes only `cid_commit = H("emit-v2/dg1-envelope", c_id)`. It continues the membership app's fresh DG1 commitment and is bound to the session's `ctx` and `C_t`. (It can't also bind `ct_commitment`: a position binds at most two slots. The pool combines the two instead.)
- `escrow_resolve(cid, sk, value, rho, r, action, fee, r_out)` opens C₀ = `H(COMMITMENT, cid, H(PK, sk), value, rho, r)`, which only the owner can (it needs `sk` and the opening from the note envelope); on accept (`action = 0`) `c_out` is the note less `fee` for the same key with `rho' = H("emit-v2/rho-resolve", C₀)` (0 or at least `MIN_NOTE_VALUE`, the fee range-checked), on reject (`1`) `c_out = 0` and no fee; the holder tag is taken in `ctx = H("emit-v2/resolve", cid, C₀, action, c_out, fee)`, bound to the membership app's, so the resolver is the note's registered owner and tags differ per resolve.

**Pipelines** (the deployment has three):

| pipeline | positions | apps / folded circuits | slots |
|---|---|---|---:|
| `identity_register` | eid/dsc, eid/sod, eid/document, identity_cache/register | 4 / 9 | 6: registry_root, date, scope, nullifier, leaf, expiry |
| `member_transfer` | identity_cache/member, channel/session, emit/dg1_envelope, emit/transfer_holder, channel/note_envelope | 5 / 11 | 27: identity_root, date, holder_tag, then the session's (6), `cid_commit`, the transfer's (11, with `c_r`) and the note envelope's (6) |
| `member_resolve` | identity_cache/member, emit/escrow_resolve | 2 / 5 | 8: identity_root, date, holder_tag, cid, c0, action, c_out, fee |

(Folded circuits: the apps, a kernel per app, and the hiding kernel.)

**Design decisions:**

- *Transactions require a registration.* The deployment has three pipelines, `identity_register`, `member_transfer` and `member_resolve`; `transact` accepts only `member_transfer` and `resolve` only `member_resolve`, both of which open with membership. The registration is what binds a shielded key to a passport; a transfer proof carries membership of that key, so the notes' owner is the registered holder.
- *Expiry from the MRZ.* `register` takes the 95-byte DG1 buffer as its private input, rebuilds the payload from it (the kernel checks its commitment against the document step's link; `pack_be` is injective, so the bytes are pinned) and reads the date of expiry as the document step does. `expiry` is at most that date; the chain caps it at the end of the registration's epoch. The register app is 4,202 gates.
- *Holder binding.* `identity_member` takes `ctx` as a private input and publishes `holder_tag = H(HOLDER, sk, ctx)`; the kernel binds `transfer_holder`'s tag to it and `transfer_holder`'s `ctx` to the session's. Equal tags mean equal `(sk, ctx)`, so the member's key is the spender's and its `ctx` the transfer's. Membership is the pipeline's first app. The wallet computes `ctx` from the nullifiers and commitments before proving. `ctx` is unique per transfer, so tags don't link transfers.
- *One key per transfer.* `transfer_holder` requires both inputs held by one key and tags that key. The wallet makes dummy inputs with its own key and a fresh `rho` (a fresh nullifier). A transfer can't spend another key's note alongside the holder's.
- *Minimum note value.* Every output of `transfer_holder` is 0 or at least `MIN_NOTE_VALUE` (1/3 of the native coin, in wei). Note values are private, so the circuit enforces it; the contract can't.
- *Registration scope.* The document step's scope is `registrationScope(epoch)`, `keccak256("emit-v2/register", chainid, pool, epoch) mod p`, `epoch = date / 7 days`, and the contract records the document's nullifier in that scope: one registration per passport per epoch, and `expiry < (epoch + 1) · 7 days`. In an epoch's last day (`RENEWAL_WINDOW`) the next epoch's scope is also accepted, with expiry up to that epoch's end. A passport has at most one live registration per pool, two during that day.
- *Contracts.* The identity tree is a separate contract (`IdentityTree is IMT`, created by the pool); `IMT` keeps its state in contract storage. `transact` takes the pipeline root as its first argument. The chain checks the proof's date against the block time; the circuit checks the registration's expiry against that date.

**Soundness notes:**

- *Revocation.* A registration is checked against the CSCA registry once, when it is made; revoking the DSC or CSCA afterwards takes effect only when the registration expires, at the end of its epoch (at most 7 days, plus the 1-day date tolerance, as a member proof's date may lag the block by a day). Likewise the passport's own expiry: a registration made on its last day ends with it.
- *Privacy.* A registration is public: its leaf, its expiry, the document's nullifier in the epoch's scope (in the `identity_register` proof's public fields), and whatever account sent it and when. The leaf is blinded by `r`: knowing the holder's shielded address (given to everyone who pays them) and MRZ (read by every payee from the DG1 envelope) doesn't let anyone recompute the leaf and find the registration; only the wallet holding `r` and `sk` can. The nullifier is eid's document nullifier in the epoch's scope, `H("eid-nullifier/v1", scope, SOD messageDigest)`: unlinkable across epochs and pools. The MRZ alone doesn't give it, but whoever holds the passport's SOD (anyone who has read its chip; with the passport in hand, the MRZ opens the chip) can compute it for the public scope and find the registration; the blinding doesn't cover it. Later transfers don't reveal which leaf they prove: a member proof publishes only the identity root, the date and a holder tag that changes with every ctx. The anonymity set is the tree's leaves at that root; which root a proof uses dates it roughly (the wallet uses the latest). Losing `r` makes the registration unusable, and the scoped nullifier blocks registering the passport again before the next epoch (or its last day).
- *A leaked `sk`* lets its holder spend the notes and prove membership as the registered identity (the MRZ goes to receivers under that name) until the registration expires: the same as losing the notes.
- *One passport, many holder keys:* prevented within an epoch by the scoped nullifier, except for the renewal's overlap: in an epoch's last day a passport can hold its current registration under one key and the next epoch's under another. Two users sharing a passport can't both register in the same epoch.
- *Front-running.* A register proof commits to its leaf; anyone may submit it, with the same effect.
