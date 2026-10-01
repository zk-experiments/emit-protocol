// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {IMT, Poseidon2} from "./IMT.sol";

/// @notice The identity cache's tree: an IMT of registration leaves the pool appends to.
contract IdentityTree is IMT {
    address public immutable pool;

    error NotPool();

    constructor() {
        pool = msg.sender;
    }

    function insert(uint256 leaf) external returns (uint256) {
        if (msg.sender != pool) revert NotPool();
        return _insert(leaf);
    }
}

/// @notice The Emit V2 private note pool: `register` takes a proof of the `identity_register` pipeline (the
/// passport's eid steps, then the registration) and appends its leaf to the identity tree; one entry point,
/// `transact`, for deposits, private transfers and withdrawals, each a folded proof of `member_transfer`
/// (membership in the identity tree, the channel session, DG1 sealed, the 2-in / 2-out JoinSplit bound to the
/// registered key, its note opening sealed), verified by the ZK_VERIFY precompile. Only registered holders
/// transact; every note is 0 or at least 1/3 of the native coin (the transfer circuit checks it). The checks are the design's "What the chain checks"
/// (emit-v2-transfer-mechanism.md §5) and the identity cache's (README).
///
/// Output 0 is escrowed: `transact` appends C1 and holds C0 with its refund note C_r until the owner resolves it
/// (`resolve`, a proof of `member_resolve`: accept appends the note less a fee, reject appends C_r) or the
/// escrow window passes (`refund`, by anyone: C_r). The sealed DG1 (u, v, c_id) travels off-chain: the chain
/// sees only env_commit = H("emit-v2/envelope", ct_commitment, cid_commit), which it emits in `Escrowed` for
/// the envelope's holder to check against. `Escrowed` and `EscrowClosed` share one sequence (`escrowEventSeq`),
/// so an indexer can prove a range of logs complete.
contract EmitV2Pool is IMT {
    address internal constant ZK_VERIFY = address(0x0100);

    /// Poseidon2 domains (the ASCII tag as a big-endian integer).
    uint256 internal constant D_CTX = 0x656d69742d76322f637478; // "emit-v2/ctx"
    uint256 internal constant D_ENVELOPE = 0x656d69742d76322f656e76656c6f7065; // "emit-v2/envelope"
    /// The BN254 scalar field's modulus.
    uint256 internal constant P = 21888242871839275222246405745257275088548364400416034343698204186575808495617;

    /// The public fields of a proof: deployment root, pipeline root, length, then the 32 slots, the pipeline's
    /// first and zeros after (circuits/manifest.toml; `Outputs::from_fields` in the generated code).
    uint256 internal constant FIELDS = 35;
    uint256 internal constant F_DEPLOYMENT = 0;
    uint256 internal constant F_PIPELINE = 1;
    /// member_transfer and member_resolve: identity root, date, holder tag, then the rest from 6.
    uint256 internal constant F_IDENTITY_ROOT = 3;
    uint256 internal constant F_DATE = 4;
    uint256 internal constant MEMBER_AT = 6;
    /// member_transfer's fields from MEMBER_AT (session, DG1 envelope, transfer, note envelope; 27 slots).
    uint256 internal constant T_CTX = 0;
    uint256 internal constant T_C_T = 1;
    uint256 internal constant T_E_X = 2;
    uint256 internal constant T_E_Y = 3;
    uint256 internal constant T_TAG = 4;
    uint256 internal constant T_CT = 5;
    uint256 internal constant T_CID_COMMIT = 6;
    uint256 internal constant T_CID = 7;
    uint256 internal constant T_ROOT = 8;
    uint256 internal constant T_N0 = 9;
    uint256 internal constant T_C0 = 11;
    uint256 internal constant T_C_R = 13;
    uint256 internal constant T_V_IN = 14;
    uint256 internal constant T_V_OUT = 15;
    uint256 internal constant T_FEE = 16;
    uint256 internal constant T_PAYOUT = 17;
    uint256 internal constant T_C_NOTE = 18; // 18..23
    /// member_resolve's fields from MEMBER_AT (8 slots).
    uint256 internal constant R_CID = 0;
    uint256 internal constant R_C0 = 1;
    uint256 internal constant R_ACTION = 2;
    uint256 internal constant R_C_OUT = 3;
    uint256 internal constant R_FEE = 4;
    /// A resolve's action (emit::ACCEPT, emit::REJECT).
    uint256 internal constant ACCEPT = 0;
    uint256 internal constant REJECT = 1;
    /// identity_register: registry root, date, scope, nullifier, leaf, expiry.
    uint256 internal constant F_REGISTRY_ROOT = 3;
    uint256 internal constant F_SCOPE = 5;
    uint256 internal constant F_NULLIFIER = 6;
    uint256 internal constant F_LEAF = 7;
    uint256 internal constant F_EXPIRY = 8;

    uint256 public constant REGISTRY_RING = 8;

    bytes32 public immutable deploymentRoot;
    /// The pipelines accepted: identity_register, member_transfer, member_resolve.
    bytes32 public immutable registerPipeline;
    bytes32 public immutable memberPipeline;
    bytes32 public immutable resolvePipeline;
    /// How long an escrowed note waits for its owner before anyone may refund it to the sender.
    uint256 public immutable escrowWindow;
    /// The identity cache's tree.
    IdentityTree public immutable identities;
    /// Registrations last until the end of their epoch at most (unix time / IDENTITY_EPOCH): the longest a
    /// revoked passport keeps transacting, so it should match the registry's revocation latency.
    uint256 public constant IDENTITY_EPOCH = 7 days;
    /// In an epoch's last RENEWAL_WINDOW, a holder may register for the next epoch ahead, so a registration
    /// made late in an epoch isn't cut short.
    uint256 public constant RENEWAL_WINDOW = 1 days;
    address public owner;
    uint256 public dateTolerance = 1 days;
    uint256[REGISTRY_RING] public registryRoots;
    uint256 public registryIndex;
    mapping(uint256 => bool) public nullifierSpent;
    /// Document nullifiers (each in its epoch's registrationScope) already registered.
    mapping(uint256 => bool) public documentRegistered;

    /// An escrowed output 0: its refund note and the last second its owner may accept it.
    struct Escrow {
        uint256 refund;
        uint64 deadline;
    }

    /// Open escrows by note commitment C0 (deadline 0: none).
    mapping(uint256 => Escrow) public escrows;
    /// The last sequence number given to an Escrowed or EscrowClosed (the first is 1).
    uint64 public escrowEventSeq;

    event NewNullifier(bytes32 nullifier);
    event NewCommitment(bytes32 commitment, uint256 leafIndex);
    /// The session's public outputs (ct: the lattice ciphertext's commitment) and the sealed note opening. The
    /// lattice ciphertext and the sealed DG1 are not here: they travel off-chain, bound by `Escrowed.envCommit`.
    event Envelope(bytes32 cT, bytes32[2] e, bytes32 tag, bytes32 ct, bytes32[6] cNote);
    event Escrowed(
        uint64 indexed seq, bytes32 noteCommitment, bytes32 chainCommitment, bytes32 envCommit, uint64 deadline
    );
    /// A resolve (accept or reject, not said) or a refund.
    event EscrowClosed(uint64 indexed seq, bytes32 noteCommitment);
    event IdentityRegistered(bytes32 leaf, uint256 index, uint256 expiry);
    event RegistryRoot(uint256 root);

    error NotOwner();
    error InvalidProof(bytes reason);
    error OutputMismatch(string field);
    error UnknownPipeline();
    error UnknownEscrow();
    error EscrowExists();
    error EscrowExpired();
    error EscrowOpen();
    error UnknownAction();
    error UnknownRoot();
    error UnknownIdentityRoot();
    error NullifierSpent();
    error UnknownRegistryRoot();
    error DateOutOfRange();
    error WrongScope();
    error AlreadyRegistered();
    error ExpiryOutOfRange();
    error ValueMismatch();
    error PaymentFailed();

    constructor(
        bytes32 deploymentRoot_,
        bytes32 registerPipeline_,
        bytes32 memberPipeline_,
        bytes32 resolvePipeline_,
        uint256 escrowWindow_
    ) {
        deploymentRoot = deploymentRoot_;
        registerPipeline = registerPipeline_;
        memberPipeline = memberPipeline_;
        resolvePipeline = resolvePipeline_;
        escrowWindow = escrowWindow_;
        identities = new IdentityTree();
        owner = msg.sender;
    }

    modifier onlyOwner() {
        if (msg.sender != owner) revert NotOwner();
        _;
    }

    /// @notice Accepts a csca-registry root (a ring of the last REGISTRY_RING). Devnet: the owner sets them;
    /// on a real chain an eid module holds them.
    function addRegistryRoot(uint256 root) external onlyOwner {
        registryIndex = (registryIndex + 1) % REGISTRY_RING;
        registryRoots[registryIndex] = root;
        emit RegistryRoot(root);
    }

    function setDateTolerance(uint256 seconds_) external onlyOwner {
        dateTolerance = seconds_;
    }

    function transferOwnership(address to) external onlyOwner {
        owner = to;
    }

    function isKnownRegistryRoot(uint256 root) public view returns (bool) {
        if (root == 0) return false;
        for (uint256 i = 0; i < REGISTRY_RING; i++) {
            if (registryRoots[i] == root) return true;
        }
        return false;
    }

    /// @notice The nullifier scope of a registration dated in `epoch`: one per pool and epoch.
    function registrationScope(uint256 epoch) public view returns (uint256) {
        return uint256(keccak256(abi.encode("emit-v2/register", block.chainid, address(this), epoch))) % P;
    }

    /// @notice Registers a passport's holder in the identity cache: a proof of identity_register (the document
    /// in the scope of its date's epoch, then the leaf and its expiry). The document's nullifier in that scope is
    /// used once and the registration ends with the epoch (and, as the circuit checks, at most at the passport's
    /// expiry). In the epoch's last RENEWAL_WINDOW the document may instead be in the next epoch's scope, the
    /// registration then lasting to that epoch's end. So a passport has at most one live registration per pool,
    /// two while a renewal overlaps the current one's last day.
    function register(bytes calldata proof) external {
        uint256[] memory f = _verify(registerPipeline, proof);
        if (!isKnownRegistryRoot(f[F_REGISTRY_ROOT])) revert UnknownRegistryRoot();
        uint256 date = f[F_DATE];
        _checkDate(date);
        uint256 epoch = date / IDENTITY_EPOCH;
        if (f[F_SCOPE] != registrationScope(epoch)) {
            bool renewing = date + RENEWAL_WINDOW >= (epoch + 1) * IDENTITY_EPOCH;
            if (!renewing || f[F_SCOPE] != registrationScope(epoch + 1)) revert WrongScope();
            epoch += 1;
        }
        uint256 nullifier = f[F_NULLIFIER];
        if (documentRegistered[nullifier]) revert AlreadyRegistered();
        uint256 expiry = f[F_EXPIRY];
        if (expiry < date || expiry >= (epoch + 1) * IDENTITY_EPOCH) revert ExpiryOutOfRange();
        documentRegistered[nullifier] = true;
        uint256 leaf = f[F_LEAF];
        emit IdentityRegistered(bytes32(leaf), identities.insert(leaf), expiry);
    }

    /// @notice Spends two notes (nullifiers) and creates two (commitments): C1 is appended, C0 escrowed with its
    /// refund note (see `resolve`, `refund`). A deposit has vPubIn = msg.value and dummy inputs; a withdrawal
    /// pays vPubOut to `payout`; the fee goes to the block producer. `pipeline` is member_transfer's root (the
    /// only one accepted; the argument leaves room for another).
    function transact(
        bytes32 pipeline,
        bytes32 root,
        bytes32[2] calldata nullifiers,
        bytes32[2] calldata commitments,
        uint256 vPubIn,
        uint256 vPubOut,
        uint256 fee,
        address payout,
        bytes calldata proof
    ) external payable {
        if (pipeline != memberPipeline) revert UnknownPipeline();
        uint256 t = MEMBER_AT;
        uint256[] memory f = _verify(pipeline, proof);
        // The registration's expiry is checked in the circuit against this date.
        if (!identities.isKnownRoot(f[F_IDENTITY_ROOT])) revert UnknownIdentityRoot();
        _checkDate(f[F_DATE]);

        // The proof's public fields are the calldata's.
        _eq(f[t + T_CID], block.chainid, "cid");
        _eq(f[t + T_ROOT], uint256(root), "root");
        _eq(f[t + T_N0], uint256(nullifiers[0]), "n0");
        _eq(f[t + T_N0 + 1], uint256(nullifiers[1]), "n1");
        _eq(f[t + T_C0], uint256(commitments[0]), "c0");
        _eq(f[t + T_C0 + 1], uint256(commitments[1]), "c1");
        _eq(f[t + T_V_IN], vPubIn, "vPubIn");
        _eq(f[t + T_V_OUT], vPubOut, "vPubOut");
        _eq(f[t + T_FEE], fee, "fee");
        _eq(f[t + T_PAYOUT], uint256(uint160(payout)), "payout");
        // ctx isn't calldata: recomputed from the transfer's own fields.
        _eq(f[t + T_CTX], _ctx(nullifiers, commitments), "ctx");

        // The pool's state.
        if (!isKnownRoot(uint256(root))) revert UnknownRoot();
        if (
            nullifiers[0] == nullifiers[1] || nullifierSpent[uint256(nullifiers[0])]
                || nullifierSpent[uint256(nullifiers[1])]
        ) revert NullifierSpent();
        if (msg.value != vPubIn) revert ValueMismatch();

        // Effects.
        for (uint256 i = 0; i < 2; i++) {
            nullifierSpent[uint256(nullifiers[i])] = true;
            emit NewNullifier(nullifiers[i]);
        }
        emit NewCommitment(commitments[1], _insert(uint256(commitments[1])));
        _escrow(f, t);
        _envelope(f, t);

        // Value leaving the pool: the fee to the block producer, vPubOut to the payout account.
        _pay(block.coinbase, fee);
        _pay(payout, vPubOut);
    }

    function _checkDate(uint256 date) internal view {
        if (date + dateTolerance < block.timestamp || date > block.timestamp + dateTolerance) {
            revert DateOutOfRange();
        }
    }

    function _verify(bytes32 pipeline, bytes calldata proof) internal view returns (uint256[] memory f) {
        (bool ok, bytes memory ret) = ZK_VERIFY.staticcall(abi.encodePacked(pipeline, proof));
        if (!ok) revert InvalidProof(ret);
        f = abi.decode(ret, (uint256[]));
        if (f.length != FIELDS) revert InvalidProof("fields");
        _eq(f[F_DEPLOYMENT], uint256(deploymentRoot), "deployment root");
        _eq(f[F_PIPELINE], uint256(pipeline), "pipeline root");
    }

    /// Holds C0 until its owner resolves it or the window passes, and publishes env_commit, the commitment the
    /// off-chain envelope (u, v, c_id) opens.
    function _escrow(uint256[] memory f, uint256 t) internal {
        uint256 c0 = f[t + T_C0];
        if (escrows[c0].deadline != 0) revert EscrowExists();
        uint64 deadline = uint64(block.timestamp + escrowWindow);
        escrows[c0] = Escrow({refund: f[t + T_C_R], deadline: deadline});
        uint256[] memory xs = new uint256[](3);
        xs[0] = D_ENVELOPE;
        xs[1] = f[t + T_CT];
        xs[2] = f[t + T_CID_COMMIT];
        emit Escrowed(++escrowEventSeq, bytes32(c0), bytes32(f[t + T_C_T]), bytes32(Poseidon2.hash(xs)), deadline);
    }

    function _envelope(uint256[] memory f, uint256 t) internal {
        bytes32[6] memory cNote;
        for (uint256 i = 0; i < 6; i++) {
            cNote[i] = bytes32(f[t + T_C_NOTE + i]);
        }
        emit Envelope(
            bytes32(f[t + T_C_T]),
            [bytes32(f[t + T_E_X]), bytes32(f[t + T_E_Y])],
            bytes32(f[t + T_TAG]),
            bytes32(f[t + T_CT]),
            cNote
        );
    }

    /// @notice Resolves an escrowed note: a proof of member_resolve by its owner (a registered holder). Accept,
    /// within the window, appends the note less `fee` (paid to the block producer) for the owner; reject, at any
    /// time, appends the sender's refund note.
    function resolve(bytes calldata proof) external {
        uint256[] memory f = _verify(resolvePipeline, proof);
        if (!identities.isKnownRoot(f[F_IDENTITY_ROOT])) revert UnknownIdentityRoot();
        _checkDate(f[F_DATE]);
        uint256 t = MEMBER_AT;
        _eq(f[t + R_CID], block.chainid, "cid");
        uint256 c0 = f[t + R_C0];
        Escrow memory e = _take(c0);
        uint256 action = f[t + R_ACTION];
        if (action == ACCEPT) {
            if (block.timestamp > e.deadline) revert EscrowExpired();
            uint256 out = f[t + R_C_OUT];
            emit NewCommitment(bytes32(out), _insert(out));
            _pay(block.coinbase, f[t + R_FEE]);
        } else if (action == REJECT) {
            emit NewCommitment(bytes32(e.refund), _insert(e.refund));
        } else {
            revert UnknownAction();
        }
    }

    /// @notice After the window, anyone may hand an unresolved escrow back: its refund note is appended.
    function refund(bytes32 noteCommitment) external {
        Escrow memory e = _take(uint256(noteCommitment));
        if (block.timestamp <= e.deadline) revert EscrowOpen();
        emit NewCommitment(bytes32(e.refund), _insert(e.refund));
    }

    /// Closes the escrow of `c0`, once: returns it, deletes it and emits EscrowClosed.
    function _take(uint256 c0) internal returns (Escrow memory e) {
        e = escrows[c0];
        if (e.deadline == 0) revert UnknownEscrow();
        delete escrows[c0];
        emit EscrowClosed(++escrowEventSeq, bytes32(c0));
    }

    function _pay(address to, uint256 amount) internal {
        if (amount == 0) return;
        (bool ok,) = payable(to).call{value: amount}("");
        if (!ok) revert PaymentFailed();
    }

    function _eq(uint256 got, uint256 want, string memory field) internal pure {
        if (got != want) revert OutputMismatch(field);
    }

    /// H("emit-v2/ctx", cid, N0, N1, C0, C1).
    function _ctx(bytes32[2] calldata n, bytes32[2] calldata c) internal view returns (uint256) {
        uint256[] memory xs = new uint256[](6);
        xs[0] = D_CTX;
        xs[1] = block.chainid;
        xs[2] = uint256(n[0]);
        xs[3] = uint256(n[1]);
        xs[4] = uint256(c[0]);
        xs[5] = uint256(c[1]);
        return Poseidon2.hash(xs);
    }
}
