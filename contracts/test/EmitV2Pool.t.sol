// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {EmitV2Pool, IdentityTree} from "../src/EmitV2Pool.sol";

/// Stands in for ZK_VERIFY: returns the fields it was given (or reverts), whatever the proof.
contract MockVerifier {
    uint256[] public fields;
    bool public fail;

    function set(uint256[] calldata f, bool fail_) external {
        fields = f;
        fail = fail_;
    }

    fallback(bytes calldata) external returns (bytes memory) {
        require(!fail, "proof does not verify");
        return abi.encode(fields);
    }
}

/// Stands in for POSEIDON2: keccak256 of the input, reduced mod p (the contract logic doesn't depend on
/// which hash it is; the devnet end to end checks the real one against the wallet).
contract MockPoseidon {
    fallback(bytes calldata input) external returns (bytes memory) {
        require(input.length > 0 && input.length % 32 == 0, "words");
        return abi.encode(uint256(keccak256(input)) % 21888242871839275222246405745257275088548364400416422507208617);
    }
}

contract EmitV2PoolTest is Test {
    address constant VERIFY = address(0x0100);
    address constant POSEIDON = address(0x0101);
    bytes32 constant DEPLOYMENT = bytes32(uint256(0xd0));
    bytes32 constant REGISTER = bytes32(uint256(0xa2));
    bytes32 constant MEMBER = bytes32(uint256(0xa3));
    bytes32 constant RESOLVE = bytes32(uint256(0xa4));
    uint256 constant WINDOW = 1 days;
    uint256 constant REGISTRY = 0x1234;

    EmitV2Pool pool;
    address payout = address(0xB0B);
    address producer = address(0xC0FFEE);

    struct Call {
        bytes32 pipeline;
        bytes32 root;
        bytes32[2] n;
        bytes32[2] c;
        uint256 vIn;
        uint256 vOut;
        uint256 fee;
        address payout;
    }

    function setUp() public {
        vm.etch(VERIFY, address(new MockVerifier()).code);
        vm.etch(POSEIDON, address(new MockPoseidon()).code);
        pool = new EmitV2Pool(DEPLOYMENT, REGISTER, MEMBER, RESOLVE, WINDOW);
        pool.addRegistryRoot(REGISTRY);
        vm.warp(1_790_467_200);
        vm.coinbase(producer);
        vm.deal(address(this), 1000 ether);
    }

    function call(uint256 vIn, uint256 vOut, uint256 fee, uint256 salt) internal view returns (Call memory c) {
        c.pipeline = MEMBER;
        c.root = bytes32(pool.currentRoot());
        c.n = [keccak256(abi.encode("n0", salt)), keccak256(abi.encode("n1", salt))];
        c.c = [keccak256(abi.encode("c0", salt)), keccak256(abi.encode("c1", salt))];
        c.vIn = vIn;
        c.vOut = vOut;
        c.fee = fee;
        c.payout = vOut > 0 ? payout : address(0);
    }

    /// The fields a valid member_transfer proof of `c` would publish: identity root, date, holder tag, then
    /// the session, DG1 envelope, transfer and note envelope from 6 (27 slots), zeros after.
    function fieldsOf(Call memory c) internal view returns (uint256[] memory f) {
        uint256 t = 6;
        f = new uint256[](35);
        f[0] = uint256(DEPLOYMENT);
        f[1] = uint256(c.pipeline);
        f[2] = 5;
        f[3] = pool.identities().currentRoot();
        f[4] = block.timestamp;
        f[5] = 0x7a6;
        (, bytes memory ctx) = POSEIDON.staticcall(
            abi.encode(
                uint256(0x656d69742d76322f637478),
                block.chainid,
                uint256(c.n[0]),
                uint256(c.n[1]),
                uint256(c.c[0]),
                uint256(c.c[1])
            )
        );
        f[t] = abi.decode(ctx, (uint256));
        f[t + 1] = uint256(keccak256(abi.encode("c_t", c.c[0])));
        f[t + 5] = 0xc7;
        f[t + 6] = 0xc1d;
        f[t + 7] = block.chainid;
        f[t + 8] = uint256(c.root);
        f[t + 9] = uint256(c.n[0]);
        f[t + 10] = uint256(c.n[1]);
        f[t + 11] = uint256(c.c[0]);
        f[t + 12] = uint256(c.c[1]);
        f[t + 13] = refundOf(c);
        f[t + 14] = c.vIn;
        f[t + 15] = c.vOut;
        f[t + 16] = c.fee;
        f[t + 17] = uint256(uint160(c.payout));
        for (uint256 i = 0; i < 6; i++) {
            f[t + 18 + i] = 0x100 + i;
        }
    }

    function refundOf(Call memory c) internal pure returns (uint256) {
        return uint256(keccak256(abi.encode("c_r", c.c[0])));
    }

    function send(Call memory c, uint256[] memory f, uint256 value) internal {
        MockVerifier(VERIFY).set(f, false);
        pool.transact{value: value}(c.pipeline, c.root, c.n, c.c, c.vIn, c.vOut, c.fee, c.payout, hex"00");
    }

    function deposit(uint256 v, uint256 salt) internal returns (Call memory c) {
        c = call(v, 0, 0, salt);
        send(c, fieldsOf(c), v);
    }

    function test_deposit_appends_c1_escrows_c0_and_emits() public {
        Call memory c = call(100 ether, 0, 0, 1);
        uint256[] memory f = fieldsOf(c);
        MockVerifier(VERIFY).set(f, false);
        vm.expectEmit(address(pool));
        emit EmitV2Pool.NewNullifier(c.n[0]);
        vm.expectEmit(address(pool));
        emit EmitV2Pool.NewNullifier(c.n[1]);
        vm.expectEmit(address(pool));
        emit EmitV2Pool.NewCommitment(c.c[1], 0);
        vm.expectEmit(address(pool));
        emit EmitV2Pool.Escrowed(
            1,
            c.c[0],
            bytes32(f[7]),
            bytes32(poseidon3(0x656d69742d76322f656e76656c6f7065, 0xc7, 0xc1d)),
            uint64(block.timestamp + WINDOW)
        );
        pool.transact{value: 100 ether}(c.pipeline, c.root, c.n, c.c, c.vIn, c.vOut, c.fee, c.payout, hex"00");
        assertEq(pool.nextIndex(), 1, "only C1 is appended");
        (uint256 r, uint64 deadline) = pool.escrows(uint256(c.c[0]));
        assertEq(r, refundOf(c));
        assertEq(deadline, block.timestamp + WINDOW);
        assertEq(pool.escrowEventSeq(), 1);
        assertEq(address(pool).balance, 100 ether);
        assertTrue(pool.nullifierSpent(uint256(c.n[0])));
        assertTrue(pool.isKnownRoot(uint256(c.root)), "the previous root stays known");
        assertTrue(pool.currentRoot() != uint256(c.root));
    }

    function test_withdraw_pays_payout_and_fee_to_the_producer() public {
        deposit(100 ether, 1);
        Call memory c = call(0, 30 ether, 1 ether, 2);
        send(c, fieldsOf(c), 0);
        assertEq(payout.balance, 30 ether);
        assertEq(producer.balance, 1 ether);
        assertEq(address(pool).balance, 69 ether);
    }

    function test_withdraw_beyond_the_pool_reverts() public {
        deposit(10 ether, 1);
        Call memory c = call(0, 30 ether, 0, 2);
        uint256[] memory f = fieldsOf(c);
        MockVerifier(VERIFY).set(f, false);
        vm.expectRevert(EmitV2Pool.PaymentFailed.selector);
        pool.transact(c.pipeline, c.root, c.n, c.c, c.vIn, c.vOut, c.fee, c.payout, hex"00");
    }

    function test_replay_is_refused() public {
        Call memory c = deposit(1 ether, 1);
        c.root = bytes32(pool.currentRoot());
        uint256[] memory f = fieldsOf(c);
        MockVerifier(VERIFY).set(f, false);
        vm.expectRevert(EmitV2Pool.NullifierSpent.selector);
        pool.transact{value: 1 ether}(c.pipeline, c.root, c.n, c.c, c.vIn, c.vOut, c.fee, c.payout, hex"00");
    }

    function test_equal_nullifiers_are_refused() public {
        Call memory c = call(1 ether, 0, 0, 1);
        c.n[1] = c.n[0];
        uint256[] memory f = fieldsOf(c);
        MockVerifier(VERIFY).set(f, false);
        vm.expectRevert(EmitV2Pool.NullifierSpent.selector);
        pool.transact{value: 1 ether}(c.pipeline, c.root, c.n, c.c, c.vIn, c.vOut, c.fee, c.payout, hex"00");
    }

    function test_every_root_stays_known() public {
        bytes32 first = bytes32(pool.currentRoot());
        for (uint256 i = 0; i < 40; i++) {
            deposit(1, 10 + i); // 80 inserts: more than Emit V1's ring of 32 kept
        }
        Call memory c = call(1, 0, 0, 99);
        c.root = first;
        send(c, fieldsOf(c), 1);

        c = call(1, 0, 0, 100);
        c.root = bytes32(uint256(0x404));
        uint256[] memory f = fieldsOf(c);
        MockVerifier(VERIFY).set(f, false);
        vm.expectRevert(EmitV2Pool.UnknownRoot.selector);
        pool.transact{value: 1}(c.pipeline, c.root, c.n, c.c, c.vIn, c.vOut, c.fee, c.payout, hex"00");
    }

    function test_value_must_equal_vpubin() public {
        Call memory c = call(1 ether, 0, 0, 1);
        MockVerifier(VERIFY).set(fieldsOf(c), false);
        vm.expectRevert(EmitV2Pool.ValueMismatch.selector);
        pool.transact{value: 2 ether}(c.pipeline, c.root, c.n, c.c, c.vIn, c.vOut, c.fee, c.payout, hex"00");
    }

    function test_a_proof_that_does_not_verify_reverts() public {
        Call memory c = call(1 ether, 0, 0, 1);
        MockVerifier(VERIFY).set(fieldsOf(c), true);
        vm.expectRevert();
        pool.transact{value: 1 ether}(c.pipeline, c.root, c.n, c.c, c.vIn, c.vOut, c.fee, c.payout, hex"00");
    }

    function test_only_the_owner_sets_registry_roots() public {
        vm.prank(address(0xBAD));
        vm.expectRevert(EmitV2Pool.NotOwner.selector);
        pool.addRegistryRoot(1);
        pool.addRegistryRoot(0x5678);
        assertTrue(pool.isKnownRegistryRoot(0x5678));
        assertTrue(pool.isKnownRegistryRoot(REGISTRY));
    }

    /// The tree: filled-subtree inserts give the root of a complete tree with zero leaves.
    function test_tree_root_is_the_complete_tree() public {
        deposit(1, 1);
        deposit(1, 2);
        (, bytes memory h) = POSEIDON.staticcall(
            abi.encode(
                uint256(keccak256(abi.encode("c1", uint256(1)))), uint256(keccak256(abi.encode("c1", uint256(2))))
            )
        );
        uint256 node = abi.decode(h, (uint256));
        for (uint256 i = 1; i < 32; i++) {
            (, h) = POSEIDON.staticcall(abi.encode(node, pool.zeros(i)));
            node = abi.decode(h, (uint256));
        }
        assertEq(pool.currentRoot(), node);
    }

    // ------------------------------------------------------------ the identity cache

    /// The fields of an identity_register proof: registry root, date, scope, nullifier, leaf, expiry.
    function registration(uint256 leaf, uint256 nullifier, uint256 expiry) internal view returns (uint256[] memory f) {
        f = new uint256[](35);
        f[0] = uint256(DEPLOYMENT);
        f[1] = uint256(REGISTER);
        f[2] = 4;
        f[3] = REGISTRY;
        // vm.getBlockTimestamp: under via_ir, block.timestamp may be read before a vm.warp.
        uint256 now_ = vm.getBlockTimestamp();
        f[4] = now_;
        f[5] = pool.registrationScope(now_ / 7 days);
        f[6] = nullifier;
        f[7] = leaf;
        f[8] = expiry;
    }

    /// The last second of the current epoch.
    function epochEnd() internal view returns (uint256) {
        return (vm.getBlockTimestamp() / 7 days + 1) * 7 days - 1;
    }

    function registerOk(uint256 leaf, uint256 nullifier) internal {
        MockVerifier(VERIFY).set(registration(leaf, nullifier, epochEnd()), false);
        pool.register(hex"00");
    }

    function test_register_appends_the_leaf_and_emits() public {
        uint256 expiry = epochEnd();
        MockVerifier(VERIFY).set(registration(0x1eaf, 0xd0c, expiry), false);
        vm.expectEmit(address(pool));
        emit EmitV2Pool.IdentityRegistered(bytes32(uint256(0x1eaf)), 0, expiry);
        pool.register(hex"00");
        assertEq(pool.identities().nextIndex(), 1);
        assertTrue(pool.documentRegistered(0xd0c));
        assertEq(pool.nextIndex(), 0, "the note tree is untouched");
        assertTrue(pool.identities().currentRoot() != pool.identities().EMPTY_ROOT());
    }

    function test_register_checks() public {
        uint256 ok = epochEnd();
        uint256[] memory f;

        f = registration(1, 2, ok);
        f[5] = 0;
        MockVerifier(VERIFY).set(f, false);
        vm.expectRevert(EmitV2Pool.WrongScope.selector);
        pool.register(hex"00");

        f = registration(1, 2, ok);
        f[3] = 0x9999;
        MockVerifier(VERIFY).set(f, false);
        vm.expectRevert(EmitV2Pool.UnknownRegistryRoot.selector);
        pool.register(hex"00");

        f = registration(1, 2, ok);
        f[4] = block.timestamp - 2 days;
        MockVerifier(VERIFY).set(f, false);
        vm.expectRevert(EmitV2Pool.DateOutOfRange.selector);
        pool.register(hex"00");

        MockVerifier(VERIFY).set(registration(1, 2, ok + 1), false);
        vm.expectRevert(EmitV2Pool.ExpiryOutOfRange.selector);
        pool.register(hex"00");

        MockVerifier(VERIFY).set(registration(1, 2, block.timestamp - 1), false);
        vm.expectRevert(EmitV2Pool.ExpiryOutOfRange.selector);
        pool.register(hex"00");

        registerOk(1, 2);
        MockVerifier(VERIFY).set(registration(3, 2, ok), false);
        vm.expectRevert(EmitV2Pool.AlreadyRegistered.selector);
        pool.register(hex"00");

        // The next epoch has its own scope (the same document gives another nullifier there).
        vm.warp(ok + 1);
        f = registration(3, 2, ok);
        f[5] = pool.registrationScope(block.timestamp / 7 days - 1);
        MockVerifier(VERIFY).set(f, false);
        vm.expectRevert(EmitV2Pool.WrongScope.selector);
        pool.register(hex"00");
        registerOk(3, 4);
    }

    /// In the epoch's last day a holder registers for the next epoch, until its end.
    function test_register_ahead_in_the_last_day() public {
        uint256 end = epochEnd();
        uint256 nextEnd = end + 7 days;
        uint256[] memory f;

        // Before the last day, the next epoch's scope is refused.
        f = registration(1, 2, nextEnd);
        f[5] = pool.registrationScope(vm.getBlockTimestamp() / 7 days + 1);
        MockVerifier(VERIFY).set(f, false);
        vm.expectRevert(EmitV2Pool.WrongScope.selector);
        pool.register(hex"00");

        vm.warp(end + 1 - 1 days);
        f = registration(1, 2, nextEnd + 1);
        f[5] = pool.registrationScope(vm.getBlockTimestamp() / 7 days + 1);
        MockVerifier(VERIFY).set(f, false);
        vm.expectRevert(EmitV2Pool.ExpiryOutOfRange.selector);
        pool.register(hex"00");

        f[8] = nextEnd;
        MockVerifier(VERIFY).set(f, false);
        vm.expectEmit(address(pool));
        emit EmitV2Pool.IdentityRegistered(bytes32(uint256(1)), 0, nextEnd);
        pool.register(hex"00");

        // The current epoch's scope still works (another nullifier); the next one's is used up.
        registerOk(3, 4);
        vm.warp(end + 1);
        MockVerifier(VERIFY).set(registration(5, 2, nextEnd), false);
        vm.expectRevert(EmitV2Pool.AlreadyRegistered.selector);
        pool.register(hex"00");
    }

    function test_register_takes_only_the_register_pipeline() public {
        // A transfer proof (another pipeline's fields) is refused: the verifier is asked for REGISTER and the
        // proof's pipeline root must be REGISTER.
        uint256[] memory f = registration(1, 2, epochEnd());
        f[1] = uint256(MEMBER);
        MockVerifier(VERIFY).set(f, false);
        vm.expectRevert(abi.encodeWithSelector(EmitV2Pool.OutputMismatch.selector, "pipeline root"));
        pool.register(hex"00");

        f = new uint256[](34);
        MockVerifier(VERIFY).set(f, false);
        vm.expectRevert(abi.encodeWithSelector(EmitV2Pool.InvalidProof.selector, bytes("fields")));
        pool.register(hex"00");
    }

    function test_member_transfer_checks() public {
        registerOk(0x1eaf, 0xd0c);
        Call memory c = call(1 ether, 0, 0, 1);

        uint256[] memory f = fieldsOf(c);
        f[3] = 0x404;
        MockVerifier(VERIFY).set(f, false);
        vm.expectRevert(EmitV2Pool.UnknownIdentityRoot.selector);
        pool.transact{value: 1 ether}(c.pipeline, c.root, c.n, c.c, c.vIn, c.vOut, c.fee, c.payout, hex"00");

        // Expired: a date the chain doesn't accept (the circuit checks the registration's expiry against it).
        f = fieldsOf(c);
        f[4] = block.timestamp + 2 days;
        MockVerifier(VERIFY).set(f, false);
        vm.expectRevert(EmitV2Pool.DateOutOfRange.selector);
        pool.transact{value: 1 ether}(c.pipeline, c.root, c.n, c.c, c.vIn, c.vOut, c.fee, c.payout, hex"00");

        f = fieldsOf(c);
        f[0] ^= 1;
        MockVerifier(VERIFY).set(f, false);
        vm.expectRevert(abi.encodeWithSelector(EmitV2Pool.OutputMismatch.selector, "deployment root"));
        pool.transact{value: 1 ether}(c.pipeline, c.root, c.n, c.c, c.vIn, c.vOut, c.fee, c.payout, hex"00");

        // Every transfer field is read at member_transfer's offsets.
        string[11] memory names = ["cid", "root", "n0", "n1", "c0", "c1", "vPubIn", "vPubOut", "fee", "payout", "ctx"];
        uint256[11] memory index = [uint256(13), 14, 15, 16, 17, 18, 20, 21, 22, 23, 6];
        for (uint256 k = 0; k < 11; k++) {
            f = fieldsOf(c);
            f[index[k]] ^= 1;
            MockVerifier(VERIFY).set(f, false);
            vm.expectRevert(abi.encodeWithSelector(EmitV2Pool.OutputMismatch.selector, names[k]));
            pool.transact{value: 1 ether}(c.pipeline, c.root, c.n, c.c, c.vIn, c.vOut, c.fee, c.payout, hex"00");
        }
    }

    function test_an_old_identity_root_stays_valid() public {
        registerOk(1, 1);
        uint256 first = pool.identities().currentRoot();
        registerOk(2, 2);
        Call memory c = call(1 ether, 0, 0, 1);
        uint256[] memory f = fieldsOf(c);
        f[3] = first;
        send(c, f, 1 ether);
    }

    function test_transact_takes_only_member_transfer() public {
        Call memory c = call(1 ether, 0, 0, 1);
        c.pipeline = REGISTER;
        MockVerifier(VERIFY).set(fieldsOf(c), false);
        vm.expectRevert(EmitV2Pool.UnknownPipeline.selector);
        pool.transact{value: 1 ether}(c.pipeline, c.root, c.n, c.c, c.vIn, c.vOut, c.fee, c.payout, hex"00");

        // Another pipeline's proof sent as a member transfer: the pipeline root differs.
        c = call(1 ether, 0, 0, 1);
        uint256[] memory f = fieldsOf(c);
        f[1] = uint256(bytes32(uint256(0xa1)));
        MockVerifier(VERIFY).set(f, false);
        vm.expectRevert(abi.encodeWithSelector(EmitV2Pool.OutputMismatch.selector, "pipeline root"));
        pool.transact{value: 1 ether}(c.pipeline, c.root, c.n, c.c, c.vIn, c.vOut, c.fee, c.payout, hex"00");
    }

    function test_only_the_pool_inserts_identities() public {
        IdentityTree t = pool.identities();
        vm.expectRevert(IdentityTree.NotPool.selector);
        t.insert(1);
    }

    // ------------------------------------------------------------ the escrow

    function poseidon3(uint256 a, uint256 b, uint256 c) internal view returns (uint256) {
        (, bytes memory h) = POSEIDON.staticcall(abi.encode(a, b, c));
        return abi.decode(h, (uint256));
    }

    /// The fields of a member_resolve proof of `c0`: identity root, date, holder tag, cid, C0, action, c_out, fee.
    function resolution(bytes32 c0, uint256 action, uint256 out, uint256 fee)
        internal
        view
        returns (uint256[] memory f)
    {
        f = new uint256[](35);
        f[0] = uint256(DEPLOYMENT);
        f[1] = uint256(RESOLVE);
        f[2] = 2;
        f[3] = pool.identities().currentRoot();
        f[4] = vm.getBlockTimestamp();
        f[5] = 0x7a7;
        f[6] = block.chainid;
        f[7] = uint256(c0);
        f[8] = action;
        f[9] = out;
        f[10] = fee;
    }

    function resolveWith(uint256[] memory f) internal {
        MockVerifier(VERIFY).set(f, false);
        pool.resolve(hex"00");
    }

    function test_accept_appends_the_note_and_pays_the_fee() public {
        Call memory c = deposit(10 ether, 1);
        MockVerifier(VERIFY).set(resolution(c.c[0], 0, 0x0e7, 1 ether), false);
        vm.expectEmit(address(pool));
        emit EmitV2Pool.EscrowClosed(2, c.c[0]);
        vm.expectEmit(address(pool));
        emit EmitV2Pool.NewCommitment(bytes32(uint256(0x0e7)), 1);
        pool.resolve(hex"00");
        assertEq(producer.balance, 1 ether);
        assertEq(pool.nextIndex(), 2);
        (, uint64 deadline) = pool.escrows(uint256(c.c[0]));
        assertEq(deadline, 0, "closed");
        assertEq(pool.escrowEventSeq(), 2);
    }

    function test_reject_appends_the_refund_any_time() public {
        Call memory c = deposit(10 ether, 1);
        vm.warp(block.timestamp + WINDOW + 1);
        MockVerifier(VERIFY).set(resolution(c.c[0], 1, 0, 0), false);
        vm.expectEmit(address(pool));
        emit EmitV2Pool.NewCommitment(bytes32(refundOf(c)), 1);
        pool.resolve(hex"00");
        assertEq(producer.balance, 0);
    }

    function test_accept_after_the_window_is_refused() public {
        Call memory c = deposit(10 ether, 1);
        vm.warp(block.timestamp + WINDOW + 1);
        MockVerifier(VERIFY).set(resolution(c.c[0], 0, 0x0e7, 0), false);
        vm.expectRevert(EmitV2Pool.EscrowExpired.selector);
        pool.resolve(hex"00");
    }

    function test_an_escrow_resolves_once() public {
        Call memory c = deposit(10 ether, 1);
        resolveWith(resolution(c.c[0], 0, 0x0e7, 0));
        MockVerifier(VERIFY).set(resolution(c.c[0], 1, 0, 0), false);
        vm.expectRevert(EmitV2Pool.UnknownEscrow.selector);
        pool.resolve(hex"00");
        vm.expectRevert(EmitV2Pool.UnknownEscrow.selector);
        pool.refund(c.c[0]);
    }

    function test_resolve_checks() public {
        Call memory c = deposit(10 ether, 1);
        uint256[] memory f;

        f = resolution(c.c[0], 2, 0, 0);
        MockVerifier(VERIFY).set(f, false);
        vm.expectRevert(EmitV2Pool.UnknownAction.selector);
        pool.resolve(hex"00");

        f = resolution(bytes32(uint256(0x404)), 0, 1, 0);
        MockVerifier(VERIFY).set(f, false);
        vm.expectRevert(EmitV2Pool.UnknownEscrow.selector);
        pool.resolve(hex"00");

        f = resolution(c.c[0], 0, 1, 0);
        f[3] = 0x404;
        MockVerifier(VERIFY).set(f, false);
        vm.expectRevert(EmitV2Pool.UnknownIdentityRoot.selector);
        pool.resolve(hex"00");

        f = resolution(c.c[0], 0, 1, 0);
        f[6] ^= 1;
        MockVerifier(VERIFY).set(f, false);
        vm.expectRevert(abi.encodeWithSelector(EmitV2Pool.OutputMismatch.selector, "cid"));
        pool.resolve(hex"00");

        // A transfer proof is not a resolve.
        f = resolution(c.c[0], 0, 1, 0);
        f[1] = uint256(MEMBER);
        MockVerifier(VERIFY).set(f, false);
        vm.expectRevert(abi.encodeWithSelector(EmitV2Pool.OutputMismatch.selector, "pipeline root"));
        pool.resolve(hex"00");
    }

    function test_refund_only_after_the_window() public {
        Call memory c = deposit(10 ether, 1);
        vm.expectRevert(EmitV2Pool.EscrowOpen.selector);
        pool.refund(c.c[0]);
        vm.warp(block.timestamp + WINDOW + 1);
        vm.expectEmit(address(pool));
        emit EmitV2Pool.EscrowClosed(2, c.c[0]);
        vm.expectEmit(address(pool));
        emit EmitV2Pool.NewCommitment(bytes32(refundOf(c)), 1);
        vm.prank(address(0xA11CE)); // anyone
        pool.refund(c.c[0]);
    }

    /// Opens and closes share one sequence, in emission order.
    function test_escrow_events_share_one_sequence() public {
        Call memory a = deposit(1 ether, 1);
        Call memory b = deposit(1 ether, 2);
        resolveWith(resolution(a.c[0], 1, 0, 0));
        Call memory c = deposit(1 ether, 3);
        MockVerifier(VERIFY).set(resolution(b.c[0], 0, 0x0e7, 0), false);
        vm.expectEmit(address(pool));
        emit EmitV2Pool.EscrowClosed(5, b.c[0]);
        pool.resolve(hex"00");
        assertEq(pool.escrowEventSeq(), 5);
        (, uint64 open) = pool.escrows(uint256(c.c[0]));
        assertTrue(open != 0);
    }

    function test_an_escrowed_c0_cannot_be_escrowed_again() public {
        Call memory c = deposit(1 ether, 1);
        Call memory d = call(1 ether, 0, 0, 2);
        d.c[0] = c.c[0];
        uint256[] memory f = fieldsOf(d);
        MockVerifier(VERIFY).set(f, false);
        vm.expectRevert(EmitV2Pool.EscrowExists.selector);
        pool.transact{value: 1 ether}(d.pipeline, d.root, d.n, d.c, d.vIn, d.vOut, d.fee, d.payout, hex"00");
    }
}
