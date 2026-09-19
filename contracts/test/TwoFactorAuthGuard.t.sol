// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Test} from "forge-std/Test.sol";
import {TwoFactorAuthGuard} from "../TwoFactorAuthGuard.sol";
import {SecurityEventEmitter} from "../SecurityEventEmitter.sol";

contract TwoFactorAuthGuardTest is Test {
    // ─── Constants ────────────────────────────────
    uint256 internal constant MAX_LIFETIME = 15 minutes;

    // ─── Actors ───────────────────────────────────
    uint256 internal signerPk;
    address internal tfaSigner;
    address internal alice;
    address internal bob = makeAddr("bob");

    // ─── Contracts ────────────────────────────────
    SecurityEventEmitter internal emitter;
    TwoFactorAuthGuard    internal guard;

    // ─── EIP-712 domain components ────────────────
    bytes32 internal constant TFA_TYPEHASH =
        keccak256("TFAChallenge(address caller,address to,uint256 amount,uint256 nonce,uint256 deadline)");

    function setUp() public {
        // Create a deterministic private key / address for the signer
        signerPk = 0xA11CE;
        tfaSigner = vm.addr(signerPk);
        alice = makeAddr("alice");

        // Deploy emitter with alice as owner (we don't need authorised emitter for guard tests)
        emitter = new SecurityEventEmitter(alice);

        // Deploy the guard
        guard = new TwoFactorAuthGuard(tfaSigner, MAX_LIFETIME, address(emitter));
    }

    // ──────────────────────────────────────────────
    // Helpers
    // ──────────────────────────────────────────────

    /// @dev Builds the EIP-712 digest using the guard's own buildChallengeHash view.
    function _digest(
        address caller,
        address to,
        uint256 amount,
        uint256 nonce,
        uint256 deadline
    ) internal view returns (bytes32) {
        return guard.buildChallengeHash(caller, to, amount, nonce, deadline);
    }

    /// @dev Signs a digest with signerPk, returns packed (r,s,v).
    function _sign(bytes32 digest) internal view returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerPk, digest);
        return abi.encodePacked(r, s, v);
    }

    /// @dev Builds a valid challenge, signs it, and returns the sig + deadline.
    function _buildSig(
        address caller,
        address to,
        uint256 amount,
        uint256 nonce,
        uint256 lifetimeSecs
    ) internal view returns (bytes memory sig, uint256 deadline) {
        deadline = block.timestamp + lifetimeSecs;
        bytes32 digest = _digest(caller, to, amount, nonce, deadline);
        sig = _sign(digest);
    }

    // ──────────────────────────────────────────────
    // Construction
    // ──────────────────────────────────────────────

    function test_Constructor_StoresImmutables() public view {
        assertEq(guard.tfaSigner(), tfaSigner);
        assertEq(guard.maxChallengeLifetime(), MAX_LIFETIME);
        assertEq(guard.eventEmitter(), address(emitter));
    }

    function test_Constructor_ZeroSignerReverts() public {
        vm.expectRevert(TwoFactorAuthGuard.ZeroAddress.selector);
        new TwoFactorAuthGuard(address(0), MAX_LIFETIME, address(emitter));
    }

    function test_Constructor_ZeroEmitterReverts() public {
        vm.expectRevert(TwoFactorAuthGuard.ZeroAddress.selector);
        new TwoFactorAuthGuard(tfaSigner, MAX_LIFETIME, address(0));
    }

    function test_Constructor_InitialNonce() public view {
        assertEq(guard.currentNonce(alice), 0);
    }

    // ──────────────────────────────────────────────
    // consumeChallenge — happy path
    // ──────────────────────────────────────────────

    function test_ConsumeChallenge_HappyPath() public {
        (bytes memory sig, uint256 deadline) = _buildSig(alice, bob, 100e6, 0, 5 minutes);

        vm.prank(alice);
        guard.consumeChallenge(alice, bob, 100e6, 0, deadline, sig);

        // nonce incremented
        assertEq(guard.currentNonce(alice), 1);
    }

    function test_ConsumeChallenge_EmitsChallengeConsumedEvent() public {
        uint256 deadline = block.timestamp + 5 minutes;
        bytes memory sig = _sign(_digest(alice, bob, 200e6, 0, deadline));

        vm.prank(alice);
        vm.expectEmit(true, true, false, true, address(guard));
        emit TwoFactorAuthGuard.ChallengeConsumed(alice, bob, 200e6, 0, deadline);
        guard.consumeChallenge(alice, bob, 200e6, 0, deadline, sig);
    }

    function test_ConsumeChallenge_IncrementNonceOnEachCall() public {
        for (uint256 i = 0; i < 3; i++) {
            (bytes memory sig, uint256 deadline) = _buildSig(alice, bob, 10e6, i, 5 minutes);
            vm.prank(alice);
            guard.consumeChallenge(alice, bob, 10e6, i, deadline, sig);
            assertEq(guard.currentNonce(alice), i + 1);
        }
    }

    function test_ConsumeChallenge_MarksHashUsed() public {
        (bytes memory sig, uint256 deadline) = _buildSig(alice, bob, 50e6, 0, 5 minutes);
        bytes32 h = keccak256(abi.encode(alice, bob, 50e6, uint256(0), deadline));

        assertFalse(guard.usedChallenges(h));

        vm.prank(alice);
        guard.consumeChallenge(alice, bob, 50e6, 0, deadline, sig);

        assertTrue(guard.usedChallenges(h));
    }

    // ──────────────────────────────────────────────
    // Critical invariant: same challenge cannot be replayed
    // ──────────────────────────────────────────────

    function test_ConsumeChallenge_ReplayReverts() public {
        (bytes memory sig, uint256 deadline) = _buildSig(alice, bob, 50e6, 0, 5 minutes);

        vm.prank(alice);
        guard.consumeChallenge(alice, bob, 50e6, 0, deadline, sig);

        // Nonce is now 1, so same nonce 0 reverts with NonceMismatch first
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(TwoFactorAuthGuard.NonceMismatch.selector, 1, 0));
        guard.consumeChallenge(alice, bob, 50e6, 0, deadline, sig);
    }

    /// @dev Even if an attacker forges a nonce match (e.g. a second challenge with same hash),
    ///      usedChallenges blocks it. We simulate this by resetting storage nonce via cheat.
    function test_ConsumeChallenge_UsedHashBlocksReplay() public {
        (bytes memory sig, uint256 deadline) = _buildSig(alice, bob, 50e6, 0, 5 minutes);

        vm.prank(alice);
        guard.consumeChallenge(alice, bob, 50e6, 0, deadline, sig);

        // Manually roll nonce back to 0 to bypass NonceMismatch (simulating hash-collision scenario).
        // forge inspect shows: nonces mapping is at storage slot 2 (EIP712 occupies slots 0-1).
        // Slot for nonces[alice] = keccak256(abi.encode(alice, 2))
        bytes32 slot = keccak256(abi.encode(alice, uint256(2)));
        vm.store(address(guard), slot, bytes32(0));

        vm.prank(alice);
        vm.expectRevert(TwoFactorAuthGuard.ChallengeAlreadyUsed.selector);
        guard.consumeChallenge(alice, bob, 50e6, 0, deadline, sig);
    }

    // ──────────────────────────────────────────────
    // Critical invariant: msg.sender must equal caller
    // ──────────────────────────────────────────────

    function test_ConsumeChallenge_WrongMsgSenderReverts() public {
        (bytes memory sig, uint256 deadline) = _buildSig(alice, bob, 50e6, 0, 5 minutes);

        // bob tries to consume alice's challenge
        vm.prank(bob);
        vm.expectRevert(TwoFactorAuthGuard.UnauthorizedCaller.selector);
        guard.consumeChallenge(alice, bob, 50e6, 0, deadline, sig);
    }

    // ──────────────────────────────────────────────
    // Deadline checks
    // ──────────────────────────────────────────────

    function test_ConsumeChallenge_ExpiredDeadlineReverts() public {
        uint256 deadline = block.timestamp + 5 minutes;
        bytes memory sig = _sign(_digest(alice, bob, 100e6, 0, deadline));

        // warp past deadline
        vm.warp(deadline + 1);

        vm.prank(alice);
        vm.expectRevert(TwoFactorAuthGuard.ChallengeExpired.selector);
        guard.consumeChallenge(alice, bob, 100e6, 0, deadline, sig);
    }

    function test_ConsumeChallenge_TooLongDeadlineReverts() public {
        // deadline - block.timestamp > maxChallengeLifetime
        uint256 deadline = block.timestamp + MAX_LIFETIME + 1;
        bytes memory sig = _sign(_digest(alice, bob, 100e6, 0, deadline));

        vm.prank(alice);
        vm.expectRevert(TwoFactorAuthGuard.ChallengeTooLong.selector);
        guard.consumeChallenge(alice, bob, 100e6, 0, deadline, sig);
    }

    function test_ConsumeChallenge_ExactlyAtMaxLifetime_Passes() public {
        uint256 deadline = block.timestamp + MAX_LIFETIME;
        bytes memory sig = _sign(_digest(alice, bob, 100e6, 0, deadline));

        vm.prank(alice);
        guard.consumeChallenge(alice, bob, 100e6, 0, deadline, sig);
        assertEq(guard.currentNonce(alice), 1);
    }

    // ──────────────────────────────────────────────
    // Nonce mismatch
    // ──────────────────────────────────────────────

    function test_ConsumeChallenge_WrongNonceReverts() public {
        (bytes memory sig, uint256 deadline) = _buildSig(alice, bob, 50e6, 5 /* wrong */, 5 minutes);

        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(TwoFactorAuthGuard.NonceMismatch.selector, 0, 5));
        guard.consumeChallenge(alice, bob, 50e6, 5, deadline, sig);
    }

    // ──────────────────────────────────────────────
    // Signature checks
    // ──────────────────────────────────────────────

    function test_ConsumeChallenge_BadSignatureReverts() public {
        uint256 deadline = block.timestamp + 5 minutes;
        // Sign with a wrong key
        uint256 wrongPk = 0xBAD5EED;
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(wrongPk, _digest(alice, bob, 100e6, 0, deadline));
        bytes memory badSig = abi.encodePacked(r, s, v);

        vm.prank(alice);
        vm.expectRevert(TwoFactorAuthGuard.InvalidTFASignature.selector);
        guard.consumeChallenge(alice, bob, 100e6, 0, deadline, badSig);
    }

    function test_ConsumeChallenge_TamperedAmountReverts() public {
        uint256 deadline = block.timestamp + 5 minutes;
        // Sign for 100e6 but call with 200e6
        bytes memory sig = _sign(_digest(alice, bob, 100e6, 0, deadline));

        vm.prank(alice);
        vm.expectRevert(TwoFactorAuthGuard.InvalidTFASignature.selector);
        guard.consumeChallenge(alice, bob, 200e6, 0, deadline, sig);
    }

    function test_ConsumeChallenge_TamperedToReverts() public {
        uint256 deadline = block.timestamp + 5 minutes;
        bytes memory sig = _sign(_digest(alice, bob, 100e6, 0, deadline));

        address eve = makeAddr("eve");
        vm.prank(alice);
        vm.expectRevert(TwoFactorAuthGuard.InvalidTFASignature.selector);
        guard.consumeChallenge(alice, eve, 100e6, 0, deadline, sig);
    }

    // ──────────────────────────────────────────────
    // buildChallengeHash view
    // ──────────────────────────────────────────────

    function test_BuildChallengeHash_ReturnsNonZero() public view {
        bytes32 h = guard.buildChallengeHash(alice, bob, 100e6, 0, block.timestamp + 60);
        assertTrue(h != bytes32(0));
    }

    // ──────────────────────────────────────────────
    // Fuzz: valid signed challenges always pass within lifetime window
    // ──────────────────────────────────────────────

    function testFuzz_ConsumeChallenge_ValidSignAlwaysPasses(
        uint256 amount,
        uint32 lifeSeconds
    ) public {
        // Bound lifetime to [1, MAX_LIFETIME]
        lifeSeconds = uint32(bound(lifeSeconds, 1, MAX_LIFETIME));
        // Bound amount to something reasonable
        amount = bound(amount, 0, 1_000_000e6);

        uint256 deadline = block.timestamp + lifeSeconds;
        bytes memory sig = _sign(_digest(alice, bob, amount, 0, deadline));

        vm.prank(alice);
        guard.consumeChallenge(alice, bob, amount, 0, deadline, sig);
        assertEq(guard.currentNonce(alice), 1);
    }

    function testFuzz_ConsumeChallenge_WrongCallerAlwaysReverts(address attacker) public {
        vm.assume(attacker != alice);

        (bytes memory sig, uint256 deadline) = _buildSig(alice, bob, 50e6, 0, 5 minutes);

        vm.prank(attacker);
        vm.expectRevert(TwoFactorAuthGuard.UnauthorizedCaller.selector);
        guard.consumeChallenge(alice, bob, 50e6, 0, deadline, sig);
    }
}
