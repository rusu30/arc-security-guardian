// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Test} from "forge-std/Test.sol";
import {TransactionValidationHook} from "../TransactionValidationHook.sol";
import {SecurityRegistry} from "../SecurityRegistry.sol";
import {SecurityEventEmitter} from "../SecurityEventEmitter.sol";
import {TwoFactorAuthGuard} from "../TwoFactorAuthGuard.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

contract TransactionValidationHookTest is Test {
    // ─── TFA signer key ───────────────────────────
    uint256 internal constant SIGNER_PK = 0xDEADBEEF1;
    address internal tfaSigner;

    // ─── Actors ───────────────────────────────────
    address internal hookDeployer  = makeAddr("hookDeployer");
    address internal guardianAdmin = makeAddr("guardianAdmin");
    address internal pauser        = makeAddr("pauser");
    address internal riskManager   = makeAddr("riskManager");
    address internal alice         = makeAddr("alice");
    address internal bob           = makeAddr("bob");

    // ─── Contracts ────────────────────────────────
    SecurityRegistry          internal registry;
    SecurityEventEmitter      internal emitter;
    TwoFactorAuthGuard        internal tfaGuard;
    TransactionValidationHook internal hook;

    // ─── Default velocity (set in registry) ───────
    // Registry defaults: window=3600, amountLimit=1000_000000, callLimit=100

    function setUp() public {
        tfaSigner = vm.addr(SIGNER_PK);

        // 1. Emitter
        emitter = new SecurityEventEmitter(guardianAdmin);

        // 2. TFA guard
        tfaGuard = new TwoFactorAuthGuard(tfaSigner, 15 minutes, address(emitter));

        // 3. Deploy registry impl + proxy (hookAddr = address(this) for now)
        SecurityRegistry impl = new SecurityRegistry();
        bytes memory initData = abi.encodeWithSelector(
            SecurityRegistry.initialize.selector,
            guardianAdmin,
            pauser,
            riskManager,
            address(this), // temporary hookAddr
            address(emitter),
            address(tfaGuard)
        );
        ERC1967Proxy proxy = new ERC1967Proxy(address(impl), initData);
        registry = SecurityRegistry(address(proxy));

        // 4. Deploy hook (deployer = address(this) via cheat)
        vm.prank(hookDeployer);
        hook = new TransactionValidationHook(address(registry), address(emitter), address(tfaGuard));

        // 5. Grant hook TRANSACTION_HOOK_ROLE in registry.
        //    Use startPrank/stopPrank: reading .TRANSACTION_HOOK_ROLE() is a staticcall
        //    that would consume vm.prank before grantRole executes.
        vm.startPrank(guardianAdmin);
        registry.grantRole(registry.TRANSACTION_HOOK_ROLE(), address(hook));
        vm.stopPrank();

        // 6. Authorize emitter for registry and hook
        vm.prank(guardianAdmin);
        emitter.setAuthorizedCaller(address(registry), true);
        vm.prank(guardianAdmin);
        emitter.setAuthorizedCaller(address(hook), true);
    }

    // ──────────────────────────────────────────────
    // Helpers
    // ──────────────────────────────────────────────

    function _digest(
        address caller,
        address to,
        uint256 amount,
        uint256 nonce,
        uint256 deadline
    ) internal view returns (bytes32) {
        return tfaGuard.buildChallengeHash(caller, to, amount, nonce, deadline);
    }

    function _sign(bytes32 digest) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(SIGNER_PK, digest);
        return abi.encodePacked(r, s, v);
    }

    function _buildSig(
        address caller,
        address to,
        uint256 amount,
        uint256 nonce,
        uint256 lifeSecs
    ) internal view returns (bytes memory sig, uint256 deadline) {
        deadline = block.timestamp + lifeSecs;
        sig = _sign(_digest(caller, to, amount, nonce, deadline));
    }

    function _blockAddress(address addr) internal {
        vm.prank(riskManager);
        registry.setRiskTier(addr, SecurityRegistry.RiskTier.BLOCKED, "blocked");
    }

    // ──────────────────────────────────────────────
    // Construction
    // ──────────────────────────────────────────────

    function test_Constructor_StoresImmutables() public view {
        assertEq(hook.registry(), address(registry));
        assertEq(hook.emitter(), address(emitter));
        assertEq(hook.tfaGuard(), address(tfaGuard));
    }

    function test_Constructor_GrantsRolesToDeployer() public view {
        assertTrue(hook.hasRole(hook.DEFAULT_ADMIN_ROLE(), hookDeployer));
        assertTrue(hook.hasRole(hook.PAUSER_ROLE(), hookDeployer));
    }

    function test_Constructor_ZeroRegistryReverts() public {
        vm.expectRevert(TransactionValidationHook.ZeroAddress.selector);
        new TransactionValidationHook(address(0), address(emitter), address(tfaGuard));
    }

    function test_Constructor_ZeroEmitterReverts() public {
        vm.expectRevert(TransactionValidationHook.ZeroAddress.selector);
        new TransactionValidationHook(address(registry), address(0), address(tfaGuard));
    }

    function test_Constructor_ZeroTfaGuardReverts() public {
        vm.expectRevert(TransactionValidationHook.ZeroAddress.selector);
        new TransactionValidationHook(address(registry), address(emitter), address(0));
    }

    // ──────────────────────────────────────────────
    // validate() — happy path
    // ──────────────────────────────────────────────

    function test_Validate_HappyPath() public {
        vm.prank(alice);
        (bool ok, string memory reason) = hook.validate(alice, bob, 100_000000, "");
        assertTrue(ok);
        assertEq(reason, "");
    }

    function test_Validate_RecordsUsageInRegistry() public {
        vm.warp(1000);
        vm.prank(alice);
        hook.validate(alice, bob, 100_000000, "");

        SecurityRegistry.VelocityState memory st = registry.getVelocityState(alice);
        assertEq(st.amountUsed, 100_000000);
        assertEq(st.callCount, 1);
    }

    // ──────────────────────────────────────────────
    // Critical invariant 1: BLOCKED address always fails validate()
    // ──────────────────────────────────────────────

    function test_Validate_BlockedAddressReturnsFalse() public {
        _blockAddress(alice);

        vm.prank(alice);
        (bool ok, string memory reason) = hook.validate(alice, bob, 100_000000, "");
        assertFalse(ok);
        assertEq(reason, "AddressBlocked");
    }

    // ──────────────────────────────────────────────
    // Critical invariant 4: from != msg.sender MUST revert in validate()
    // ──────────────────────────────────────────────

    function test_Validate_FromNotCallerReverts() public {
        vm.prank(alice);
        vm.expectRevert(bytes("from must be caller"));
        hook.validate(bob, bob, 100_000000, ""); // from = bob, caller = alice
    }

    // ──────────────────────────────────────────────
    // Velocity: validate() returns false when amount exceeds window limit
    // ──────────────────────────────────────────────

    function test_Validate_VelocityAmountExceeded() public {
        // Set a low limit for alice
        vm.prank(riskManager);
        registry.setVelocityConfig(alice, 3600, 200_000000, 100); // 200 USDC limit

        vm.warp(1000);
        vm.prank(alice);
        (bool ok,) = hook.validate(alice, bob, 100_000000, ""); // 100 USDC
        assertTrue(ok);

        vm.prank(alice);
        (bool ok2, string memory reason2) = hook.validate(alice, bob, 110_000000, ""); // would push to 210
        assertFalse(ok2);
        assertEq(reason2, "VelocityAmountExceeded");
    }

    function test_Validate_VelocityCallsExceeded() public {
        // Set call limit of 2
        vm.prank(riskManager);
        registry.setVelocityConfig(alice, 3600, 100_000e6, 2);

        vm.warp(1000);
        vm.prank(alice);
        hook.validate(alice, bob, 1, "");
        vm.prank(alice);
        hook.validate(alice, bob, 1, "");

        vm.prank(alice);
        (bool ok, string memory reason) = hook.validate(alice, bob, 1, "");
        assertFalse(ok);
        assertEq(reason, "VelocityCallsExceeded");
    }

    // ──────────────────────────────────────────────
    // Critical invariant 2: amountUsed in registry never exceeds the window limit
    // after successful validate() calls
    // ──────────────────────────────────────────────

    function test_Validate_AmountUsedNeverExceedsLimitAfterPass() public {
        uint256 limit = 500_000000;
        vm.prank(riskManager);
        registry.setVelocityConfig(alice, 3600, limit, 100);

        vm.warp(1000);

        // Fill to exactly the limit
        vm.prank(alice);
        (bool ok,) = hook.validate(alice, bob, 500_000000, "");
        assertTrue(ok);

        SecurityRegistry.VelocityState memory st = registry.getVelocityState(alice);
        assertLe(st.amountUsed, limit);
    }

    // ──────────────────────────────────────────────
    // validate() — paused system
    // ──────────────────────────────────────────────

    function test_Validate_ReturnsFalseWhenPaused() public {
        vm.prank(hookDeployer);
        hook.pause();

        vm.prank(alice);
        (bool ok, string memory reason) = hook.validate(alice, bob, 1, "");
        assertFalse(ok);
        assertEq(reason, "SystemPaused");
    }

    // ──────────────────────────────────────────────
    // Critical invariant 6: recordUsage failure causes validate to revert
    // (tested by pausing registry so recordUsage reverts)
    // ──────────────────────────────────────────────

    function test_Validate_RecordUsageFailureCausesRevert() public {
        // Pause the registry — recordUsage will revert (whenNotPaused)
        vm.prank(pauser);
        registry.pause();

        // The hook's _validate calls registry.recordUsage which will revert.
        // Since hook does NOT catch that revert, validate() must revert.
        vm.prank(alice);
        vm.expectRevert();
        hook.validate(alice, bob, 100_000000, "");
    }

    // ──────────────────────────────────────────────
    // validateStrict() — CONTRACT BUG: always reverts UnauthorizedCaller
    //
    // validateStrict calls tfaGuard.consumeChallenge(msg.sender=alice, ...)
    // but consumeChallenge checks msg.sender==caller:
    //   inside consumeChallenge, msg.sender = address(hook), caller = alice
    //   → hook != alice → UnauthorizedCaller
    //
    // The design is incompatible: consumeChallenge requires the user to be the
    // DIRECT caller, but validateStrict routes through the hook contract.
    // All tests below document the ACTUAL (buggy) behaviour and are marked accordingly.
    // ──────────────────────────────────────────────

    function test_ValidateStrict_AlwaysRevertsUnauthorizedCaller_ContractBug() public {
        (bytes memory sig, uint256 deadline) = _buildSig(alice, bob, 100_000000, 0, 5 minutes);
        vm.prank(alice);
        // CONTRACT BUG: should succeed, reverts UnauthorizedCaller instead
        vm.expectRevert(TwoFactorAuthGuard.UnauthorizedCaller.selector);
        hook.validateStrict(bob, 100_000000, "", 0, deadline, sig);
    }

    function test_ValidateStrict_BlockedAddress_AlsoRevertsUnauthorizedCaller_ContractBug() public {
        _blockAddress(alice);
        (bytes memory sig, uint256 deadline) = _buildSig(alice, bob, 100_000000, 0, 5 minutes);
        vm.prank(alice);
        // CONTRACT BUG: consumeChallenge check fires before risk-tier check
        vm.expectRevert(TwoFactorAuthGuard.UnauthorizedCaller.selector);
        hook.validateStrict(bob, 100_000000, "", 0, deadline, sig);
    }

    function test_ValidateStrict_InvalidSig_AlsoRevertsUnauthorizedCaller_ContractBug() public {
        uint256 wrongPk = 0x1234567890;
        uint256 deadline = block.timestamp + 5 minutes;
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(wrongPk, _digest(alice, bob, 100_000000, 0, deadline));
        bytes memory badSig = abi.encodePacked(r, s, v);
        vm.prank(alice);
        // CONTRACT BUG: UnauthorizedCaller fires before signature check
        vm.expectRevert(TwoFactorAuthGuard.UnauthorizedCaller.selector);
        hook.validateStrict(bob, 100_000000, "", 0, deadline, badSig);
    }

    // ──────────────────────────────────────────────
    // validateWithTFA() — same CONTRACT BUG as validateStrict
    // ──────────────────────────────────────────────

    function test_ValidateWithTFA_HappyPath_AlsoRevertsUnauthorizedCaller_ContractBug() public {
        (bytes memory sig, uint256 deadline) = _buildSig(alice, bob, 100_000000, 0, 5 minutes);
        vm.prank(alice);
        // CONTRACT BUG: should succeed, reverts UnauthorizedCaller
        vm.expectRevert(TwoFactorAuthGuard.UnauthorizedCaller.selector);
        hook.validateWithTFA(alice, bob, 100_000000, "", 0, deadline, sig);
    }

    function test_ValidateWithTFA_FromNotCallerReverts() public {
        (bytes memory sig, uint256 deadline) = _buildSig(alice, bob, 100_000000, 0, 5 minutes);
        vm.prank(alice);
        vm.expectRevert(bytes("from must be caller"));
        hook.validateWithTFA(bob, bob, 100_000000, "", 0, deadline, sig); // from = bob, caller = alice
    }

    // ──────────────────────────────────────────────
    // TFA replay invariant: documented via direct consumeChallenge calls
    // (invariant cannot be tested through validateStrict due to the contract bug above)
    // ──────────────────────────────────────────────

    function test_TFAReplay_DirectConsumeChallenge_Reverts() public {
        // Sign for alice directly and call consumeChallenge as alice — this works fine
        (bytes memory sig, uint256 deadline) = _buildSig(alice, bob, 100_000000, 0, 5 minutes);

        vm.prank(alice);
        tfaGuard.consumeChallenge(alice, bob, 100_000000, 0, deadline, sig);

        // Replay: nonce is now 1
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(TwoFactorAuthGuard.NonceMismatch.selector, 1, 0));
        tfaGuard.consumeChallenge(alice, bob, 100_000000, 0, deadline, sig);
    }

    // ──────────────────────────────────────────────
    // Pause / Unpause
    // ──────────────────────────────────────────────

    function test_Pause_NonPauserReverts() public {
        vm.prank(alice);
        vm.expectRevert();
        hook.pause();
    }

    function test_Pause_PauserSucceeds() public {
        vm.prank(hookDeployer);
        hook.pause();
        assertTrue(hook.paused());
    }

    function test_Unpause_PauserSucceeds() public {
        vm.prank(hookDeployer);
        hook.pause();
        vm.prank(hookDeployer);
        hook.unpause();
        assertFalse(hook.paused());
    }

    // ──────────────────────────────────────────────
    // Critical invariant 5: consumeChallenge with wrong msg.sender MUST revert
    // Tested directly on the guard (validateStrict is broken due to the contract bug above)
    // ──────────────────────────────────────────────

    function test_ConsumeChallenge_WrongMsgSender_RevertsUnauthorizedCaller() public {
        (bytes memory sig, uint256 deadline) = _buildSig(alice, bob, 100_000000, 0, 5 minutes);

        // bob tries to consume alice's challenge directly
        vm.prank(bob);
        vm.expectRevert(TwoFactorAuthGuard.UnauthorizedCaller.selector);
        tfaGuard.consumeChallenge(alice, bob, 100_000000, 0, deadline, sig);
    }

    // ──────────────────────────────────────────────
    // Fuzz: validate with fuzzy amounts, always respects velocity limit
    // ──────────────────────────────────────────────

    function testFuzz_Validate_BlockedAlwaysFails(address victim) public {
        vm.assume(victim != address(0));
        vm.assume(victim != address(registry)); // avoid self-referential registry calls

        _blockAddress(victim);

        vm.prank(victim);
        (bool ok, string memory reason) = hook.validate(victim, bob, 1, "");
        assertFalse(ok);
        assertEq(reason, "AddressBlocked");
    }

    function testFuzz_Validate_AmountWithinLimitPasses(uint96 rawAmount) public {
        uint256 limit = 1000_000000; // default
        // Pick amount within limit
        uint256 amount = bound(rawAmount, 0, limit);

        vm.warp(1000);
        vm.prank(alice);
        (bool ok,) = hook.validate(alice, bob, amount, "");
        assertTrue(ok);

        SecurityRegistry.VelocityState memory st = registry.getVelocityState(alice);
        assertLe(st.amountUsed, limit);
    }

    function testFuzz_Validate_AmountExceedingLimitFails(uint96 rawAmount) public {
        uint256 limit = 100_000000;
        vm.prank(riskManager);
        registry.setVelocityConfig(alice, 3600, limit, 100);

        // Fill to the limit first
        vm.warp(1000);
        vm.prank(alice);
        hook.validate(alice, bob, limit, "");

        // Now any positive amount must fail
        uint256 extra = bound(rawAmount, 1, 1_000_000e6);

        vm.prank(alice);
        (bool ok, string memory reason) = hook.validate(alice, bob, extra, "");
        assertFalse(ok);
        assertEq(reason, "VelocityAmountExceeded");
    }

    // ──────────────────────────────────────────────
    // Velocity window reset: after window expires,
    // amountUsed is reset and validate passes again
    // ──────────────────────────────────────────────

    function test_Validate_VelocityResetsAfterWindow() public {
        uint256 limit = 100_000000;
        vm.prank(riskManager);
        registry.setVelocityConfig(alice, 3600, limit, 100);

        vm.warp(1000);
        // Fill up
        vm.prank(alice);
        (bool ok,) = hook.validate(alice, bob, limit, "");
        assertTrue(ok);

        // Try to exceed — should fail
        vm.prank(alice);
        (bool ok2,) = hook.validate(alice, bob, 1, "");
        assertFalse(ok2);

        // Advance past window
        vm.warp(1000 + 3600 + 1);

        // Now should pass again
        vm.prank(alice);
        (bool ok3,) = hook.validate(alice, bob, 50_000000, "");
        assertTrue(ok3);
    }
}
