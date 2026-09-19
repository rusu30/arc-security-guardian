// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Test} from "forge-std/Test.sol";
import {SecurityRegistry} from "../SecurityRegistry.sol";
import {SecurityEventEmitter} from "../SecurityEventEmitter.sol";
import {TwoFactorAuthGuard} from "../TwoFactorAuthGuard.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

/// @dev Thin wrapper so the test contract can call recordUsage as TRANSACTION_HOOK_ROLE.
contract RegistryHarness is Test {
    SecurityRegistry public registry;

    constructor(SecurityRegistry _registry) {
        registry = _registry;
    }

    function recordUsage(address addr, uint256 amount) external {
        registry.recordUsage(addr, amount);
    }
}

contract SecurityRegistryTest is Test {
    // ─── Constants ────────────────────────────────
    uint256 internal constant DEFAULT_WINDOW  = 3600;
    uint256 internal constant DEFAULT_LIMIT   = 1000_000000; // 1000 USDC
    uint256 internal constant DEFAULT_CALLS   = 100;

    // ─── Actors ───────────────────────────────────
    address internal guardianAdmin = makeAddr("guardianAdmin");
    address internal pauser        = makeAddr("pauser");
    address internal riskManager   = makeAddr("riskManager");
    address internal alice         = makeAddr("alice");
    address internal bob           = makeAddr("bob");

    // ─── Contracts ────────────────────────────────
    SecurityRegistry     internal registry;
    SecurityEventEmitter internal emitter;
    TwoFactorAuthGuard   internal tfaGuard;

    // The test contract itself will hold TRANSACTION_HOOK_ROLE (hookAddr = address(this))
    // We deploy a harness contract for it.
    RegistryHarness internal hook;

    function setUp() public {
        // 1. Emitter
        emitter = new SecurityEventEmitter(guardianAdmin);

        // 2. TFA guard (signer = guardianAdmin for simplicity — guard used only as address here)
        tfaGuard = new TwoFactorAuthGuard(guardianAdmin, 15 minutes, address(emitter));

        // 3. Deploy SecurityRegistry implementation
        SecurityRegistry impl = new SecurityRegistry();

        // 4. Deploy proxy (ERC1967) pointing to impl
        //    We encode initialize() call data; hookAddr = address(this) is set AFTER proxy is known.
        //    Strategy: deploy proxy with hookAddr = address(this) (the test contract);
        //    then deploy the harness wrapping the proxy.

        bytes memory initData = abi.encodeWithSelector(
            SecurityRegistry.initialize.selector,
            guardianAdmin,
            pauser,
            riskManager,
            address(this), // hookAddr → test contract gets TRANSACTION_HOOK_ROLE
            address(emitter),
            address(tfaGuard)
        );
        ERC1967Proxy proxy = new ERC1967Proxy(address(impl), initData);
        registry = SecurityRegistry(address(proxy));

        // Authorize the emitter to receive calls from registry
        vm.prank(guardianAdmin);
        emitter.setAuthorizedCaller(address(registry), true);

        // Wrap the test-contract's hook role into a callable harness
        hook = new RegistryHarness(registry);

        // Grant TRANSACTION_HOOK_ROLE to the harness (guardianAdmin holds DEFAULT_ADMIN_ROLE).
        // Use startPrank/stopPrank because reading TRANSACTION_HOOK_ROLE() is a separate call
        // that would consume a plain vm.prank before grantRole executes.
        vm.startPrank(guardianAdmin);
        registry.grantRole(registry.TRANSACTION_HOOK_ROLE(), address(hook));
        vm.stopPrank();
    }

    // ──────────────────────────────────────────────
    // Initialize
    // ──────────────────────────────────────────────

    function test_Initialize_RolesAssigned() public view {
        assertTrue(registry.hasRole(registry.DEFAULT_ADMIN_ROLE(), guardianAdmin));
        assertTrue(registry.hasRole(registry.GUARDIAN_ADMIN_ROLE(), guardianAdmin));
        assertTrue(registry.hasRole(registry.PAUSER_ROLE(), pauser));
        assertTrue(registry.hasRole(registry.RISK_MANAGER_ROLE(), riskManager));
        assertTrue(registry.hasRole(registry.TRANSACTION_HOOK_ROLE(), address(this)));
    }

    function test_Initialize_DefaultVelocityConfig() public view {
        (uint256 w, uint256 a, uint256 c) = registry.getEffectiveVelocityConfig(alice);
        assertEq(w, DEFAULT_WINDOW);
        assertEq(a, DEFAULT_LIMIT);
        assertEq(c, DEFAULT_CALLS);
    }

    function test_Initialize_CannotReinitialize() public {
        vm.expectRevert();
        registry.initialize(guardianAdmin, pauser, riskManager, address(this), address(emitter), address(tfaGuard));
    }

    function test_Initialize_ZeroAddressReverts() public {
        SecurityRegistry impl2 = new SecurityRegistry();
        bytes memory badInit = abi.encodeWithSelector(
            SecurityRegistry.initialize.selector,
            address(0), pauser, riskManager, address(this), address(emitter), address(tfaGuard)
        );
        vm.expectRevert();
        new ERC1967Proxy(address(impl2), badInit);
    }

    // ──────────────────────────────────────────────
    // setRiskTier
    // ──────────────────────────────────────────────

    function test_SetRiskTier_HappyPath() public {
        vm.prank(riskManager);
        registry.setRiskTier(alice, SecurityRegistry.RiskTier.CLEAN, "clean");

        SecurityRegistry.RiskRecord memory rec = registry.getRiskRecord(alice);
        assertEq(uint8(rec.tier), uint8(SecurityRegistry.RiskTier.CLEAN));
        assertEq(rec.metadata, "clean");
    }

    function test_SetRiskTier_VerifiedAgentSetsVerifiedAt() public {
        vm.warp(1000);
        vm.prank(riskManager);
        registry.setRiskTier(alice, SecurityRegistry.RiskTier.VERIFIED_AGENT, "vip");

        SecurityRegistry.RiskRecord memory rec = registry.getRiskRecord(alice);
        assertEq(rec.verifiedAt, 1000);
        assertEq(rec.flaggedAt, 0);
    }

    function test_SetRiskTier_BlockedSetsFlaggedAt() public {
        vm.warp(2000);
        vm.prank(riskManager);
        registry.setRiskTier(alice, SecurityRegistry.RiskTier.BLOCKED, "blocked");

        SecurityRegistry.RiskRecord memory rec = registry.getRiskRecord(alice);
        assertEq(rec.flaggedAt, 2000);
    }

    function test_SetRiskTier_WatchSetsFlaggedAt() public {
        vm.warp(3000);
        vm.prank(riskManager);
        registry.setRiskTier(alice, SecurityRegistry.RiskTier.WATCH, "watch");

        SecurityRegistry.RiskRecord memory rec = registry.getRiskRecord(alice);
        assertEq(rec.flaggedAt, 3000);
    }

    function test_SetRiskTier_ZeroAddressReverts() public {
        vm.prank(riskManager);
        vm.expectRevert(SecurityRegistry.ZeroAddress.selector);
        registry.setRiskTier(address(0), SecurityRegistry.RiskTier.CLEAN, "");
    }

    function test_SetRiskTier_NonRiskManagerReverts() public {
        vm.prank(alice);
        vm.expectRevert();
        registry.setRiskTier(bob, SecurityRegistry.RiskTier.CLEAN, "");
    }

    function test_SetRiskTier_RevertsWhenPaused() public {
        vm.prank(pauser);
        registry.pause();

        vm.prank(riskManager);
        vm.expectRevert();
        registry.setRiskTier(alice, SecurityRegistry.RiskTier.CLEAN, "");
    }

    // ──────────────────────────────────────────────
    // batchSetRiskTier
    // ──────────────────────────────────────────────

    function test_BatchSetRiskTier_HappyPath() public {
        address[] memory addrs = new address[](3);
        addrs[0] = alice; addrs[1] = bob; addrs[2] = makeAddr("carol");

        SecurityRegistry.RiskTier[] memory tiers = new SecurityRegistry.RiskTier[](3);
        tiers[0] = SecurityRegistry.RiskTier.CLEAN;
        tiers[1] = SecurityRegistry.RiskTier.WATCH;
        tiers[2] = SecurityRegistry.RiskTier.BLOCKED;

        string[] memory metas = new string[](3);
        metas[0] = "a"; metas[1] = "b"; metas[2] = "c";

        vm.prank(riskManager);
        registry.batchSetRiskTier(addrs, tiers, metas);

        assertEq(uint8(registry.getRiskRecord(alice).tier), uint8(SecurityRegistry.RiskTier.CLEAN));
        assertEq(uint8(registry.getRiskRecord(bob).tier),  uint8(SecurityRegistry.RiskTier.WATCH));
    }

    function test_BatchSetRiskTier_LengthMismatchReverts() public {
        address[] memory addrs = new address[](2);
        addrs[0] = alice; addrs[1] = bob;

        SecurityRegistry.RiskTier[] memory tiers = new SecurityRegistry.RiskTier[](1);
        tiers[0] = SecurityRegistry.RiskTier.CLEAN;

        string[] memory metas = new string[](2);
        metas[0] = "a"; metas[1] = "b";

        vm.prank(riskManager);
        vm.expectRevert(SecurityRegistry.ArrayLengthMismatch.selector);
        registry.batchSetRiskTier(addrs, tiers, metas);
    }

    function test_BatchSetRiskTier_TooLargeReverts() public {
        uint256 n = 201;
        address[] memory addrs = new address[](n);
        SecurityRegistry.RiskTier[] memory tiers = new SecurityRegistry.RiskTier[](n);
        string[] memory metas = new string[](n);
        for (uint256 i = 0; i < n; i++) {
            addrs[i] = address(uint160(i + 1));
            tiers[i] = SecurityRegistry.RiskTier.CLEAN;
            metas[i] = "";
        }

        vm.prank(riskManager);
        vm.expectRevert(abi.encodeWithSelector(SecurityRegistry.BatchTooLarge.selector, 200));
        registry.batchSetRiskTier(addrs, tiers, metas);
    }

    // ──────────────────────────────────────────────
    // setRiskFlag
    // ──────────────────────────────────────────────

    function test_SetRiskFlag_SetsBit() public {
        vm.prank(riskManager);
        registry.setRiskFlag(alice, 3, true);

        SecurityRegistry.RiskRecord memory rec = registry.getRiskRecord(alice);
        bytes32 mask = bytes32(uint256(1) << 3);
        assertTrue(rec.flags & mask != 0);
    }

    function test_SetRiskFlag_ClearsBit() public {
        vm.prank(riskManager);
        registry.setRiskFlag(alice, 3, true);

        vm.prank(riskManager);
        registry.setRiskFlag(alice, 3, false);

        SecurityRegistry.RiskRecord memory rec = registry.getRiskRecord(alice);
        bytes32 mask = bytes32(uint256(1) << 3);
        assertEq(rec.flags & mask, bytes32(0));
    }

    function test_SetRiskFlag_ZeroAddressReverts() public {
        vm.prank(riskManager);
        vm.expectRevert(SecurityRegistry.ZeroAddress.selector);
        registry.setRiskFlag(address(0), 0, true);
    }

    function test_SetRiskFlag_NonRiskManagerReverts() public {
        vm.prank(alice);
        vm.expectRevert();
        registry.setRiskFlag(bob, 0, true);
    }

    // ──────────────────────────────────────────────
    // setVelocityConfig
    // ──────────────────────────────────────────────

    function test_SetVelocityConfig_HappyPath() public {
        vm.prank(riskManager);
        registry.setVelocityConfig(alice, 7200, 500_000000, 50);

        SecurityRegistry.VelocityConfig memory cfg = registry.getVelocityConfig(alice);
        assertEq(cfg.windowSeconds, 7200);
        assertEq(cfg.amountLimitUsdc, 500_000000);
        assertEq(cfg.callLimit, 50);
    }

    function test_SetVelocityConfig_ZeroWindowReverts() public {
        vm.prank(riskManager);
        vm.expectRevert(SecurityRegistry.ZeroWindowSeconds.selector);
        registry.setVelocityConfig(alice, 0, 500_000000, 50);
    }

    function test_SetVelocityConfig_ZeroAddressReverts() public {
        vm.prank(riskManager);
        vm.expectRevert(SecurityRegistry.ZeroAddress.selector);
        registry.setVelocityConfig(address(0), 3600, 500_000000, 50);
    }

    function test_SetVelocityConfig_NonRiskManagerReverts() public {
        vm.prank(alice);
        vm.expectRevert();
        registry.setVelocityConfig(bob, 3600, 100_000000, 10);
    }

    // ──────────────────────────────────────────────
    // recordUsage
    // ──────────────────────────────────────────────

    function test_RecordUsage_FirstCallStartsWindow() public {
        vm.warp(1000);
        hook.recordUsage(alice, 100_000000);

        SecurityRegistry.VelocityState memory st = registry.getVelocityState(alice);
        assertEq(st.windowStart, 1000);
        assertEq(st.amountUsed, 100_000000);
        assertEq(st.callCount, 1);
    }

    function test_RecordUsage_AccumulatesWithinWindow() public {
        vm.warp(1000);
        hook.recordUsage(alice, 100_000000);
        hook.recordUsage(alice, 200_000000);

        SecurityRegistry.VelocityState memory st = registry.getVelocityState(alice);
        assertEq(st.amountUsed, 300_000000);
        assertEq(st.callCount, 2);
        assertEq(st.windowStart, 1000); // same window
    }

    function test_RecordUsage_ResetsAfterWindowExpiry() public {
        vm.warp(1000);
        hook.recordUsage(alice, 100_000000);

        // Advance past default 3600-second window
        vm.warp(1000 + 3600 + 1);
        hook.recordUsage(alice, 50_000000);

        SecurityRegistry.VelocityState memory st = registry.getVelocityState(alice);
        assertEq(st.amountUsed, 50_000000);
        assertEq(st.callCount, 1);
        assertEq(st.windowStart, 1000 + 3600 + 1);
    }

    function test_RecordUsage_ZeroAddressReverts() public {
        vm.expectRevert(SecurityRegistry.ZeroAddress.selector);
        registry.recordUsage(address(0), 100);
    }

    function test_RecordUsage_NonHookReverts() public {
        vm.prank(alice);
        vm.expectRevert();
        registry.recordUsage(bob, 100);
    }

    function test_RecordUsage_RevertsWhenPaused() public {
        vm.prank(pauser);
        registry.pause();

        vm.expectRevert();
        registry.recordUsage(alice, 100);
    }

    // ──────────────────────────────────────────────
    // Pause / Unpause
    // ──────────────────────────────────────────────

    function test_Pause_NonPauserReverts() public {
        vm.prank(alice);
        vm.expectRevert();
        registry.pause();
    }

    function test_Pause_PauserSucceeds() public {
        vm.prank(pauser);
        registry.pause();
        assertTrue(registry.paused());
    }

    function test_Unpause_PauserSucceeds() public {
        vm.prank(pauser);
        registry.pause();
        vm.prank(pauser);
        registry.unpause();
        assertFalse(registry.paused());
    }

    // ──────────────────────────────────────────────
    // setEventEmitter
    // ──────────────────────────────────────────────

    function test_SetEventEmitter_HappyPath() public {
        address newEmitter = makeAddr("newEmitter");
        vm.prank(guardianAdmin);
        registry.setEventEmitter(newEmitter);
        // No getter exposed — confirm no revert and re-set back
        vm.prank(guardianAdmin);
        registry.setEventEmitter(address(emitter)); // restore
    }

    function test_SetEventEmitter_ZeroReverts() public {
        vm.prank(guardianAdmin);
        vm.expectRevert(SecurityRegistry.ZeroAddress.selector);
        registry.setEventEmitter(address(0));
    }

    function test_SetEventEmitter_NonAdminReverts() public {
        vm.prank(alice);
        vm.expectRevert();
        registry.setEventEmitter(makeAddr("x"));
    }

    // ──────────────────────────────────────────────
    // getEffectiveVelocityConfig — default fallback
    // ──────────────────────────────────────────────

    function test_EffectiveVelocityConfig_DefaultsWhenNotSet() public {
        address nobody = makeAddr("nobody");
        (uint256 w, uint256 a, uint256 c) = registry.getEffectiveVelocityConfig(nobody);
        assertEq(w, DEFAULT_WINDOW);
        assertEq(a, DEFAULT_LIMIT);
        assertEq(c, DEFAULT_CALLS);
    }

    function test_EffectiveVelocityConfig_CustomOverridesDefault() public {
        vm.prank(riskManager);
        registry.setVelocityConfig(alice, 7200, 500_000000, 10);

        (uint256 w, uint256 a, uint256 c) = registry.getEffectiveVelocityConfig(alice);
        assertEq(w, 7200);
        assertEq(a, 500_000000);
        assertEq(c, 10);
    }

    // ──────────────────────────────────────────────
    // Fuzz: velocity accumulation within window never overflows the limit accounting
    // ──────────────────────────────────────────────

    function testFuzz_RecordUsage_AmountAccumulates(uint96 a1, uint96 a2) public {
        // Bound to reasonable USDC-range amounts
        uint256 amount1 = bound(a1, 0, 500_000000);
        uint256 amount2 = bound(a2, 0, 500_000000);

        vm.warp(1000);
        hook.recordUsage(alice, amount1);
        hook.recordUsage(alice, amount2);

        SecurityRegistry.VelocityState memory st = registry.getVelocityState(alice);
        // amountUsed == sum (no window reset happened)
        assertEq(st.amountUsed, amount1 + amount2);
        assertEq(st.callCount, 2);
    }

    function testFuzz_RecordUsage_WindowResetOnExpiry(uint32 extra) public {
        // warp by at least 1 sec past window
        uint256 advance = bound(extra, 1, 7200);

        vm.warp(1000);
        hook.recordUsage(alice, 100_000000);

        vm.warp(1000 + DEFAULT_WINDOW + advance);
        hook.recordUsage(alice, 50_000000);

        SecurityRegistry.VelocityState memory st = registry.getVelocityState(alice);
        // New window → amountUsed should be only the second call's amount
        assertEq(st.amountUsed, 50_000000);
        assertEq(st.callCount, 1);
    }

    // ──────────────────────────────────────────────
    // Invariant: amountUsed within current window ≤ running sum of recorded amounts
    // ──────────────────────────────────────────────

    // (Tested through the fuzz above; a stateful invariant handler follows)
}

/// @dev Stateful invariant handler for SecurityRegistry velocity accounting.
///      Tracks the "expected" amountUsed in parallel with the registry so we can
///      assert the registry's running total always equals ours.
contract RegistryInvariantHandler is Test {
    SecurityRegistry public registry;
    address public subject;

    // Shadow-state: mirror exactly what the registry does for the current window.
    uint256 public expectedAmountUsed;
    uint256 public expectedWindowStart;
    uint256 public expectedCallCount;

    uint256 internal constant WINDOW = 3600;

    constructor(SecurityRegistry _registry) {
        registry = _registry;
        subject = makeAddr("invSubject");
        vm.warp(1);
    }

    function recordAmount(uint96 rawAmount) external {
        uint256 amount = bound(rawAmount, 0, 500_000000);

        // Mirror the registry's window-reset logic
        if (expectedWindowStart == 0 || expectedWindowStart + WINDOW <= block.timestamp) {
            expectedWindowStart = block.timestamp;
            expectedAmountUsed = amount;
            expectedCallCount = 1;
        } else {
            expectedAmountUsed += amount;
            expectedCallCount += 1;
        }

        registry.recordUsage(subject, amount);
    }

    function advanceTime(uint32 secs) external {
        vm.warp(block.timestamp + bound(secs, 1, 3700));
    }
}

contract SecurityRegistryInvariantTest is Test {
    SecurityRegistry          internal registry;
    SecurityEventEmitter      internal emitter;
    TwoFactorAuthGuard        internal tfaGuard;
    RegistryInvariantHandler  internal handler;

    address internal guardianAdmin = makeAddr("invGuardianAdmin");
    address internal pauser        = makeAddr("invPauser");
    address internal riskManager   = makeAddr("invRiskManager");

    function setUp() public {
        emitter  = new SecurityEventEmitter(guardianAdmin);
        tfaGuard = new TwoFactorAuthGuard(guardianAdmin, 15 minutes, address(emitter));

        SecurityRegistry impl = new SecurityRegistry();
        handler = new RegistryInvariantHandler(SecurityRegistry(address(0))); // placeholder

        // Deploy proxy; hookAddr = handler (will be set after)
        bytes memory initData = abi.encodeWithSelector(
            SecurityRegistry.initialize.selector,
            guardianAdmin,
            pauser,
            riskManager,
            address(this), // hook = test contract; we'll grant to handler
            address(emitter),
            address(tfaGuard)
        );
        ERC1967Proxy proxy = new ERC1967Proxy(address(impl), initData);
        registry = SecurityRegistry(address(proxy));

        vm.prank(guardianAdmin);
        emitter.setAuthorizedCaller(address(registry), true);

        // Re-create handler with real registry
        handler = new RegistryInvariantHandler(registry);

        // Grant handler TRANSACTION_HOOK_ROLE
        vm.startPrank(guardianAdmin);
        registry.grantRole(registry.TRANSACTION_HOOK_ROLE(), address(handler));
        vm.stopPrank();

        // Target only the handler
        targetContract(address(handler));
    }

    /// @dev The registry's amountUsed must always equal the handler's parallel shadow tally.
    function invariant_AmountUsedMatchesShadow() public view {
        SecurityRegistry.VelocityState memory st = registry.getVelocityState(handler.subject());
        // If handler has not yet recorded anything, nothing to assert
        if (handler.expectedWindowStart() == 0) return;

        assertEq(st.amountUsed, handler.expectedAmountUsed(), "amountUsed mismatch");
        assertEq(st.callCount, handler.expectedCallCount(), "callCount mismatch");
        assertEq(st.windowStart, handler.expectedWindowStart(), "windowStart mismatch");
    }
}
