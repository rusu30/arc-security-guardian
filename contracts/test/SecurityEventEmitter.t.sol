// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Test} from "forge-std/Test.sol";
import {SecurityEventEmitter} from "../SecurityEventEmitter.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";

contract SecurityEventEmitterTest is Test {
    SecurityEventEmitter internal emitter;

    address internal owner = makeAddr("owner");
    address internal caller = makeAddr("caller");
    address internal alice  = makeAddr("alice");
    address internal bob    = makeAddr("bob");

    function setUp() public {
        emitter = new SecurityEventEmitter(owner);
    }

    // ──────────────────────────────────────────────
    // Construction
    // ──────────────────────────────────────────────

    function test_Constructor_SetsOwner() public view {
        assertEq(emitter.owner(), owner);
    }

    function test_Constructor_ZeroOwnerReverts() public {
        // OZ Ownable(address(0)) fires OwnableInvalidOwner before our ZeroAddress check —
        // this is a suspected contract bug (unreachable ZeroAddress guard); we test the actual revert.
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableInvalidOwner.selector, address(0)));
        new SecurityEventEmitter(address(0));
    }

    function test_Constructor_NoCallerAuthorized() public view {
        assertFalse(emitter.authorizedCallers(owner));
        assertFalse(emitter.authorizedCallers(caller));
    }

    // ──────────────────────────────────────────────
    // setAuthorizedCaller
    // ──────────────────────────────────────────────

    function test_SetAuthorizedCaller_AuthorizesAddress() public {
        vm.prank(owner);
        emitter.setAuthorizedCaller(caller, true);
        assertTrue(emitter.authorizedCallers(caller));
    }

    function test_SetAuthorizedCaller_RevokesAddress() public {
        vm.prank(owner);
        emitter.setAuthorizedCaller(caller, true);

        vm.prank(owner);
        emitter.setAuthorizedCaller(caller, false);
        assertFalse(emitter.authorizedCallers(caller));
    }

    function test_SetAuthorizedCaller_EmitsEvent() public {
        vm.prank(owner);
        vm.expectEmit(true, false, false, true, address(emitter));
        emit SecurityEventEmitter.AuthorizedCallerSet(caller, true);
        emitter.setAuthorizedCaller(caller, true);
    }

    function test_SetAuthorizedCaller_NonOwnerReverts() public {
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, alice));
        emitter.setAuthorizedCaller(caller, true);
    }

    function test_SetAuthorizedCaller_ZeroAddressReverts() public {
        vm.prank(owner);
        vm.expectRevert(SecurityEventEmitter.ZeroAddress.selector);
        emitter.setAuthorizedCaller(address(0), true);
    }

    // ──────────────────────────────────────────────
    // onlyAuthorized guard — all emit functions
    // ──────────────────────────────────────────────

    function test_EmitSecurityValidation_UnauthorizedReverts() public {
        vm.prank(alice);
        vm.expectRevert(SecurityEventEmitter.UnauthorizedEmitter.selector);
        emitter.emitSecurityValidation(alice, bob, 100, true, "ok");
    }

    function test_EmitRiskTierChanged_UnauthorizedReverts() public {
        vm.prank(alice);
        vm.expectRevert(SecurityEventEmitter.UnauthorizedEmitter.selector);
        emitter.emitRiskTierChanged(alice, 0, 1, owner);
    }

    function test_EmitRiskFlagChanged_UnauthorizedReverts() public {
        vm.prank(alice);
        vm.expectRevert(SecurityEventEmitter.UnauthorizedEmitter.selector);
        emitter.emitRiskFlagChanged(alice, 3, true, owner);
    }

    function test_EmitVelocityBreach_UnauthorizedReverts() public {
        vm.prank(alice);
        vm.expectRevert(SecurityEventEmitter.UnauthorizedEmitter.selector);
        emitter.emitVelocityBreach(alice, 0, 1000, 500);
    }

    function test_EmitEmergencyPause_UnauthorizedReverts() public {
        vm.prank(alice);
        vm.expectRevert(SecurityEventEmitter.UnauthorizedEmitter.selector);
        emitter.emitEmergencyPause(alice, bob, "test");
    }

    function test_EmitTFAChallengeConsumed_UnauthorizedReverts() public {
        vm.prank(alice);
        vm.expectRevert(SecurityEventEmitter.UnauthorizedEmitter.selector);
        emitter.emitTFAChallengeConsumed(alice, bob, 100, 0);
    }

    // ──────────────────────────────────────────────
    // Happy-path event emissions
    // ──────────────────────────────────────────────

    function _authorize(address c) internal {
        vm.prank(owner);
        emitter.setAuthorizedCaller(c, true);
    }

    function test_EmitSecurityValidation_EmitsEvent() public {
        _authorize(caller);
        vm.prank(caller);
        vm.expectEmit(true, true, false, true, address(emitter));
        emit SecurityEventEmitter.SecurityValidation(alice, bob, 500e6, true, "ok");
        emitter.emitSecurityValidation(alice, bob, 500e6, true, "ok");
    }

    function test_EmitRiskTierChanged_EmitsEvent() public {
        _authorize(caller);
        vm.prank(caller);
        vm.expectEmit(true, false, false, true, address(emitter));
        emit SecurityEventEmitter.RiskTierChanged(alice, 0, 3, owner);
        emitter.emitRiskTierChanged(alice, 0, 3, owner);
    }

    function test_EmitRiskFlagChanged_EmitsEvent() public {
        _authorize(caller);
        vm.prank(caller);
        vm.expectEmit(true, false, false, true, address(emitter));
        emit SecurityEventEmitter.RiskFlagChanged(alice, 7, true, owner);
        emitter.emitRiskFlagChanged(alice, 7, true, owner);
    }

    function test_EmitVelocityBreach_EmitsEvent() public {
        _authorize(caller);
        vm.prank(caller);
        vm.expectEmit(true, false, false, false, address(emitter));
        emit SecurityEventEmitter.VelocityBreach(alice, 1000, 2000e6, 1000e6);
        emitter.emitVelocityBreach(alice, 1000, 2000e6, 1000e6);
    }

    function test_EmitEmergencyPause_EmitsEvent() public {
        _authorize(caller);
        vm.prank(caller);
        vm.expectEmit(true, true, false, true, address(emitter));
        emit SecurityEventEmitter.EmergencyPause(caller, bob, "fire drill");
        emitter.emitEmergencyPause(caller, bob, "fire drill");
    }

    function test_EmitTFAChallengeConsumed_EmitsEvent() public {
        _authorize(caller);
        vm.prank(caller);
        vm.expectEmit(true, true, false, true, address(emitter));
        emit SecurityEventEmitter.TFAChallengeConsumed(alice, bob, 100e6, 7);
        emitter.emitTFAChallengeConsumed(alice, bob, 100e6, 7);
    }

    // ──────────────────────────────────────────────
    // Fuzz: authorization is binary — arbitrary callers stay unauthorized until set
    // ──────────────────────────────────────────────

    function testFuzz_UnauthorizedCallerAlwaysReverts(address rando) public {
        vm.assume(rando != owner);
        // Make sure rando is not authorized
        assertFalse(emitter.authorizedCallers(rando));

        vm.prank(rando);
        vm.expectRevert(SecurityEventEmitter.UnauthorizedEmitter.selector);
        emitter.emitSecurityValidation(rando, bob, 1, true, "");
    }

    function testFuzz_AuthorizeAndEmit(address c, uint256 amount, bool ok) public {
        vm.assume(c != address(0));
        vm.assume(c != owner); // avoid owner confusion

        _authorize(c);

        vm.prank(c);
        // just shouldn't revert
        emitter.emitSecurityValidation(alice, bob, amount, ok, "fuzz");
    }
}
