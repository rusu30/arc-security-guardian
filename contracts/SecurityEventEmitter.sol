// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";

/// @title SecurityEventEmitter
/// @notice Immutable event bus for Arc Security Guardian components.
/// @dev Only authorized callers can emit events; owner manages caller authorization.
contract SecurityEventEmitter is Ownable {
    error UnauthorizedEmitter();
    error ZeroAddress();

    /// @notice Tracks contracts/accounts authorized to emit security events.
    mapping(address => bool) public authorizedCallers;

    event AuthorizedCallerSet(address indexed caller, bool authorized);
    event SecurityValidation(
        address indexed from,
        address indexed to,
        uint256 amount,
        bool ok,
        string reason
    );
    event RiskTierChanged(
        address indexed subject,
        uint8 oldTier,
        uint8 newTier,
        address indexed operator
    );
    event RiskFlagChanged(
        address indexed subject,
        uint8 flagBit,
        bool value,
        address indexed operator
    );
    event VelocityBreach(
        address indexed subject,
        uint256 windowStart,
        uint256 amountUsed,
        uint256 limit
    );
    event EmergencyPause(address indexed operator, address indexed target, string reason);
    event TFAChallengeConsumed(
        address indexed caller,
        address indexed to,
        uint256 amount,
        uint256 nonce
    );

    modifier onlyAuthorized() {
        if (!authorizedCallers[msg.sender]) revert UnauthorizedEmitter();
        _;
    }

    /// @notice Deploys the event emitter and sets the initial owner.
    /// @param initialOwner Owner allowed to manage authorized callers.
    constructor(address initialOwner) Ownable(initialOwner) {}

    /// @notice Adds or removes an authorized event-emitting caller.
    /// @param caller Address to update.
    /// @param authorized Whether the caller is authorized.
    function setAuthorizedCaller(address caller, bool authorized) external onlyOwner {
        if (caller == address(0)) revert ZeroAddress();
        authorizedCallers[caller] = authorized;
        emit AuthorizedCallerSet(caller, authorized);
    }

    /// @notice Emits the security validation result for a transaction attempt.
    function emitSecurityValidation(
        address from,
        address to,
        uint256 amount,
        bool ok,
        string calldata reason
    ) external onlyAuthorized {
        emit SecurityValidation(from, to, amount, ok, reason);
    }

    /// @notice Emits a risk-tier change for a subject.
    function emitRiskTierChanged(
        address subject,
        uint8 oldTier,
        uint8 newTier,
        address operator
    ) external onlyAuthorized {
        emit RiskTierChanged(subject, oldTier, newTier, operator);
    }

    /// @notice Emits a risk-flag bit toggle for a subject.
    function emitRiskFlagChanged(
        address subject,
        uint8 flagBit,
        bool value,
        address operator
    ) external onlyAuthorized {
        emit RiskFlagChanged(subject, flagBit, value, operator);
    }

    /// @notice Emits a velocity-limit breach signal.
    function emitVelocityBreach(
        address subject,
        uint256 windowStart,
        uint256 amountUsed,
        uint256 limit
    ) external onlyAuthorized {
        emit VelocityBreach(subject, windowStart, amountUsed, limit);
    }

    /// @notice Emits an emergency pause signal for a target component.
    function emitEmergencyPause(
        address operator,
        address target,
        string calldata reason
    ) external onlyAuthorized {
        emit EmergencyPause(operator, target, reason);
    }

    /// @notice Emits confirmation that a TFA challenge has been consumed.
    function emitTFAChallengeConsumed(
        address caller,
        address to,
        uint256 amount,
        uint256 nonce
    ) external onlyAuthorized {
        emit TFAChallengeConsumed(caller, to, amount, nonce);
    }
}
