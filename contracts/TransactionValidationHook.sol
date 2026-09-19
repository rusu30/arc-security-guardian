// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";
import {Pausable} from "@openzeppelin/contracts/utils/Pausable.sol";

interface ISecurityRegistry {
    enum RiskTier {
        UNKNOWN,
        CLEAN,
        WATCH,
        BLOCKED,
        VERIFIED_AGENT
    }

    struct RiskRecord {
        RiskTier tier;
        uint64 verifiedAt;
        uint64 flaggedAt;
        bytes32 flags;
        string metadata;
    }

    struct VelocityState {
        uint256 windowStart;
        uint256 amountUsed;
        uint256 callCount;
    }

    function getRiskRecord(address addr) external view returns (RiskRecord memory);

    function getEffectiveVelocityConfig(
        address addr
    ) external view returns (uint256 windowSeconds, uint256 amountLimitUsdc, uint256 callLimit);

    function getVelocityState(address addr) external view returns (VelocityState memory);

    function recordUsage(address addr, uint256 amount) external;
}

interface ISecurityEventEmitter {
    function emitSecurityValidation(
        address from,
        address to,
        uint256 amount,
        bool ok,
        string calldata reason
    ) external;

    function emitVelocityBreach(
        address subject,
        uint256 windowStart,
        uint256 amountUsed,
        uint256 limit
    ) external;
}

interface ITwoFactorAuthGuard {
    function consumeChallenge(
        address caller,
        address to,
        uint256 amount,
        uint256 nonce,
        uint256 deadline,
        bytes calldata sig
    ) external;
}

/// @title TransactionValidationHook
/// @notice Immutable pre-transfer validation hook for Arc Security Guardian.
contract TransactionValidationHook is AccessControl, Pausable {
    error ValidationFailed(string reason);
    error ZeroAddress();

    bytes32 public constant PAUSER_ROLE = keccak256("PAUSER_ROLE");

    address public immutable registry;
    address public immutable emitter;
    address public immutable tfaGuard;

    /// @notice Deploys the validation hook and assigns admin/pause roles to deployer.
    /// @param _registry Security registry contract.
    /// @param _emitter Security event emitter contract.
    /// @param _tfaGuard TFA challenge guard contract.
    constructor(address _registry, address _emitter, address _tfaGuard) {
        if (_registry == address(0) || _emitter == address(0) || _tfaGuard == address(0)) {
            revert ZeroAddress();
        }

        registry = _registry;
        emitter = _emitter;
        tfaGuard = _tfaGuard;

        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(PAUSER_ROLE, msg.sender);
    }

    /// @notice Validates a transfer-like action against pause state, risk tier and velocity limits.
    /// @param from Subject address being validated.
    /// @param to Destination address.
    /// @param amount Amount to validate.
    /// @param data Arbitrary additional context data.
    /// @return ok Whether validation passed.
    /// @return reason Empty when `ok=true`, otherwise short failure reason code.
    function validate(
        address from,
        address to,
        uint256 amount,
        bytes calldata data
    ) external returns (bool ok, string memory reason) {
        require(from == msg.sender, "from must be caller");
        return _validate(from, to, amount, data);
    }

    /// @notice Performs strict validation and reverts when validation fails.
    /// @param to Destination address.
    /// @param amount Amount to validate.
    /// @param data Arbitrary additional context data.
    /// @param nonce Challenge nonce.
    /// @param deadline Challenge deadline.
    /// @param sig EIP-712 signature over the challenge.
    function validateStrict(
        address to,
        uint256 amount,
        bytes calldata data,
        uint256 nonce,
        uint256 deadline,
        bytes calldata sig
    ) external {
        ITwoFactorAuthGuard(tfaGuard).consumeChallenge(msg.sender, to, amount, nonce, deadline, sig);

        (bool ok, string memory reason) = _validate(msg.sender, to, amount, data);
        if (!ok) revert ValidationFailed(reason);
    }

    /// @notice Backward-compatible alias that consumes a TFA challenge then runs strict validation.
    /// @param from Subject address being validated.
    /// @param to Destination address.
    /// @param amount Amount to validate.
    /// @param data Arbitrary additional context data.
    /// @param nonce Challenge nonce.
    /// @param deadline Challenge deadline.
    /// @param sig EIP-712 signature over the challenge.
    function validateWithTFA(
        address from,
        address to,
        uint256 amount,
        bytes calldata data,
        uint256 nonce,
        uint256 deadline,
        bytes calldata sig
    ) external {
        require(from == msg.sender, "from must be caller");

        ITwoFactorAuthGuard(tfaGuard).consumeChallenge(msg.sender, to, amount, nonce, deadline, sig);

        (bool ok, string memory reason) = _validate(msg.sender, to, amount, data);
        if (!ok) revert ValidationFailed(reason);
    }

    /// @notice Pauses validation flows.
    function pause() external onlyRole(PAUSER_ROLE) {
        _pause();
    }

    /// @notice Unpauses validation flows.
    function unpause() external onlyRole(PAUSER_ROLE) {
        _unpause();
    }

    function _validate(
        address from,
        address to,
        uint256 amount,
        bytes calldata data
    ) internal returns (bool ok, string memory reason) {
        // data is intentionally unused — reserved for future extensibility (e.g. calldata context checks).
        // solhint-disable-next-line no-unused-vars
        (data);

        if (paused()) {
            _emitValidation(from, to, amount, false, "SystemPaused");
            return (false, "SystemPaused");
        }

        ISecurityRegistry.RiskRecord memory record = ISecurityRegistry(registry).getRiskRecord(from);
        if (record.tier == ISecurityRegistry.RiskTier.BLOCKED) {
            _emitValidation(from, to, amount, false, "AddressBlocked");
            return (false, "AddressBlocked");
        }

        (uint256 windowSeconds, uint256 amountLimitUsdc, uint256 callLimit) = ISecurityRegistry(registry)
            .getEffectiveVelocityConfig(from);
        ISecurityRegistry.VelocityState memory state = ISecurityRegistry(registry).getVelocityState(from);

        uint256 amountUsed = state.amountUsed;
        uint256 callCount = state.callCount;

        if (state.windowStart == 0 || state.windowStart + windowSeconds <= block.timestamp) {
            amountUsed = 0;
            callCount = 0;
        }

        if (amountUsed + amount > amountLimitUsdc) {
            _emitValidation(from, to, amount, false, "VelocityAmountExceeded");
            return (false, "VelocityAmountExceeded");
        }

        if (callCount + 1 > callLimit) {
            _emitValidation(from, to, amount, false, "VelocityCallsExceeded");
            return (false, "VelocityCallsExceeded");
        }

        ISecurityRegistry(registry).recordUsage(from, amount);

        _emitValidation(from, to, amount, true, "");
        return (true, "");
    }

    function _emitValidation(
        address from,
        address to,
        uint256 amount,
        bool ok,
        string memory reason
    ) internal {
        try ISecurityEventEmitter(emitter).emitSecurityValidation(from, to, amount, ok, reason) {
            // no-op
        } catch {
            // no-op
        }
    }
}
