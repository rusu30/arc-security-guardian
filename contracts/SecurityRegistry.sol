// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {AccessControlUpgradeable} from "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import {PausableUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/PausableUpgradeable.sol";
import {ReentrancyGuardUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/ReentrancyGuardUpgradeable.sol";

interface ISecurityEventEmitter {
    function emitRiskTierChanged(address subject, uint8 oldTier, uint8 newTier, address operator) external;

    function emitRiskFlagChanged(address subject, uint8 flagBit, bool value, address operator) external;

    function emitVelocityBreach(
        address subject,
        uint256 windowStart,
        uint256 amountUsed,
        uint256 limit
    ) external;
}

/// @title SecurityRegistry
/// @notice Upgradeable registry for risk tiers, risk flags, and velocity-control state.
contract SecurityRegistry is
    Initializable,
    AccessControlUpgradeable,
    PausableUpgradeable,
    UUPSUpgradeable,
    ReentrancyGuardUpgradeable
{
    error ArrayLengthMismatch();
    error BatchTooLarge(uint256 max);
    error ZeroAddress();
    error ZeroWindowSeconds();
    error InvalidFlagBit();

    bytes32 public constant GUARDIAN_ADMIN_ROLE = keccak256("GUARDIAN_ADMIN_ROLE");
    bytes32 public constant PAUSER_ROLE = keccak256("PAUSER_ROLE");
    bytes32 public constant RISK_MANAGER_ROLE = keccak256("RISK_MANAGER_ROLE");
    bytes32 public constant TRANSACTION_HOOK_ROLE = keccak256("TRANSACTION_HOOK_ROLE");

    uint256 internal constant _MAX_BATCH_SIZE = 200;

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

    struct VelocityConfig {
        uint256 windowSeconds;
        uint256 amountLimitUsdc;
        uint256 callLimit;
    }

    struct VelocityState {
        uint256 windowStart;
        uint256 amountUsed;
        uint256 callCount;
    }

    struct RegistryStorage {
        mapping(address => RiskRecord) records;
        mapping(address => VelocityConfig) velocity;
        mapping(address => VelocityState) velState;
        address eventEmitter;
        address tfaGuard;
        uint256 defaultWindowSeconds;
        uint256 defaultAmountLimitUsdc;
        uint256 defaultCallLimit;
    }

    // keccak256(abi.encode(uint256(keccak256("arc.security.registry.v1")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 private constant _REGISTRY_STORAGE_LOCATION =
        keccak256(abi.encode(uint256(keccak256("arc.security.registry.v1")) - 1)) &
            ~bytes32(uint256(0xff));

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    /// @notice Initializes the registry roles, event wiring, and default velocity constraints.
    /// @param guardianAdmin Address receiving guardian admin role and default admin role.
    /// @param pauser Address receiving pause/unpause permissions.
    /// @param riskManager Address receiving risk-management permissions.
    /// @param hookAddr Address receiving transaction-hook permissions.
    /// @param emitter Event emitter address.
    /// @param tfaGuard_ TFA guard address.
    function initialize(
        address guardianAdmin,
        address pauser,
        address riskManager,
        address hookAddr,
        address emitter,
        address tfaGuard_
    ) public initializer {
        if (
            guardianAdmin == address(0) ||
            pauser == address(0) ||
            riskManager == address(0) ||
            hookAddr == address(0) ||
            emitter == address(0) ||
            tfaGuard_ == address(0)
        ) revert ZeroAddress();

        __AccessControl_init();
        __Pausable_init();
        __UUPSUpgradeable_init();
        __ReentrancyGuard_init();

        _grantRole(DEFAULT_ADMIN_ROLE, guardianAdmin);
        _grantRole(GUARDIAN_ADMIN_ROLE, guardianAdmin);
        _grantRole(PAUSER_ROLE, pauser);
        _grantRole(RISK_MANAGER_ROLE, riskManager);
        _grantRole(TRANSACTION_HOOK_ROLE, hookAddr);

        RegistryStorage storage $ = _getStorage();
        $.eventEmitter = emitter;
        $.tfaGuard = tfaGuard_;
        $.defaultWindowSeconds = 3600;
        $.defaultAmountLimitUsdc = 1000_000000;
        $.defaultCallLimit = 100;
    }

    /// @notice Sets a risk tier and metadata for an address.
    /// @param addr Address whose record is updated.
    /// @param tier New risk tier.
    /// @param metadata Human-readable metadata for the update.
    function setRiskTier(
        address addr,
        RiskTier tier,
        string calldata metadata
    ) external onlyRole(RISK_MANAGER_ROLE) whenNotPaused {
        _setRiskTier(addr, tier, metadata);
    }

    /// @notice Batch updates risk tiers and metadata for up to 200 addresses.
    /// @param addrs Addresses to update.
    /// @param tiers New risk tiers.
    /// @param metadatas Metadata strings aligned with `addrs`.
    function batchSetRiskTier(
        address[] calldata addrs,
        RiskTier[] calldata tiers,
        string[] calldata metadatas
    ) external onlyRole(RISK_MANAGER_ROLE) whenNotPaused {
        uint256 len = addrs.length;
        if (len != tiers.length || len != metadatas.length) revert ArrayLengthMismatch();
        if (len > _MAX_BATCH_SIZE) revert BatchTooLarge(_MAX_BATCH_SIZE);

        for (uint256 i = 0; i < len; ++i) {
            _setRiskTier(addrs[i], tiers[i], metadatas[i]);
        }
    }

    /// @notice Sets or clears a specific risk-flag bit for an address.
    /// @param addr Address whose risk-flag bitmap is updated.
    /// @param flagBit Bit index to toggle.
    /// @param value New bit value.
    function setRiskFlag(
        address addr,
        uint8 flagBit,
        bool value
    ) external onlyRole(RISK_MANAGER_ROLE) whenNotPaused {
        if (addr == address(0)) revert ZeroAddress();
        // flagBit is uint8, so it is always in [0, 255]. No range check needed here.
        // The InvalidFlagBit error is reserved for future custom validation if flag semantics are extended.

        RegistryStorage storage $ = _getStorage();
        bytes32 mask = bytes32(uint256(1) << flagBit);

        if (value) {
            $.records[addr].flags |= mask;
        } else {
            $.records[addr].flags &= ~mask;
        }

        try ISecurityEventEmitter($.eventEmitter).emitRiskFlagChanged(addr, flagBit, value, msg.sender) {
            // no-op
        } catch {
            // no-op
        }
    }

    /// @notice Sets velocity limits for an address.
    /// @param addr Address whose velocity config is updated.
    /// @param windowSeconds Rolling window size in seconds.
    /// @param amountLimitUsdc Amount limit for the window (USDC 6-decimals convention).
    /// @param callLimit Maximum number of calls allowed per window.
    function setVelocityConfig(
        address addr,
        uint256 windowSeconds,
        uint256 amountLimitUsdc,
        uint256 callLimit
    ) external onlyRole(RISK_MANAGER_ROLE) whenNotPaused {
        if (addr == address(0)) revert ZeroAddress();
        if (windowSeconds == 0) revert ZeroWindowSeconds();

        RegistryStorage storage $ = _getStorage();
        $.velocity[addr] = VelocityConfig({
            windowSeconds: windowSeconds,
            amountLimitUsdc: amountLimitUsdc,
            callLimit: callLimit
        });
    }

    /// @notice Records transaction usage for velocity accounting.
    /// @param addr Address whose usage state is updated.
    /// @param amount Amount to add into the current window usage.
    function recordUsage(
        address addr,
        uint256 amount
    ) external onlyRole(TRANSACTION_HOOK_ROLE) whenNotPaused nonReentrant {
        if (addr == address(0)) revert ZeroAddress();

        RegistryStorage storage $ = _getStorage();
        (uint256 windowSeconds, uint256 amountLimitUsdc, uint256 callLimit) = _effectiveVelocityConfig($, addr);

        VelocityState storage state = $.velState[addr];
        uint256 start = state.windowStart;

        if (start == 0 || start + windowSeconds <= block.timestamp) {
            state.windowStart = block.timestamp;
            state.amountUsed = amount;
            state.callCount = 1;
        } else {
            state.amountUsed += amount;
            state.callCount += 1;
        }

        if (state.amountUsed > amountLimitUsdc || state.callCount > callLimit) {
            try
                ISecurityEventEmitter($.eventEmitter).emitVelocityBreach(
                    addr,
                    state.windowStart,
                    state.amountUsed,
                    amountLimitUsdc
                )
            {
                // no-op
            } catch {
                // no-op
            }
        }
    }

    /// @notice Returns the complete risk record for an address.
    /// @param addr Address whose record is requested.
    function getRiskRecord(address addr) external view returns (RiskRecord memory) {
        return _getStorage().records[addr];
    }

    /// @notice Returns the explicit velocity config for an address.
    /// @param addr Address whose velocity config is requested.
    function getVelocityConfig(address addr) external view returns (VelocityConfig memory) {
        return _getStorage().velocity[addr];
    }

    /// @notice Returns the current velocity state for an address.
    /// @param addr Address whose velocity state is requested.
    function getVelocityState(address addr) external view returns (VelocityState memory) {
        return _getStorage().velState[addr];
    }

    /// @notice Returns velocity config with defaults applied for zero-valued fields.
    /// @param addr Address whose effective config is requested.
    function getEffectiveVelocityConfig(
        address addr
    ) external view returns (uint256 windowSeconds, uint256 amountLimitUsdc, uint256 callLimit) {
        RegistryStorage storage $ = _getStorage();
        return _effectiveVelocityConfig($, addr);
    }

    /// @notice Pauses privileged flows guarded by `whenNotPaused`.
    function pause() external onlyRole(PAUSER_ROLE) {
        _pause();
    }

    /// @notice Unpauses privileged flows guarded by `whenNotPaused`.
    function unpause() external onlyRole(PAUSER_ROLE) {
        _unpause();
    }

    /// @notice Updates the external security event emitter.
    /// @param emitter New emitter contract address.
    function setEventEmitter(address emitter) external onlyRole(GUARDIAN_ADMIN_ROLE) {
        if (emitter == address(0)) revert ZeroAddress();
        _getStorage().eventEmitter = emitter;
    }

    /// @notice Authorizes implementation upgrades.
    /// @param newImplementation Proposed new implementation address.
    function _authorizeUpgrade(
        address newImplementation
    ) internal view override onlyRole(GUARDIAN_ADMIN_ROLE) {
        if (newImplementation == address(0)) revert ZeroAddress();
    }

    function _setRiskTier(address addr, RiskTier tier, string calldata metadata) internal {
        if (addr == address(0)) revert ZeroAddress();

        RegistryStorage storage $ = _getStorage();
        RiskRecord storage rec = $.records[addr];

        RiskTier oldTier = rec.tier;
        rec.tier = tier;
        rec.metadata = metadata;

        if (tier == RiskTier.VERIFIED_AGENT) {
            rec.verifiedAt = uint64(block.timestamp);
        }
        if (tier == RiskTier.WATCH || tier == RiskTier.BLOCKED) {
            rec.flaggedAt = uint64(block.timestamp);
        }

        try
            ISecurityEventEmitter($.eventEmitter).emitRiskTierChanged(
                addr,
                uint8(oldTier),
                uint8(tier),
                msg.sender
            )
        {
            // no-op
        } catch {
            // no-op
        }
    }

    function _effectiveVelocityConfig(
        RegistryStorage storage $,
        address addr
    ) internal view returns (uint256 windowSeconds, uint256 amountLimitUsdc, uint256 callLimit) {
        VelocityConfig storage cfg = $.velocity[addr];

        windowSeconds = cfg.windowSeconds == 0 ? $.defaultWindowSeconds : cfg.windowSeconds;
        amountLimitUsdc = cfg.amountLimitUsdc == 0
            ? $.defaultAmountLimitUsdc
            : cfg.amountLimitUsdc;
        callLimit = cfg.callLimit == 0 ? $.defaultCallLimit : cfg.callLimit;
    }

    function _getStorage() private pure returns (RegistryStorage storage $) {
        bytes32 slot = _REGISTRY_STORAGE_LOCATION;
        assembly {
            $.slot := slot
        }
    }
}
