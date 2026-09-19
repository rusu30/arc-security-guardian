// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {EIP712} from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";

interface ISecurityEventEmitter {
    function emitTFAChallengeConsumed(address caller, address to, uint256 amount, uint256 nonce) external;
}

/// @title TwoFactorAuthGuard
/// @notice Immutable EIP-712 challenge verifier for Arc Security Guardian 2FA flows.
contract TwoFactorAuthGuard is EIP712 {
    error ChallengeExpired();
    error ChallengeTooLong();
    error InvalidTFASignature();
    error NonceMismatch(uint256 expected, uint256 given);
    error ChallengeAlreadyUsed();
    error UnauthorizedCaller();
    error ZeroAddress();
    error NotOwner();

    bytes32 public constant TFA_CHALLENGE_TYPEHASH =
        keccak256("TFAChallenge(address caller,address to,uint256 amount,uint256 nonce,uint256 deadline)");

    address public immutable tfaSigner;
    uint256 public immutable maxChallengeLifetime;
    address public immutable eventEmitter;
    address public immutable owner;

    mapping(address => uint256) public nonces;
    mapping(bytes32 => bool) public usedChallenges;
    mapping(address => bool) public trustedCallers;

    event ChallengeConsumed(
        address indexed caller,
        address indexed to,
        uint256 amount,
        uint256 nonce,
        uint256 deadline
    );
    event TrustedCallerSet(address indexed caller, bool trusted);

    /// @notice Deploys the guard with immutable signer, challenge lifetime and event emitter.
    /// @param _tfaSigner Trusted signer for TFA challenges.
    /// @param _maxChallengeLifetime Maximum seconds a challenge may remain valid from the current block time.
    /// @param _eventEmitter Security event bus address.
    constructor(
        address _tfaSigner,
        uint256 _maxChallengeLifetime,
        address _eventEmitter
    ) EIP712("ArcSecurityGuardian.TFA", "1") {
        if (_tfaSigner == address(0) || _eventEmitter == address(0)) revert ZeroAddress();

        tfaSigner = _tfaSigner;
        maxChallengeLifetime = _maxChallengeLifetime;
        eventEmitter = _eventEmitter;
        owner = msg.sender;
    }

    /// @notice Sets whether `caller` is trusted to invoke `consumeChallenge` on behalf of users.
    /// @param caller Address to update trust status for.
    /// @param trusted Whether `caller` is trusted.
    function setTrustedCaller(address caller, bool trusted) external {
        if (msg.sender != owner) revert NotOwner();
        if (caller == address(0)) revert ZeroAddress();

        trustedCallers[caller] = trusted;
        emit TrustedCallerSet(caller, trusted);
    }

    /// @notice Consumes a TFA challenge after verifying nonce, deadline, and EIP-712 signature.
    /// @param caller Caller identity that the challenge was issued for.
    /// @param to Destination address covered by the challenge.
    /// @param amount Amount covered by the challenge.
    /// @param nonce Monotonic per-caller nonce expected by this contract.
    /// @param deadline Expiration timestamp for the challenge.
    /// @param sig EIP-712 signature by `tfaSigner`.
    function consumeChallenge(
        address caller,
        address to,
        uint256 amount,
        uint256 nonce,
        uint256 deadline,
        bytes calldata sig
    ) external {
        if (msg.sender != caller && !trustedCallers[msg.sender]) revert UnauthorizedCaller();
        if (block.timestamp > deadline) revert ChallengeExpired();
        if (deadline - block.timestamp > maxChallengeLifetime) revert ChallengeTooLong();

        uint256 expected = nonces[caller];
        if (nonce != expected) revert NonceMismatch(expected, nonce);

        bytes32 digest = _buildDigest(caller, to, amount, nonce, deadline);
        (address recovered, ECDSA.RecoverError err,) = ECDSA.tryRecover(digest, sig);
        if (err != ECDSA.RecoverError.NoError || recovered != tfaSigner) {
            revert InvalidTFASignature();
        }

        bytes32 challengeHash = keccak256(abi.encode(caller, to, amount, nonce, deadline));
        if (usedChallenges[challengeHash]) revert ChallengeAlreadyUsed();

        nonces[caller] = expected + 1;
        usedChallenges[challengeHash] = true;

        // Emit local event BEFORE external call to satisfy CEI ordering.
        emit ChallengeConsumed(caller, to, amount, nonce, deadline);

        try ISecurityEventEmitter(eventEmitter).emitTFAChallengeConsumed(caller, to, amount, nonce) {
            // no-op
        } catch {
            // no-op: emitter failures must not block challenge consumption
        }
    }

    /// @notice Returns the current nonce for `caller`.
    /// @param caller Address whose nonce is queried.
    function currentNonce(address caller) external view returns (uint256) {
        return nonces[caller];
    }

    /// @notice Builds the EIP-712 digest to be signed off-chain.
    /// @param caller Caller identity that the challenge is bound to.
    /// @param to Destination address covered by the challenge.
    /// @param amount Amount covered by the challenge.
    /// @param nonce Expected monotonic nonce.
    /// @param deadline Expiration timestamp.
    function buildChallengeHash(
        address caller,
        address to,
        uint256 amount,
        uint256 nonce,
        uint256 deadline
    ) external view returns (bytes32) {
        return _buildDigest(caller, to, amount, nonce, deadline);
    }

    function _buildDigest(
        address caller,
        address to,
        uint256 amount,
        uint256 nonce,
        uint256 deadline
    ) internal view returns (bytes32) {
        bytes32 structHash = keccak256(
            abi.encode(TFA_CHALLENGE_TYPEHASH, caller, to, amount, nonce, deadline)
        );
        return _hashTypedDataV4(structHash);
    }
}
