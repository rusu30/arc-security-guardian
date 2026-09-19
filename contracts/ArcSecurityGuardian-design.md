# Arc Security Guardian — Smart Contract Design Document

**Status:** Draft  
**Target Chain:** Arc Testnet (Chain ID 5042002) / Arc Mainnet (Chain ID 5042)  
**Language / Toolchain:** Solidity 0.8.28, Foundry  
**EVM Target:** Paris (Arc constraint)  
**Review Tracker:**
- [ ] Design Review
- [ ] Security Review
- [ ] Ops Review
- [ ] Compliance Review

---

## Action Items (living)

_Empty — fill after each review round._

---

## 1. Goals / Non-Goals

### Goals
- Maintain a canonical on-chain registry of verified addresses and their risk status.
- Gate every AI-agent-initiated or high-frequency micropayment transaction through a pre-execution validation hook.
- Emit structured, ABI-indexed security events for real-time off-chain telemetry.
- Survive Arc's USDC-as-gas model: no separate ETH balance; all fee logic uses the ERC-20 view.
- Enforce least-privilege, separate roles, and a timelock on administrative changes.

### Non-Goals
- Does NOT custody user funds or USDC.
- Does NOT implement its own oracle or price feed.
- Does NOT bridge USDC cross-chain (use CCTP for that).
- Does NOT replace a full DEX or lending protocol's own access-control layer.
- Does NOT provide cryptographic identity verification off-chain (entity verification is operator-attested on-chain).

---

## 2. Requirements

### Functional
1. Operators can whitelist / de-list addresses and attach a risk tier (CLEAN / WATCH / BLOCKED / VERIFIED_AGENT).
2. A pre-execution hook can be called before any sensitive transaction; it returns a pass/fail with a revert reason.
3. Per-address USDC velocity limits (per-window amount + per-call count) are enforced and configurable.
4. Events for every state change are emitted through a dedicated event bus contract.
5. Role changes require a 48-hour timelock delay.

### Security
- No path lets an address bypass a BLOCKED flag without the RiskManager role.
- No path lets the hook drain funds (it reads state only, never moves assets).
- Rate-limit windows cannot be set to zero (prevents trivial bypass).
- A paused system blocks all hook validations and registry writes until unpaused.
- Upgrading the Registry implementation requires the GuardianAdmin role AND a timelock pass.

---

## 3. Terminology & Actors

| Term | Definition |
|---|---|
| Registry | `SecurityRegistry` — stores address status and risk flags |
| Hook | `TransactionValidationHook` — read-only pre-execution gate |
| EventEmitter | `SecurityEventEmitter` — canonical event bus |
| Timelock | `TimelockController` — 48 h delay on role-change proposals |
| Risk Tier | Enum: UNKNOWN / CLEAN / WATCH / BLOCKED / VERIFIED_AGENT |
| Velocity Window | Configurable time bucket (default 1 h) for rate limits |
| Agent | Autonomous AI address performing high-frequency stablecoin micropayments |

### Actors

| Actor | On/Off-chain | Trust Level | Capabilities |
|---|---|---|---|
| GuardianAdmin | On-chain (multisig) | Trusted | Upgrade Registry impl, assign roles (via timelock) |
| Pauser | On-chain (multisig) | Trusted | Pause / unpause Registry and Hook |
| RiskManager | On-chain (multisig / automation) | Semi-trusted | Set risk tiers, velocity limits, risk flags |
| Caller (Agent / User) | On-chain | Untrusted | Call the Hook before a transaction; read registry state |
| EventEmitter Caller | On-chain | Semi-trusted (whitelisted) | Emit security events |

---

## 4. Language / Runtime

- **Solidity 0.8.28** — checked arithmetic by default; `unchecked` only in counters where overflow is impossible.
- **EVM hardfork: Paris** — Arc's pinned target; no Cancun opcodes (`mcopy`, `tload`, `tstore`, transient storage).
- **OpenZeppelin 5.1.0** — pinned in the sandbox; `UUPSUpgradeable`, `AccessControlUpgradeable`, `PausableUpgradeable`, `TimelockController`, `ReentrancyGuardUpgradeable`, `Initializable`.

---

## 5. Transaction & Execution Model

All state changes are atomic. The hook is a read-heavy function; it touches storage only to update velocity-window counters. CEI discipline is enforced: state updates precede any event emission; no external calls made from the hook.

Re-entry surface: none on the Hook (no external calls). Registry `initialize` uses `_disableInitializers()` in the implementation constructor.

---

## 6. Architecture Overview

```mermaid
graph TD
    subgraph "Callers"
        A[AI Agent / dApp]
    end
    subgraph "Arc Security Guardian"
        H[TransactionValidationHook\nimmutable]
        R[SecurityRegistry\nUUPS proxy]
        E[SecurityEventEmitter\nimmutable]
        T[TimelockController\n48h delay]
    end
    subgraph "Operators"
        PA[GuardianAdmin multisig]
        PB[Pauser multisig]
        PC[RiskManager]
    end

    A -->|validate(from, to, amount)| H
    H -->|read riskTier, velocityLimit| R
    H -->|emitValidation| E
    PC -->|setRiskTier / setVelocityLimit| R
    PB -->|pause / unpause| R
    PB -->|pause / unpause| H
    PA -->|propose upgrade| T
    T -->|execute after 48h| R
    R -->|emitRegistryEvent| E
```

### Flow of Funds

The system holds NO funds. All fund movement is the caller's responsibility. The hook validates but never transfers.

| Step | Who | What | Invariant |
|---|---|---|---|
| 1 | Caller | Calls `validate(from, to, amount, data)` | Hook reads state only |
| 2 | Hook | Checks risk tier + velocity window | Reverts or returns `(true, "")` |
| 3 | Caller | Proceeds with (or cancels) the real transaction | Hook result is advisory OR enforced by caller |

**Resting-state invariant:** The Guardian system holds 0 USDC and 0 native balance at rest.

---

## 7. Contract Design

### 7.1 SecurityRegistry (UUPS Upgradeable)

**Roles**

| Role | Holder | Permissions |
|---|---|---|
| `DEFAULT_ADMIN_ROLE` | TimelockController | Grant / revoke roles |
| `GUARDIAN_ADMIN_ROLE` | GuardianAdmin multisig | `_authorizeUpgrade`, set timelock |
| `PAUSER_ROLE` | Pauser multisig | `pause`, `unpause` |
| `RISK_MANAGER_ROLE` | RiskManager multisig / bot | `setRiskTier`, `setVelocityLimit`, `setRiskFlag`, `batchSetRiskTier` |

**Storage layout (EIP-7201 namespace: `arc.security.registry.v1`)**

```
struct RegistryStorage {
    mapping(address => RiskRecord) records;      // per-address risk record
    mapping(address => VelocityConfig) velocity; // per-address velocity config
    mapping(address => VelocityState) velState;  // per-address live counter
    address eventEmitter;                        // SecurityEventEmitter address
    uint256 defaultWindowSeconds;                // default velocity window (1h)
    uint256 defaultAmountLimit;                  // default USDC limit per window (6 dec)
    uint256 defaultCallLimit;                    // default call count per window
}

struct RiskRecord {
    RiskTier tier;          // UNKNOWN / CLEAN / WATCH / BLOCKED / VERIFIED_AGENT
    uint64  verifiedAt;     // timestamp of last verification
    uint64  flaggedAt;      // timestamp of last flag change
    bytes32 flags;          // bitmask of active risk flags
    string  metadata;       // off-chain URI or IPFS CID
}

struct VelocityConfig {
    uint256 windowSeconds;   // 0 = use default
    uint256 amountLimitUsdc; // max USDC (6 dec) per window; 0 = use default
    uint256 callLimit;       // max calls per window; 0 = use default
}

struct VelocityState {
    uint256 windowStart;     // timestamp this window opened
    uint256 amountUsed;      // USDC consumed this window
    uint256 callCount;       // calls this window
}
```

**Key functions (write)**

| Function | Caller | State mutated | Events | Reverts when |
|---|---|---|---|---|
| `initialize(admin, pauser, riskMgr, emitter, timelockDelay)` | Deployer (once) | Sets all roles, defaults | `Initialized` | Already initialized |
| `setRiskTier(addr, tier, metadata)` | RISK_MANAGER_ROLE | `records[addr]` | `RiskTierSet` | Paused |
| `batchSetRiskTier(addrs[], tiers[], metadatas[])` | RISK_MANAGER_ROLE | batch records | `RiskTierSet` × N | Paused, array mismatch |
| `setRiskFlag(addr, flagBit, value)` | RISK_MANAGER_ROLE | `records[addr].flags` | `RiskFlagSet` | Paused |
| `setVelocityConfig(addr, windowSec, amountLimit, callLimit)` | RISK_MANAGER_ROLE | `velocity[addr]` | `VelocityConfigSet` | Paused, windowSec==0 |
| `recordUsage(addr, amount)` | TRANSACTION_HOOK_ROLE | `velState[addr]` | `VelocityUsageRecorded` | Not hook role |
| `pause()` / `unpause()` | PAUSER_ROLE | Pausable state | `Paused` / `Unpaused` | Wrong role |
| `_authorizeUpgrade(newImpl)` | GUARDIAN_ADMIN_ROLE | (proxy impl pointer) | `Upgraded` | Wrong role |
| `setEventEmitter(addr)` | GUARDIAN_ADMIN_ROLE | `eventEmitter` | `EventEmitterSet` | Zero address |

### 7.2 TransactionValidationHook (Immutable)

**Constructor args:** `registry` address, `emitter` address.

**Key functions**

| Function | Caller | Returns | Logic |
|---|---|---|---|
| `validate(from, to, amount, data)` | Anyone | `(bool ok, string reason)` | Reads `from` risk tier; if BLOCKED → revert; checks velocity window → revert if exceeded; emits `ValidationResult` |
| `validateStrict(from, to, amount, data)` | Anyone | void (reverts on fail) | Same as `validate` but reverts instead of returning false |
| `pause()` / `unpause()` | PAUSER_ROLE | | Pause gate on validations |

**Velocity check pseudocode:**
```
windowSec = config.windowSeconds || registry.defaultWindowSeconds
if (now > state.windowStart + windowSec):
    reset state
state.amountUsed += amount
state.callCount  += 1
if state.amountUsed > amountLimit: revert VelocityAmountExceeded
if state.callCount  > callLimit:   revert VelocityCallsExceeded
```
State is written back to the Registry via `recordUsage(from, amount)` only when validation passes.

### 7.3 SecurityEventEmitter (Immutable)

**Events**

| Event | Indexed params | When |
|---|---|---|
| `SecurityValidation(from, to, amount, ok, reason)` | from, to | Every hook call |
| `RiskTierChanged(subject, oldTier, newTier, operator)` | subject, operator | `setRiskTier` |
| `RiskFlagChanged(subject, flagBit, value, operator)` | subject | `setRiskFlag` |
| `VelocityBreach(subject, windowStart, amountUsed, limit, operator)` | subject | Velocity exceeded |
| `EmergencyPause(operator, contract, reason)` | operator | Pause called |

Only whitelisted emitter callers (set in the Emitter) can call `emit*` functions, preventing spam.

---

### 7.4 TwoFactorAuthGuard (Immutable)

Provides on-chain two-factor authentication for any operation that moves real assets or tokens (USDC transfers, token mints/burns, Registry privilege writes). Uses EIP-712 typed-data signatures issued by a designated **2FA Signer** (an off-chain service or hardware key). The pattern is a commit-then-execute challenge:

1. **Off-chain:** The 2FA signer produces a signed `TFAChallenge` struct tied to `(caller, to, amount, nonce, deadline, chainId)`.
2. **On-chain:** The caller submits the signature alongside the real transaction; the Guard verifies it, marks the nonce used, and allows the call through.

**Why EIP-712 over TOTP codes:**  
TOTP/HOTP codes cannot be verified on-chain without an oracle. EIP-712 signatures from a controlled HSM/cold key give the same "you proved you hold a second factor" guarantee, are cryptographically binding to the exact operation (amount, recipient, chain), and carry a deadline — so a stolen challenge is useless after expiry.

**Storage (immutable contract — no upgradeable storage needed):**

```
mapping(address => uint256) public nonces;           // per-caller monotonic nonce
mapping(bytes32 => bool)    public usedChallenges;   // replay prevention by challengeHash
address public immutable tfaSigner;                  // EIP-712 signing key address
uint256 public immutable maxChallengeLifetime;       // e.g. 300 seconds (5 min)
```

**EIP-712 domain:**
```
name:    "ArcSecurityGuardian.TFA"
version: "1"
chainId: <Arc chain ID>
verifyingContract: <TwoFactorAuthGuard address>
```

**Typed struct:**
```
TFAChallenge {
    address caller;     // msg.sender who will consume this challenge
    address to;         // recipient of the protected operation
    uint256 amount;     // USDC amount (6-decimal ERC-20 view)
    uint256 nonce;      // must equal nonces[caller] at time of use
    uint256 deadline;   // block.timestamp must be <= deadline
}
```

**Key functions (write)**

| Function | Caller | State mutated | Events | Reverts when |
|---|---|---|---|---|
| `consumeChallenge(to, amount, nonce, deadline, sig)` | Protected contract (via modifier) | `nonces[caller]++`, `usedChallenges[hash]=true` | `ChallengeConsumed` | Expired, wrong signer, nonce mismatch, replayed hash |
| `requireTFA(to, amount, nonce, deadline, sig)` | Any contract via `modifier withTFA` | Same as `consumeChallenge` | `ChallengeConsumed` | Same conditions |

**Modifier pattern (to be applied in Registry privileged writes and on any USDC transfer wrapper):**
```solidity
modifier withTFA(address to, uint256 amount, uint256 nonce, uint256 deadline, bytes calldata sig) {
    tfaGuard.consumeChallenge(msg.sender, to, amount, nonce, deadline, sig);
    _;
}
```

**Security properties:**
- Each challenge is bound to exact `(caller, to, amount, nonce, deadline, chainId)` — no reuse on a different chain or operation.
- `maxChallengeLifetime` caps `deadline - block.timestamp`; the 2FA signer refuses to issue challenges with longer lifetimes.
- `usedChallenges` bitmask prevents replay even within the deadline window.
- The `tfaSigner` key is an immutable constructor argument — rotating it requires deploying a new Guard and re-registering.

---

## 8. Deployment & Initialization Order

1. Deploy `TimelockController(minDelay=48h, proposers=[guardianAdmin], executors=[guardianAdmin])`.
2. Deploy `SecurityEventEmitter(authorizedCallers=[])` (initially empty; updated after step 5/6).
3. Deploy `TwoFactorAuthGuard(tfaSigner, maxChallengeLifetime=300)`.
4. Deploy `SecurityRegistry` implementation + `ERC1967Proxy`, calling `initialize(timelock, pauser, riskMgr, emitter, tfaGuard, 48h)`.
5. Deploy `TransactionValidationHook(registry, emitter, tfaGuard)`.
6. Call `SecurityEventEmitter.setAuthorizedCaller(registry, true)`, `setAuthorizedCaller(hook, true)`, and `setAuthorizedCaller(tfaGuard, true)`.

---

## 9. Upgradeability

Pattern: UUPS proxy (`SecurityRegistry` only).  
- `_authorizeUpgrade` is guarded by `GUARDIAN_ADMIN_ROLE` (held by a multisig).
- All role grants/revocations route through the `TimelockController` (48 h delay).
- Storage layout uses EIP-7201 namespaced storage to prevent slot collisions on upgrades.
- `TransactionValidationHook` and `SecurityEventEmitter` are immutable — new versions are deployed fresh and re-registered.

---

## 10. Security Considerations

| Vulnerability | Applicable? | Mitigation |
|---|---|---|
| Reentrancy | Yes — hook writes velocity state | CEI ordering; no external calls from hook |
| Access control | Yes — all privileged functions | AccessControlUpgradeable + role checks + timelock |
| Integer overflow/underflow | No — Solidity 0.8 checked | `unchecked` not used on amount arithmetic |
| Unchecked external call | No — hook makes no external calls | n/a |
| Fee-on-transfer tokens | No — Registry doesn't receive tokens | n/a |
| Signature replay | No — no off-chain signatures | n/a |
| Front-running | Low — velocity windows are per-address | Limits are per-window, not absolute; MEV not a concern |
| Denial of service | Yes — batch functions could be large | `batchSetRiskTier` capped at 200 addresses per call |
| Delegatecall/proxy safety | Yes — Registry is UUPS | EIP-7201 namespaced storage; `_disableInitializers()` in impl constructor |
| Timestamp dependence | Yes — velocity windows use `block.timestamp` | Windows are seconds-wide; ±15s miner drift is within tolerance |
| Approval persistence | No — no token approvals | n/a |
| Centralization risk | Yes — roles hold power | Multisig holders; 48 h timelock; separate Pauser |
| Velocity bypass (new address) | Yes | Default limits applied to all addresses not explicitly configured |
| Hook bypass (caller ignores result) | Yes | `validateStrict` reverts; callers who ignore are outside scope |

---

## 11. Trust Model & Threat Analysis

| Actor | Max Damage if Compromised | Mitigation | Detection |
|---|---|---|---|
| GuardianAdmin key | Upgrade Registry to malicious impl after 48 h delay | TimelockController 48 h window allows cancellation; multisig | Timelock `CallScheduled` event monitored |
| Pauser key | Pause system, blocking all validations | Separate from RiskManager; can't upgrade or change tiers | `Paused` event → PagerDuty alert |
| RiskManager key | Set any address to BLOCKED/CLEAN, change velocity limits | No fund access; no upgrade power; changes logged and emitted | `RiskTierChanged` event monitored |
| Timelock itself | Could be targeted if proposers are compromised | GuardianAdmin is a multisig (≥2-of-N); cancel window exists | Monitoring `CallScheduled` on emitter |

---

## 12. Emergency Response

- `Pauser` can call `pause()` on Registry and Hook independently.
- Paused Registry: all writes revert. Hook reads are still available (so callers can check tiers) but `recordUsage` is blocked.
- Paused Hook: `validate` and `validateStrict` revert immediately with `SystemPaused`.
- No fund rescue needed (contract holds no funds).
- Incident playbook: detect alert → Pauser multisig executes pause → investigate via telemetry → RiskManager adjusts tiers → Pauser unpauses.

---

## 13. Testing Strategy

- Unit tests (Foundry): happy path, revert paths, events, fuzz on amount/window arithmetic, invariant: `velocityAmountUsed <= amountLimit` post-reset, invariant: `BLOCKED` address always fails validation.
- Static analysis: Slither on all three contracts.
- Fork test: Arc Testnet fork, real USDC ERC-20 contract at `0x3600000000000000000000000000000000000000`.
- Coverage target: 100% branch on access-control modifiers and velocity logic.

---

## 14. Monitoring & Alerting

| Event | Threshold | Severity | Playbook |
|---|---|---|---|
| `VelocityBreach` | Any | High | Alert RiskManager; review address |
| `RiskTierChanged` to BLOCKED | Any | High | Alert ops; confirm legitimacy |
| `EmergencyPause` | Any | Critical | Page on-call; begin incident review |
| `Upgraded` | Any | Critical | Verify new impl hash; page security |
| `CallScheduled` on Timelock | Any | Medium | 48 h window to cancel if malicious |

---

## 15. Third-Party Libraries

| Library | Version | In sandbox? | Why | Security reviewed? |
|---|---|---|---|---|
| OpenZeppelin Contracts | 5.1.0 | Yes (pinned) | UUPS, AccessControl, Pausable, TimelockController | Yes (OZ audited) |
| Forge-std | Latest | Yes | Testing | n/a (test-only) |
