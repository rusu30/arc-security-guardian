# Arc Security Guardian

> Built with Arc Studio - money-powered apps in minutes

On-chain security and risk-management middleware for the Arc network. Includes four Solidity contracts (SecurityRegistry, TransactionValidationHook, TwoFactorAuthGuard, SecurityEventEmitter), 110 passing Foundry tests, and a Node.js/TypeScript telemetry service.

## Deployed Contracts (Arc Testnet — Chain ID 5042002)

| Contract | Address | Role |
|---|---|---|
| SecurityEventEmitter | 0xe39b0273aab76127b4f35090a7ed1ca3dab4d189 | Canonical on-chain event bus |
| TwoFactorAuthGuard | 0x0ae2a41fe83a1c206a513f5dc7041d9069507e40 | EIP-712 2FA challenge verifier |
| SecurityRegistry (impl) | 0x9976a2ac30393d8f51f33ec6faca3e48eaf27096 | UUPS upgradeable risk/velocity registry |
| TransactionValidationHook | 0x73f7187d3f6d9dc9db56818c9687b0539e018e36 | Pre-execution transaction validator |

### Post-Deploy Wiring (required before production use)

These calls must be made from the deployer wallet (0x5B12Ce46C7194aD57d143bC22847224047b1Ef42) after deployment:

1. **Initialize the Registry proxy** — deploy an ERC1967Proxy wrapping the SecurityRegistry implementation, then call `initialize(guardianAdmin, pauser, riskManager, hook, emitter, tfaGuard)`.
2. **Authorize emitter callers** — call `SecurityEventEmitter.setAuthorizedCaller(registry, true)` and `setAuthorizedCaller(hook, true)`.
3. **Register Hook as trustedCaller on TFA Guard** — call `TwoFactorAuthGuard.setTrustedCaller(hook, true)`.
4. **Grant TRANSACTION_HOOK_ROLE** — call `SecurityRegistry.grantRole(TRANSACTION_HOOK_ROLE, hook)` via the initialized proxy.
5. **Deploy TimelockController** — `TimelockController(48h, [guardianAdmin], [guardianAdmin])`, then transfer DEFAULT_ADMIN_ROLE to it.

### 2FA Flow (for real-asset operations)

1. Off-chain: 2FA signer computes `buildChallengeHash(caller, to, amount, nonce, deadline)` and signs it with the `tfaSigner` private key.
2. On-chain: caller calls `TransactionValidationHook.validateStrict(to, amount, data, nonce, deadline, sig)` — this consumes the challenge via TwoFactorAuthGuard then enforces velocity/risk checks.
3. The real asset transfer proceeds only after `validateStrict` returns without reverting.

This is the **project memory** - what Arc Studio remembers about building this app. It helps future agents (or humans) understand and extend the project.

---

## What This App Does

[Brief description of what the app does and its primary use case]

## Tech Stack

- Frontend: React 18, Vite, TypeScript, Tailwind CSS
- Web3: wagmi v2, viem v2, ConnectKit
- Contracts: Solidity 0.8.28 + Foundry. Sources in `contracts/`, unit tests in `contracts/test/*.t.sol`. Build with `bun run contracts:build` (`forge build`), test with `bun run contracts:test` (`forge test`).
- Wallet: injected (MetaMask, etc.)
- Chain: Arc Testnet (Chain ID: 5042002, imported from `viem/chains`)
- Token: USDC (6 decimals) (Address: 0x3600000000000000000000000000000000000000, Chain: Arc Testnet)
- Toasts: Sonner

## Key Files

- `src/App.tsx` - Main application logic
- `src/components/` - UI components
- `src/config.ts` - wagmi config (chains, connectors, transports)

## To Run

```bash
bun install
bun run dev
```
