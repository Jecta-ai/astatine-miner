## Astatine Miner v0.1.0-testnet.14

Testnet.14 is a focused CLI and release-tooling hotfix on the audited Testnet.13 V3 release trust root.

### Highlights

- `astatine init` explains the per-session INJ authorization cap in plain language. The safe first-run cap remains 0 INJ; 0.5 INJ is suggested as a starting allowance, and the user must enter/select a positive cap and separately confirm before paid mining. A fresh allowance is never granted silently.
- Re-enabling paid transactions for an existing session requires confirmation and preserves the existing remaining authorization; it does not reset the allowance.
- Standalone wallet creation/import cannot replace the wallet bound to an open paid session or change wallet selection during unresolved recovery or an interrupted session transition. Wallet/session mismatches also require an explicitly approved new session at the transaction-manager boundary.
- Completed session authorization counters and wallet/session identities remain journaled when a new session is approved, including orphaned pre-sign reservations.
- Journal schema v9 authenticates journal contents and anchors the latest revision in the OS credential store (macOS Keychain, Linux Secret Service, or Windows Credential Manager). Missing or invalid checkpoints fail closed. All positive-cap pre-v9 sessions are conservatively charged the full cap on first migration; sessions without unresolved transactions close and require fresh explicit approval, while unresolved sessions remain available only for read-only recovery. Missing or inconsistent v7/v8 counters are rejected; earlier schemas reconstruct from retained transaction and archive history before sealing.
- An unresolved transaction blocks session replacement. `astatine recover` performs read-only transaction recovery using the original journaled session and never unlocks or uses the wallet key. After recovery, a separately confirmed `astatine mine --new-session` starts a new session, followed by a fresh V3 wallet unlock.
- Transaction history, maximum authorization, and wallet/session identity remain intact across restarts, recovery, reorgs, and interrupted initialization transitions.
- The nine-node dashboard distinguishes required, in-progress, confirming, retrying, blocked, synchronizing, recovering, wallet-locked, and active-mining states. It identifies when an older window is finalizing while the chain has advanced, and reports when 0 H/s is expected because every selected window is expired.
- The global dashboard mode reports active confirmation/finalization ahead of waiting or mining states, with row-level status retained.
- Dashboard metadata, status, rows, and footer fit common terminal sizes without column collisions.
- The offline release publisher detects drafts through the release-list API, reads them by numeric release ID, verifies uploaded assets, checks active non-bypassable tag update/deletion protection and the exact remote tag/source SHA after upload, immediately before publication, and after publication, and refuses to overwrite or retry an existing draft.

The proof algorithm, rewards, deployed Testnet nodes and addresses, contract behavior, and 0.01 INJ submission fee remain unchanged. Automatic AST reward forwarding remains disabled because the selected RPC can fabricate reward evidence. Mainnet transaction signing remains disabled.

GitHub Actions builds and attests unsigned assets only. The owner verifies production tag provenance online, signs offline with the existing V3 key, and manually publishes the signed inventory. A tag does not sign or publish by itself.

Commit-pinned source: https://github.com/__RELEASE_REPOSITORY__/tree/__RELEASE_COMMIT__
