## Astatine Miner v0.1.0-testnet.15

Testnet.15 adds explicitly approved per-run spending sessions and wallet-address QR output while preserving the Testnet.14 journal, release-verification, and protocol trust boundaries.

### Highlights

- New installations default to a 1 INJ per-run authorization ceiling. Each paid `astatine mine` invocation asks for fresh approval and creates at most one run session; it never automatically refills during the run.
- Each run's temporary cap is limited by the configured ceiling and confirmed wallet balance after subtracting the minimum reserve and all unresolved maximum transaction liabilities. The computed cap is journaled for that run but is not written back as the configured default.
- Existing schema-v1 accounts retain legacy cumulative-session behavior until the owner explicitly opts in with `astatine init --per-run-sessions` or accepts the interactive migration prompt.
- In per-run mode, unresolved transactions remain reserved and continue read-only receipt/nonce recovery while live hashing and fresh-run signing continue. A new transaction must use a distinct pending nonce and pass the existing balance, reserve, deployment, intent, fee, and journal checks. Old transactions are never rebroadcast.
- Virtual Injective logs no longer invalidate an otherwise coherent EVM transaction receipt. Virtual and removed logs are excluded from EVM event/reward verification; transaction inclusion, status, and gas accounting continue through the existing canonical receipt checks.
- `astatine wallet address` displays a QR code in interactive terminals, with a four-module quiet zone. Piped and redirected output remains plain text. A decoder regression verifies the displayed address payload is scannable.

The proof algorithm, rewards, deployed Testnet nodes and addresses, contract behavior, and 0.01 INJ submission fee remain unchanged. Automatic AST reward forwarding remains disabled because the selected RPC can fabricate reward evidence. Mainnet transaction signing remains disabled.

GitHub Actions builds and attests unsigned assets only. The owner verifies production tag provenance online, signs offline with the existing V3 key, and manually publishes the signed inventory. A tag does not sign or publish by itself.

Commit-pinned source: https://github.com/__RELEASE_REPOSITORY__/tree/__RELEASE_COMMIT__
