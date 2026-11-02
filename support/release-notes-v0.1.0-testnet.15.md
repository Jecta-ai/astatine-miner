## Astatine Miner v0.1.0-testnet.15

Testnet.15 adds an authenticated per-run spending policy and wallet-address QR output while preserving the Testnet.14 release-verification and protocol trust boundaries.

### Highlights

- New installations default to a 1 INJ per-run authorization ceiling. The owner approves the persistent policy during `astatine init`; each later paid `astatine mine` invocation creates one fresh session automatically, without another full-cap prompt or an automatic refill during the run.
- Each run's temporary cap is limited by the configured ceiling and confirmed wallet balance after subtracting the minimum reserve and all unresolved maximum transaction liabilities. The computed cap is journaled for that run but is not written back as the configured default.
- Journal schema v10 authenticates a per-run policy approval bound to network, chain ID, wallet, ceiling, and reserve. Schema-v9 journals migrate without changing their existing session counters or liabilities.
- Existing schema-v1 accounts retain legacy cumulative-session behavior until the owner explicitly opts in with `astatine init --per-run-sessions` or accepts the interactive migration prompt.
- In per-run mode, unresolved transactions remain reserved and continue read-only receipt/nonce recovery while live hashing and fresh-run signing continue. A new transaction must use a distinct pending nonce and pass the existing balance, reserve, deployment, intent, fee, and journal checks. Old transactions are never rebroadcast.
- A balance-derived reduction is requested once per affected invocation, rounded down to cents, and committed only after a locked-journal recheck. Declining creates no session. Insufficient reserve/liability budgets show wallet funding instructions and never silently reduce the configured ceiling.
- Finalization attempts are keyed by contract/node/window across sessions and archives. An unresolved or successful prior attempt prevents a duplicate signature; one retry is possible only after a confirmed revert is revalidated against canonical receipt and current window state.
- Virtual Injective logs no longer invalidate an otherwise coherent EVM transaction receipt. Virtual and removed logs are excluded from EVM event/reward verification; transaction inclusion, status, and gas accounting continue through the existing canonical receipt checks.
- The checked-in mixed-log receipt fixture records transaction `0x0bb5c1a62950464c0e27a7e6ba525ad9305be3064f6977ac67b80206f2211dfe`: three EVM logs, five Injective `virtual: true` logs, all `removed: false`. Primary and archival RPC responses were observed with matching block identity.
- `astatine wallet address` displays a QR code in interactive terminals, with a four-module quiet zone. Piped and redirected output remains plain text. A decoder regression verifies the displayed address payload is scannable.
- Local Anvil integration tests use checked-in fixtures from Astatine EVM source commit `eb9ea498ed4da10536cd6b4d5d8b55cf38e8aa30` and Coordinator commit `54588aa7b020cd7e49fa2275a560cde8138dd707`; the pinned miner fixture validates the 0.01 INJ (`10000000000000000` wei) submission fee. Tests do not rebuild an adjacent EVM checkout.

The proof algorithm, rewards, deployed Testnet nodes and addresses, contract behavior, and 0.01 INJ submission fee remain unchanged. Automatic AST reward forwarding remains disabled because the selected RPC can fabricate reward evidence. Mainnet transaction signing remains disabled.

GitHub Actions builds and attests unsigned assets only. The owner verifies production tag provenance online, signs offline with the existing V3 key, and manually publishes the signed inventory. A tag does not sign or publish by itself.

Commit-pinned source: https://github.com/__RELEASE_REPOSITORY__/tree/__RELEASE_COMMIT__
