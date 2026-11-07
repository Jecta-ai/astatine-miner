## Astatine Miner v0.1.0-testnet.18 — Testnet.18 Contract Migration

Testnet.18 updates the miner client to the owner-provided Injective Testnet deployment and its `0.003 INJ` proof submission fee.

### Highlights

- The Testnet manifest pins chain ID `1439`, the AST token at `0x5C730A3110a565bf388120ce64F37bb7dd0c7F83`, all nine mining contracts, and the configured Genesis Coordinator.
- The miner contracts are pinned to Solidity source commit `80e8f7cbeb21b18bc5f7475d8b751c9d9e8fb9d1`; the Genesis Coordinator is pinned to source commit `c710b4d7add5f10de326487d0ff851eb926499c6`.
- The client pins the exact `0.003 INJ` submission fee and validates token identity, miner runtime and constructor state, coordinator owner/token configuration, and configured node ordering before enabling transaction broadcast.
- The deployment is initially unstarted. The miner continues to display `WAIT GENESIS` until owner-controlled activation; the CLI does not activate Genesis.
- Mainnet remains read-only. Wallets, configuration, authenticated transaction journals, and prior authorization records remain compatible with the update.
- Local Anvil fixtures now use the reviewed Testnet.18 miner and Coordinator creation bytecode; tests remain local and do not alter the public deployment.

Existing Testnet.12 installations pinned to the former signing key require a trusted key migration or a fresh trusted installation before receiving updates signed with the current key. Testnet.18 does not include a dual-key bridge.

Commit-pinned source: https://github.com/__RELEASE_REPOSITORY__/tree/__RELEASE_COMMIT__
