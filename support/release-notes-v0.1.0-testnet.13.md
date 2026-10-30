## Astatine Miner v0.1.0-testnet.13

Testnet.13 is an RC1 security-remediation candidate for the Rust miner.

### Highlights

- Configure a network-specific RPC with `astatine get rpc`, `astatine set rpc`,
  or `astatine init`. Remote endpoints require HTTPS and the expected chain ID.
  The selected RPC is trusted input; custom endpoints do not silently fall back
  to another provider.
- The transaction journal durably counts each session's maximum transaction
  authorization before signing. Receipts, gas reports, and reorgs never refund
  the authorization budget; RPC-reported actual costs remain separate.
- Unix and Windows installers fail closed on unsupported versions and reject
  downgrades, including stable/prerelease ordering.

The protocol, proof algorithm, GPU pipeline, rewards, node pins, and 0.01 INJ
submission fee remain unchanged. RPC state, receipts, and reward evidence are
not cryptographically authenticated by the miner.

Commit-pinned source: [Testnet.13 release tag](https://github.com/emyrinj/astatine-miner/tree/v0.1.0-testnet.13).
