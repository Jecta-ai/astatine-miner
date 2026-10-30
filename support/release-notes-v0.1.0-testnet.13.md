## Astatine Miner v0.1.0-testnet.13

Testnet.13 is an RC1 security-remediation candidate for the Rust miner. It retains
the Testnet.12 protocol, proof algorithm, GPU pipeline, rewards, node pins, and fee
policy.

### RPC selection and trust

- The bundled Testnet primary remains `https://k8s.testnet.json-rpc.injective.network/`.
  `astatine get rpc`, `astatine set rpc`, and `astatine set rpc default` manage
  the selected network's RPC override; `astatine init` displays the network
  default and optionally validates a user-selected HTTPS RPC by chain ID.
- Astatine uses the selected primary for state-changing preflight, receipts, and
  reconciliation. The bundled archival endpoint is a historical-log fallback
  only with the bundled primary; custom RPC selections never silently fall back
  to another provider for financially consequential requests.
- RPC state, receipts and reward evidence are trusted inputs and are not
  cryptographically authenticated by the miner. Operators should select RPC
  services they trust.

### Local transaction authorization accounting

- Before signing, the journal atomically records `gas_limit × max_fee_per_gas +
  transaction_value` in a cumulative session authorization counter. It is never
  reduced by successful/reverted receipts, reported gas usage, or reorgs.
- The dashboard distinguishes cumulative maximum authorized exposure, remaining
  authorization budget, and RPC-reported actual transaction cost. `--new-session`
  explicitly begins a separate session after prior spending; it is refused while
  a transaction remains unresolved.
- The journal migration preserves historical recorded costs and archives,
  classifies pre-RC1 settlement evidence as legacy-unverified, and initializes
  the new authorization counter conservatively from stored maximum exposures.

### Release and installer integrity

- CI pins GitHub Actions by commit and Rust to 1.94.1. Package construction,
  protected-environment signing, Windows package smoke tests, and publication
  run as separate jobs. The transferred package is checked against its manifest
  before signing, including an artifact-substitution negative test.
- Unix and Windows bootstrap installers compare supported SemVer versions and
  refuse downgrade or unparseable existing versions.

### Validation and trust boundary

- The protocol and canonical SHA-256d work algorithm are unchanged. Testnet.12
  performance measurements remain historical references; Testnet.13 performance
  should be measured on comparable hardware before publication.
- Release artifacts must be independently reviewed before Testnet.13
  publication. GitHub signing and publishing environments require configured
  independent reviewers and branch/tag protections.

Commit-pinned source: [Testnet.13 release tag](https://github.com/emyrinj/astatine-miner/tree/v0.1.0-testnet.13).
