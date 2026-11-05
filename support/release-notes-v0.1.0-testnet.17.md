## Astatine Miner v0.1.0-testnet.17 — Native CUDA Mining

Testnet.17 adds a native NVIDIA CUDA Driver API backend for compatible Linux and Windows systems while preserving the Testnet.17 mining and transaction safety controls.

### Highlights

- Native CUDA loads the precompiled PTX image through the NVIDIA Driver API and requires successful kernel execution plus canonical SHA-256d runtime self-tests before a device is selected. A CUDA Toolkit, `nvcc`, NVRTC, or a display server is not required on the mining host.
- GPU candidates are rehashed by the canonical Rust `WorkHasher` before entering the bounded proof pipeline. NVIDIA CUDA, Apple Metal, Vulkan, DirectX 12, and CPU compute do not change the proof algorithm or own transaction authorization.
- The miner supports nine independent mining nodes and continues after proof submission. A new same-window submission requires fresh canonical state and a strictly better incumbent; exact duplicate proofs remain blocked by the authenticated journal. Each additional on-chain proof costs `0.01 INJ` plus gas, and a proof overtaken before inclusion may still consume that fee.
- Multiple same-wallet proofs for one window can earn at most that window's single reward.
- Cumulative INJ session authorization remains durably capped before signing. Authenticated transaction journals preserve maximum exposure across restart and reorganizations, while finalization history and reward reconciliation remain verified against authenticated records.
- Installers and update clients cryptographically verify signed release manifests, hashes, sizes, and platform packages. Automatic AST reward forwarding remains disabled, and Mainnet transaction signing remains disabled.

### Hardware qualification

Physical mining tests have been performed on Linux and macOS, including NVIDIA CUDA mining on Linux and Apple Metal mining on macOS. Physical mining and GPU runtime testing have not yet been performed on Windows. Windows builds and automated CI tests have passed, but Windows GPU functionality remains physically unverified.

The Linux CUDA physical test used an NVIDIA RTX 3070. The macOS physical GPU test used Apple Silicon M4 with Metal. Windows native compilation, unit tests, installer smoke, and automated CI validation passed, but no Windows NVIDIA or other GPU runtime test was performed. Runtime selection remains conditional on compatible hardware, drivers, and successful self-tests; a build or PTX reproduction is not physical runtime evidence.

Existing Testnet.12 installations pinned to the former signing key cannot authenticate releases signed exclusively with the current key. Those installations require a trusted key migration or a fresh trusted installation before receiving Testnet.17 updates; Testnet.17 does not include a dual-key bridge.

CUDA kernel source and pinned-container PTX reproduction instructions: https://github.com/__RELEASE_REPOSITORY__/tree/__RELEASE_COMMIT__/support/cuda/README.md

The deployed contracts, addresses, contract behavior, rewards, proof algorithm, and `0.01 INJ` submission fee are unchanged.

Commit-pinned source: https://github.com/__RELEASE_REPOSITORY__/tree/__RELEASE_COMMIT__
