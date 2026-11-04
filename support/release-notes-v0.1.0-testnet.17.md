## Astatine Miner v0.1.0-testnet.17 — Native CUDA Mining

Testnet.17 adds a native NVIDIA CUDA Driver API compute backend for supported Linux and Windows systems.

### Highlights

- On Linux and Windows, compatible NVIDIA GPUs are checked through the CUDA Driver API before use. A successful CUDA kernel execution and canonical SHA-256d self-test are required before the device is advertised or selected.
- Existing mining commands remain unchanged. `astatine mine --device gpu` prefers the validated native CUDA backend and can use an existing validated Vulkan/DirectX compute backend when CUDA is unavailable. Explicit GPU mode never falls back to CPU hashing.
- The CUDA kernel uses precompiled PTX embedded in the executable. Mining hosts need a compatible NVIDIA driver but do not need the CUDA Toolkit, `nvcc`, NVRTC, Vulkan graphics libraries, a display server, or administrator access.
- Every CUDA candidate is independently rehashed by the canonical Rust `WorkHasher` before it can enter the existing bounded proof pipeline. CUDA does not own transaction authorization, signing, journal, or nonce policy.
- Existing Apple Metal, Linux Vulkan, Windows DirectX 12/Vulkan, and CPU paths are preserved.

The CUDA source and pinned-container PTX reproduction instructions are included in the source tree at `src/gpu/cuda/` and `support/cuda/`. CUDA availability remains conditional on the installed driver, device compute capability, and runtime self-test. Record any Linux and Windows physical-hardware validation separately from the code; compilation and PTX assembly alone are not runtime evidence.

CUDA kernel source and build instructions: https://github.com/__RELEASE_REPOSITORY__/tree/__RELEASE_COMMIT__/support/cuda/README.md

The proof algorithm, deployed contracts and addresses, contract behavior, rewards, and 0.01 INJ submission fee are unchanged. Automatic AST reward forwarding remains disabled. Mainnet transaction signing remains disabled.

Commit-pinned source: https://github.com/__RELEASE_REPOSITORY__/tree/__RELEASE_COMMIT__
