## Astatine Miner v0.1.0-testnet.10

Testnet.10 adds the first portable wgpu/WGSL GPU compute backend while preserving the Testnet.9 proof protocol and transaction pipeline.

### GPU compute and safety

- `astatine mine --device cpu` remains the default. `--device gpu` requires a physical adapter to pass the real WGSL SHA-256d self-test; `--device auto` prefers a validated GPU and safely falls back to CPU.
- The WGSL shader hashes the canonical ABI-encoded `WORK_DOMAIN_V2` tuple using double SHA-256, including the complete 128-bit nonce and supported header lengths.
- GPU outputs are CPU-rehashed by the canonical `WorkHasher` before entering the existing proof inbox. The existing transaction manager remains the only signing and broadcasting authority.
- GPU nonce batches share each node's existing allocator; stale results are rejected and failed GPU ranges are never reused.
- `astatine devices` lists adapters and executes a real shader self-test. `astatine benchmark` measures CPU and GPU throughput on identical canonical work without RPC access or transactions.

### Hardware validation

- The physical Apple M4 GPU on Metal passed canonical work vectors, SHA-256 block-padding boundaries, 128-bit nonce carries/exhaustion, deterministic CPU/GPU differential batches, and target/incumbent comparisons.
- The complete three-window mining, finalization, receipt, reward reconciliation, recovery, and forwarding lifecycle passed against local Anvil using that GPU.
- NVIDIA and AMD adapters and Windows/Linux GPU driver execution remain unverified on physical hardware; wgpu target builds alone do not establish runtime compatibility.
- A 2-second Apple M4/Metal sample using four CPU workers measured 17.504 MH/s on CPU and 1.309 MH/s on GPU (0.07x ratio); GPU initialization/self-test took 0.093 s, each 2,048-nonce dispatch/compute/readback averaged 1.559 ms, and measured GPU host processing used approximately 0.94% of ten logical CPUs. This is a single measured run, not a performance claim.

### Protocol and security

- No Solidity contract, deployment address, tokenomics, difficulty, proof fee, or proof format changes.
- GPU proofs are independently checked on CPU before submission. Existing spending limits, journal recovery, reorg handling, reward accounting, and opt-in forwarding are unchanged.
- Mainnet transaction signing remains disabled.

### Install

macOS/Linux one-command install:

```sh
curl --fail --show-error --location https://raw.githubusercontent.com/Jecta-ai/astatine-miner/__RELEASE_COMMIT__/support/install-unix.sh | sh
```

Windows PowerShell one-command install:

```powershell
$Installer = Join-Path $env:TEMP 'astatine-install.ps1'; Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/Jecta-ai/astatine-miner/__RELEASE_COMMIT__/support/install-windows.ps1' -OutFile $Installer; powershell.exe -NoProfile -ExecutionPolicy Bypass -File $Installer
```

Both scripts can be downloaded and reviewed before execution; the full commands are in the README.

### Downloads

- `astatine-macos-aarch64.tar.gz`
- `astatine-macos-x86_64.tar.gz`
- `astatine-linux-aarch64.tar.gz`
- `astatine-linux-x86_64.tar.gz`
- `astatine-windows-x86_64.zip`
- `update-manifest.txt`, `update-manifest.sig`, and `SHA256SUMS`

The authenticated update path from Testnet.9 can discover and install Testnet.10. See the README for device selection, hardware limitations, verification, and benchmark methodology.
