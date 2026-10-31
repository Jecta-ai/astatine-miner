## Astatine Miner v0.1.0-testnet.11

Testnet.11 improves the portable wgpu/WGSL GPU compute pipeline while preserving the existing proof protocol and transaction pipeline.

### GPU throughput and selection

- GPU mining now uses cached SHA-256 state for the invariant ABI prefix, workgroup-level winner reduction, bounded adaptive nonce batches, and a two-slot asynchronous readback pipeline.
- The default CPU backend is unchanged. `--device auto` compares canonical CPU and GPU throughput and selects GPU only when it measures more than 10% faster; explicit `--device gpu` continues to require a physical adapter to pass the WGSL self-test.
- `astatine benchmark` reports repeated canonical CPU/GPU samples, initialization and host-stage timings, and optional JSON. `--profile`, `--compare-full-sha`, and `--serial` support bounded configuration sweeps and matched comparisons.
- Every GPU proof candidate selected for submission is rehashed using the canonical Rust `WorkHasher` and then passes through the existing bounded proof inbox, preflight, journal, and transaction manager.

### Performance and hardware validation

- On an Apple M4 / Metal adapter, three 10-second production-configuration samples measured 59.504, 60.691, and 57.257 MH/s (median 59.504 MH/s). This is 44.60x the retained Testnet.10 GPU reference of 1.334 MH/s; it is a measured single-device result, not a cross-device guarantee.
- A matched full-SHA versus cached-midstate comparison measured a 45.1% median throughput increase for the midstate path. Separate serial and pipelined samples measured medians of 42.095 and 59.504 MH/s respectively.
- The physical M4/Metal GPU passed its canonical shader self-tests and local Anvil lifecycle tests for single-, three-, and nine-node compute-only scheduling. GPU-backed three-window mining and reward forwarding also passed against local Anvil.
- wgpu timestamp queries are unavailable on this M4/Metal adapter, so GPU execution duration is not reported as an isolated measurement. The performance report records dispatch-to-readback wall latency instead.
- NVIDIA/AMD GPU drivers and physical Windows/Linux GPU runtime execution remain unverified.

### Protocol and security

- No Solidity contract, deployment address, tokenomics, difficulty, proof fee, or proof format changes.
- CPU remains the default backend, and GPU results are CPU-verified before proof submission. The existing spending limits, journal recovery, reorg handling, reward accounting, opt-in forwarding, and Mainnet signing restriction are unchanged.
- `--compute-only` remains transaction-free.

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

See [the Testnet.11 GPU performance report](https://github.com/Jecta-ai/astatine-miner/blob/__RELEASE_COMMIT__/support/testnet11-performance.md) for the retained Testnet.10 reference, sample measurements, methodology, and adapter limitations.
