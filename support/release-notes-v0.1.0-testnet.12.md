## Astatine Miner v0.1.0-testnet.12

Testnet.12 adds a genesis-aware read-only startup lifecycle while retaining the
Testnet.11 proof protocol, approved Testnet deployment pins, 0.01 INJ submission
fee, and GPU compute pipeline.

### Start before genesis

- Start mining before activation with the existing `astatine mine` command. Verified selected nodes show `WAIT GENESIS`; when all selected nodes are inactive, the dashboard shows `WAITING FOR GENESIS`.
- The existing read-only observer polls only selected, verified, unstarted nodes approximately once per second using bounded `work()` status reads. Polling requests do not overlap or accumulate; the normal active-node refresh cadence is unchanged.
- A possible activation requests one coalesced full refresh. Work is scheduled only after a fresh canonical snapshot, expected chain ID, pinned runtime code, ABI state coherence, and canonical Rust/contract `computeWorkHash` parity have been verified.
- Nodes activate independently. When the authorized Coordinator atomically starts all nine nodes, one canonical refresh discovers and schedules every selected eligible node.
- The CLI never calls `activateGenesis()` or the Coordinator, and polling cannot sign, submit, finalize, or allocate mining nonces for unstarted nodes. Existing transaction journals and spending limits remain authoritative.

### Performance transparency

- The supplied physical Apple M4 / Metal Testnet.11 reference remains visible: CPU `23.284 MH/s` median and GPU `69.102 MH/s` median, with four CPU workers, 262,144-nonce GPU batches, 32-lane workgroups, SHA-256 midstate, and the asynchronous pipeline.
- The fresh pre-commit Testnet.12 binary measured GPU `68.689`, `68.677`, and `68.738 MH/s` (median `68.689 MH/s`) and CPU `22.727`, `22.304`, and `22.126 MH/s` (median `22.304 MH/s`) on the same Apple M4 / Metal configuration. Across fifteen local Testnet.12 samples, the combined GPU median is `68.568 MH/s`, 0.51% below the local Testnet.11 reproduction and 0.77% below the supplied `69.102 MH/s` reference. The combined CPU median is `22.283 MH/s`, 1.18% below the local Testnet.11 reproduction. These small measured differences are not material regressions; the GPU implementation was unchanged.
- Release-mode local activation-to-scheduled-hashing latency was 1.002 s for one selected CPU node, 1.001–1.013 s for three independently activated CPU nodes, 1.036 s maximum for nine nodes started by one atomic Coordinator transaction, and 1.040 s for one selected GPU node. Measured healthy first-two-poll intervals were 1.003 s for one, three, and nine selected nodes, with maximum concurrent reads of three. Injected transient failures retried after 2.000 s and 4.001 s; backoff is capped at 30 seconds.
- The M4 / Metal adapter does not expose wgpu timestamp queries, so shader execution time is not isolated; report only dispatch-to-readback wall latency. NVIDIA/AMD physical GPU runtime testing remains outstanding.
- See [the Testnet.12 performance report](https://github.com/Jecta-ai/astatine-miner/blob/__RELEASE_COMMIT__/support/testnet12-performance.md) for all samples, methodology, and limitations.

### Local genesis lifecycle validation

- Physical M4/Metal GPU and CPU Anvil tests cover one selected node, three independently activated nodes, and nine nodes started by one actual atomic Coordinator transaction.
- The tests start the same miner process before genesis, verify approximately one-second polling and zero pre-activation hashing/transactions, observe automatic activation, exercise reorganization rollback/re-activation, and verify clean shutdown while a poll is in flight.
- A separate local Anvil signing test confirms normal proof submission begins only after activation. No funded public Injective Testnet transactions were used.

### Protocol, compatibility, and security

- No protocol, Solidity source, deployment address, tokenomics, difficulty, proof format, submission fee, or required init configuration changes.
- Existing Testnet.11 configurations, wallets, journals, archives, CPU default, GPU verification, authenticated updates, recovery, and opt-in reward forwarding remain supported.
- Mainnet transaction signing remains disabled. The genesis observer is read-only; activation remains the responsibility of the externally authorized deployment operation.

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
