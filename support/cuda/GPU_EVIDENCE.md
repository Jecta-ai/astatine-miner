# Physical GPU evidence: recorded artifacts, gaps and capture procedure

This document describes the physical NVIDIA evidence that exists for the CUDA
backend, what it does and does not establish, and how to capture a bundle that
can be checked later. It is documentation only. No GPU hardware is rented,
emulated or inferred here, and no result is promoted to a platform or release
qualification.

## Recorded artifacts

Three files were recorded locally on 2026-11-13 and are **not** committed to
this repository. They are referenced here by content, not by host path.

| Artifact | Recorded content |
| --- | --- |
| `host-evidence.txt` | Source commit `b049ff731d33b0aeee3b7ab9c42f9e6c13984e14`; SHA-256 `b684e095a0dc1706c31a704bd18522984cd7ad70f4a259ac811caacd5257f655` labeled `target/release/astatine`; `NVIDIA GeForce RTX 3070, 595.91.07, 8192 MiB`. |
| `astatine-gpu-benchmark.json` | Schema `astatine-gpu-benchmark-v1`, version `0.1.0-testnet.0`, three 2-second samples per backend. CUDA Driver API entry: RTX 3070, compute capability 8.6, 7.7 GiB, batch 262144, workgroup 32, self-test 0.142 s. GPU samples 74.6 / 71.5 / 72.3 MH/s; 4-thread CPU samples 0.96–0.98 MH/s. |
| `astatine-stability.json` | Same schema and settings, recorded from the same evidence session. |

Commit `b049ff731d33b0aeee3b7ab9c42f9e6c13984e14` is an ancestor of this
branch and is present in its history, so the recorded commit is identifiable.
The recorded settings include three 2-second samples, batch 262144 and
workgroup 32; the exact command is unknown. The CUDA entry suggests
that adapter enumeration, kernel self-test and canonical-work rehashing
succeeded before the samples were taken, because the benchmark selects the CUDA
backend only after its runtime self-test passes, but the missing transcript
prevents independent confirmation of the run.

## What the artifacts do not establish

- **No build provenance.** No compiler version, target triple, profile flags,
  `Cargo.lock` digest, source-tree cleanliness or exact build command were
  recorded. The binary digest is a line in a plain text file; it is not signed,
  attested or recomputable because the binary was not retained.
- **No command transcript.** The exact command lines, stdout/stderr, start/end
  times and exit statuses are absent. The JSON files carry no host, commit or
  binary fields, so they cannot independently bind themselves to the other two
  files.
- **No host provenance.** OS distribution, kernel, driver package and container
  or bare-metal status are unknown beyond the single driver line.
- **No independent witness.** All three artifacts were produced on the same
  host by the same operator; none is independently reproducible or attested.
- **No current-release or platform coverage.** The evidence predates this
  branch's HEAD and does not cover Windows, macOS, release acceptance,
  multi-adapter systems, changed drivers, or paid transaction acceptance. The
  Windows and macOS statements in the README remain unverified or merely
  historical, as stated there.
- **No paid-run evidence.** The artifacts are wallet-free benchmark and
  stability outputs. They do not prove a paid Anvil lifecycle, submission,
  finalization or reward settlement on a physical GPU.

## Reproducible capture procedure

Run this on the physical NVIDIA host that is to be qualified. It is wallet-free
except for the optional Anvil lifecycle step, which uses disposable local keys
and no public RPC. Never include a mnemonic, keystore, keystore password,
journal, credential-store secret or `.env` file in the bundle.

```sh
set -euo pipefail
# Choose a private directory outside the source worktree.
OUT="$(mktemp -d "${TMPDIR:-/tmp}/astatine-gpu-evidence.XXXXXXXX")"
umask 077

# 1. Identify the exact source tree and toolchain.
git rev-parse HEAD > "$OUT/source-commit.txt"
git status --porcelain=v1 > "$OUT/worktree-status.txt"   # expect an empty file
git rev-parse --show-toplevel > "$OUT/repository-root.txt"
cargo --version > "$OUT/cargo-version.txt"
rustc --version --verbose > "$OUT/rustc-version.txt"

# 2. Record host and driver identity.
uname -a > "$OUT/uname.txt"
cat /etc/os-release > "$OUT/os-release.txt"
nvidia-smi --query-gpu=name,driver_version,memory.total,compute_cap --format=csv,noheader \
  > "$OUT/nvidia-smi-gpu.csv"
nvidia-smi > "$OUT/nvidia-smi.txt"

# 3. Build the exact tree and record the binary digest.
cargo build --locked --release 2>&1 | tee "$OUT/build.log"
sha256sum target/release/astatine > "$OUT/binary-sha256.txt"

# 4. Run the wallet-free probes and benchmarks.
./target/release/astatine devices 2>&1 | tee "$OUT/devices.txt"
./target/release/astatine benchmark --seconds 2 --threads 4 --runs 3 \
  --output-json "$OUT/benchmark.json" 2>&1 | tee "$OUT/benchmark.txt"

# 5. Optional physical kernel differential test (no wallet, no RPC).
cargo test --locked \
  gpu::cuda::tests::physical_cuda_executes_canonical_sha256d_and_u128_differential_tests \
  -- --ignored --exact --nocapture --test-threads=1 \
  2>&1 | tee "$OUT/physical-cuda-test.txt"

# 6. Bind every artifact with a digest list.
sha256sum "$OUT"/* > "$OUT/SHA256SUMS"
```

For the paid Anvil lifecycle path, run the existing ignored transaction
lifecycle test with `ASTATINE_E2E_DEVICE=gpu` on the same host, capture its full
output and exit status, and keep the disposable Anvil state directory with the
bundle. Do not point the run at a public RPC endpoint and do not reuse a real
wallet.

A bundle is usable as evidence only when `worktree-status.txt` is empty, the
recorded commit is the commit under review, and `SHA256SUMS` verifies locally.
Review and redact hostnames, device identifiers, PCI information and process
metadata before publishing any bundle; retain the original privately and
recompute digests for any redacted copy. Alternatively publish only a digest.
A green benchmark on a
different commit, a different driver, or a different adapter does not qualify
this commit.

## Claim policy

Until a bundle from the exact commit and target platform is recorded, the CUDA
backend remains **implemented, historically observed on
one Linux RTX 3070 host, and not release-qualified on physical hardware**.
Windows physical GPU behavior remains unverified.
