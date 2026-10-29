# Testnet.11 GPU Performance Report

## Testnet.10 reference baseline

The established Testnet.10 measurement supplied for this work is retained as
the release-comparison baseline:

| Device | CPU MH/s | GPU MH/s | GPU/CPU | Batch wall | GPU init/self-test | GPU host processing |
|---|---:|---:|---:|---:|---:|---:|
| Apple M4 / Metal, 10 s, 4 CPU workers, 2,048 batch, workgroup 64 | 22.910 | 1.334 | 0.0582x | 1.518 ms | 0.102 s | 1.366 s / 10 s |

This is the user's independent physical-hardware sample and remains the
official Testnet.10 baseline.

### Local pre-change reproduction

Before modifying the shader or compute pipeline, the existing release binary
was run three times sequentially with:

```sh
target/release/astatine benchmark --seconds 10 --threads 4
```

All samples used the canonical 10-byte Testnet work header on Apple M4/Metal,
2,048-nonce batches and 64-invocation workgroups.

| Sample | CPU MH/s | GPU MH/s | Batch wall | GPU init/self-test | Reported host processing |
|---:|---:|---:|---:|---:|---:|
| 1 | 22.111 | 1.486 | 1.374 ms | 0.088 s | 0.510 s |
| 2 | 21.830 | 1.497 | 1.364 ms | 0.072 s | 0.441 s |
| 3 | 22.044 | 1.486 | 1.373 ms | 0.072 s | 0.504 s |
| Median | 22.044 | 1.486 | 1.373 ms | 0.072 s | 0.504 s |

These local runs are a reproduction, not a replacement for the established
baseline. Their effective rates differ materially, so comparisons must use
multiple samples on controlled hardware and preserve both sets of results.

### Instrumented synchronization profile (shader unchanged)

After adding host-stage measurements and detecting that M4/Metal does not
expose wgpu timestamp queries, the same 10-second command was run three more
times. Before changing the shader, the fixed `Poll` + 1 ms sleep loop was
replaced with a bounded blocking wait on the exact wgpu submission, using a
2 ms timeout quantum for cancellation and device-loss checks.

| Sample | CPU MH/s | GPU MH/s | Batch wall | Queue wait | Host upload enqueue | GPU init |
|---:|---:|---:|---:|---:|---:|---:|
| 1 | 19.042 | 3.738 | 0.544 ms | 0.473 ms | 0.025 ms | 0.056 s |
| 2 | 18.432 | 4.078 | 0.499 ms | 0.438 ms | 0.022 ms | 0.048 s |
| 3 | 19.732 | 4.548 | 0.447 ms | 0.390 ms | 0.020 ms | 0.056 s |
| Median | 19.042 | 4.078 | 0.499 ms | 0.438 ms | 0.022 ms | 0.056 s |

The shader and 2,048/64 configuration were unchanged. This is preliminary
evidence that the original polling/sleep granularity was a major end-to-end
cost; GPU execution time itself remains unavailable on this M4 adapter. The
three results vary, and the CPU sample was slower than the established
22.910 MH/s reference, so the 4.078 MH/s local median is not a universal or
thermal-controlled claim. Keep it separate from the official baseline.

## Pre-change pipeline audit

For the 10-byte canonical header, the ABI template is 352 bytes. Its first
SHA-256 pass executes six 64-byte compression blocks; the second pass executes
one. The nonce starts at ABI byte offset 192, exactly after the first three
complete invariant blocks. A correctly cached SHA-256 chaining state after
those blocks can therefore remove three first-pass compressions per nonce.

The existing 2,048-nonce batch has these costs and limits:

- The shader computes all six first-pass blocks and the second SHA-256 pass in
  every invocation.
- Every invocation writes a 13-word (52-byte) record. The output and readback
  copy therefore handle 106,496 bytes per batch even when only one workgroup
  winner is useful for proof selection.
- Each batch creates a command encoder and bind group, submits one dispatch,
  then maps and waits for the result before starting another batch.
- While mapping is pending, the polling loop calls non-blocking `Poll` and
  sleeps for 1 ms. This introduces a millisecond-scale completion granularity
  and can consume polling CPU between waits.
- The benchmark's batch-wall metric includes submission, GPU work, copy,
  mapping, and wait. It does not isolate shader time.
- The reported host-processing value sums host preparation, result decoding,
  and candidate verification/collection; it excludes the blocking mapping
  wait. Its current console label therefore overstates what it measures.
- The Testnet.10 benchmark does not expose per-stage timing, multi-run
  statistics, configurable batch/workgroup sizes, or JSON output.

Wgpu 30 documents Metal timestamp queries as unavailable on Apple GPUs. The M4
benchmark must therefore use an honest wall-time fallback and must not present
submit-to-readback latency as GPU execution time. Timestamp-query-capable
adapters can report measured pass timestamps where the adapter exposes the
required features.

## Testnet.11 results

All measurements below were collected on the same Apple M4 / Metal adapter
using the canonical 10-byte work header and three samples per configuration.
GPU throughput is effective completed hashes divided by wall-clock sample
duration; it includes host-side verification of the reduced winner. The M4
adapter reports no timestamp-query support, so GPU compute time cannot be
isolated from submit-to-readback time.

| Configuration | Three 10 s samples (MH/s) | Median | Relative to Testnet.10 GPU baseline | Compute timing | Correctness |
|---|---|---:|---:|---|---|
| 262,144-nonce batches, 32-lane workgroups, reduced output, full SHA-256 (midstate A/B reference) | 28.927, 28.869, 28.042 | 28.869 | 21.64x | Not available; Metal timestamp queries unsupported | GPU self-test and canonical CPU winner verification |
| Same configuration with cached 192-byte-prefix SHA-256 midstate | 41.911, 41.904, 40.382 | 41.904 | 31.41x | Not available; submit-to-readback median 6.114 ms | GPU self-test and canonical CPU winner verification |
| Production two-slot pipeline, midstate, reduced output, 262,144 batch, 32-lane workgroups | 59.504, 60.691, 57.257 | 59.504 | 44.60x | Not available; dispatch-to-readback median 8.584 ms | GPU self-test; single-, three-, and nine-node Anvil compute-only lifecycles pass |

The 10-second full-SHA/midstate A/B measures a 45.1% median throughput gain
from the cached prefix state at the same batch size and workgroup size. A
separate three-run 10-second serial measurement produced 42.095, 49.352, and
40.653 MH/s (median 42.095); the pipeline run produced 59.504, 60.691, and
57.257 MH/s (median 59.504), a 41.4% higher median. These are separate,
sequential benchmark invocations rather than randomized interleaved trials;
they support the direction and scale of the improvement but are not a
thermal-controlled causal estimate.

The full-SHA reference row includes the large batch and workgroup reduction;
the available measurements do not isolate those two changes from each other.
Likewise, the Testnet.10 reference is the established external sample above,
not a same-session rerun. The combined median is therefore 44.60x that
reference, while the separate pre-change local reproduction remains recorded
above for context.

Combined production GPU initialization was 0.093 s (including a 0.070 s
self-test). Average candidate CPU verification was 0.139–0.159 ms per dispatch
in the three samples. `gpu_compute_average_ms` is null on this adapter; the
8.584 ms dispatch-to-readback latency must not be described as shader execution
time.

The compute-only Anvil lifecycle passed with `ASTATINE_E2E_GPU_NODE_SET=single`,
`three`, and `all` on the physical M4 GPU. These tests confirm bounded node
scheduling and context transitions without creating mining transaction-journal
entries. The GPU-backed three-window reward-forwarding lifecycle passed, and
all five ignored Anvil integration tests passed on the Testnet.11 versioned
tree.
