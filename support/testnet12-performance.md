# Testnet.12 Performance Verification

## Retained Testnet.11 Apple M4 reference

The user-supplied physical Apple M4 / Metal result for Testnet.11 is retained
as the primary comparison reference:

| Device | CPU workers | CPU median | GPU median | GPU batch | Workgroup | SHA midstate | Pipeline |
|---|---:|---:|---:|---:|---:|---:|---:|
| Apple M4 / Metal | 4 | 23.284 MH/s | 69.102 MH/s | 262,144 | 32 | enabled | enabled |

This is a single-device reference; it is not a claim that GPU mining is faster
than every CPU or GPU.

## Comparable local before/after measurements

The Testnet.11 release binary was measured before Testnet.12 source changes,
then the Testnet.12 source candidate was measured in five repeated three-run
sets, including the final-version binary and a fresh pre-commit verification
run, with the same command and hardware configuration:

```sh
astatine benchmark --seconds 10 --threads 4 --batch-size 262144 --workgroup-size 32 --runs 3
```

All samples used the canonical 10-byte benchmark header, Apple M4 / Metal,
SHA-256 midstate, 262,144-nonce batches, 32-lane workgroups, and the default
two-slot pipeline. Runs were sequential, not randomized interleaved trials.

| Binary / run set | CPU samples (MH/s) | CPU median | GPU samples (MH/s) | GPU median |
|---|---|---:|---|---:|
| Testnet.11 before source changes | 22.550, 22.209, 22.691 | 22.550 | 68.921, 69.064, 68.847 | 68.921 |
| Testnet.12 development set A (package version still .11) | 22.683, 22.520, 22.275 | 22.520 | 68.378, 68.539, 68.595 | 68.539 |
| Testnet.12 development set B (package version still .11) | 22.312, 22.255, 22.596 | 22.312 | 68.568, 68.598, 68.490 | 68.568 |
| Testnet.12 versioned candidate, set C | 22.049, 22.283, 22.192 | 22.192 | 68.488, 68.611, 68.450 | 68.488 |
| Testnet.12 final benchmark output, set D | 22.032, 22.223, 22.439 | 22.223 | 68.407, 68.596, 68.548 | 68.548 |
| Testnet.12 fresh pre-commit verification, set E | 22.727, 22.304, 22.126 | 22.304 | 68.689, 68.677, 68.738 | 68.689 |

The fifteen Testnet.12 GPU samples have a combined median of **68.568 MH/s**,
0.51% below the local Testnet.11 reproduction and 0.77% below the supplied
69.102 MH/s reference. The fresh pre-commit run's three-sample GPU median is
68.689 MH/s (0.60% below the supplied reference). The fifteen Testnet.12 CPU
samples have a combined median of 22.283 MH/s, 1.18% below the local
Testnet.11 reproduction; the fresh run's three-sample median is 22.304 MH/s.
The GPU implementation and shader were not changed for Testnet.12. These small
sequential-run differences are not a material performance regression; all
individual samples are reported rather than rounded away.

## Timing limits and genesis observer

The M4 / Metal adapter reports no wgpu timestamp-query support. The benchmark
therefore reports dispatch-to-readback wall latency, not isolated GPU shader
time. Testnet.11 and Testnet.12 use the same 262,144/32/midstate/pipeline
configuration; the Testnet.11 dispatch-to-readback median was 7.366 ms per
batch, while the fresh Testnet.12 pre-commit run measured 7.474 ms. The prior
Testnet.12 set D measured 7.368 ms. These are wall-latency observations, not
isolated shader timings.

The new genesis observer runs only while selected nodes have verified
`started == false` work. It polls those nodes' `work()` status at approximately
one-second intervals, with three concurrent node reads maximum and no
overlapping observer poll. It does not recreate GPU resources or enter the
hash scheduler. A possible activation triggers the existing canonical full
snapshot, runtime/ABI pin verification, and canonical Rust/contract
`computeWorkHash` check before work is published.

Local Anvil measurements on Apple M4 / Metal observed:

| Scenario | Activation to eligible scheduled hashing |
|---|---:|
| One selected node | 1.002 s (CPU); 1.040 s (GPU) |
| Three selected nodes, independently activated | 1.001–1.013 s (CPU) |
| Nine selected nodes, one atomic Coordinator transaction | 1.036 s maximum (CPU) |

The fresh release-mode lifecycle run measured first-two-poll intervals of
1.003 s for one node, three independently selected nodes, and nine atomic
nodes. Observed
maximum concurrent `work()` reads were respectively 1, 3, and 3.
The transient-RPC release test measured retry start intervals of 2.000 s and
4.001 s after consecutive probe failures; exponential backoff is bounded at
30 s. A healthy full refresh does not erase the genesis-probe retry state.

These are local Anvil timings from external activation transaction submission
through verified observer refresh and first completed hash. They are not
public-chain latency guarantees. The E2E tests also revert activation and
verify that work is invalidated before reactivation.
