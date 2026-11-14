# Native CUDA kernel

`src/gpu/cuda/sha256d.cu` is the CUDA C++ source for the native Driver API SHA-256d backend. `src/gpu/cuda/sha256d.ptx` is the compiled PTX image embedded in Linux/Windows binaries. The kernel only computes candidate hashes; Rust re-hashes every candidate through the canonical `WorkHasher` before proof intake.

The PTX is reproducibly built with NVIDIA CUDA Toolkit 12.0.1 from the immutable official container image `nvidia/cuda@sha256:0cca95cbbdbdc5011919e5182891bc944a159b9c529999c1e434b6406fa90f53` (Linux x86_64 image). It targets the virtual architecture `compute_52`, which lets the installed NVIDIA driver JIT the PTX for compatible compute-capability-5.2-and-newer GPUs. The build does not depend on an NVIDIA GPU; the script also assembles the PTX for the generic `sm_86` target as a code-generation check, not as physical-device evidence.

With Docker available, generate a comparison image and verify it against the checked-in PTX:

```sh
temporary_ptx="$(mktemp "${TMPDIR:-/tmp}/astatine-sha256d.XXXXXX.ptx")"
rm -f "$temporary_ptx"
support/cuda/build-ptx.sh "$temporary_ptx"
cmp src/gpu/cuda/sha256d.ptx "$temporary_ptx"
rm -f "$temporary_ptx"
```

The pinned image is fetched by digest on first use; subsequent builds can run offline while that image remains in the local Docker cache. No CUDA Toolkit, `nvcc`, NVRTC, Vulkan graphics stack, display server, or administrator privilege is required on a mining host. The runtime dynamically loads only the NVIDIA CUDA Driver API (`libcuda.so.1` on Linux, `nvcuda.dll` on Windows), then loads the checked-in PTX using `cuModuleLoadData` through cudarc. The cudarc `Ptx` wrapper is used only to pass precompiled PTX to the Driver API; `compile_ptx`/NVRTC are never called.

The PTX uses the same 32-bit big-endian SHA-256 words, 192-byte invariant prefix midstate, ABI nonce word location, full-width inclusive target comparison, strict incumbent comparison, and lexicographic `(hash, nonce)` workgroup reduction as the existing WGSL backend. The host ABI is defined in `src/gpu/cuda_abi.rs` and the kernel layout in `src/gpu/cuda/sha256d.cu`; changes to either require corresponding differential-test updates and consensus review.

The checked-in `.cu` and `.ptx` are MIT-licensed with the rest of Astatine source. The CUDA Driver API itself remains an NVIDIA system component and is not bundled or redistributed.

## Driver-call liveness and shutdown

The CUDA backend polls event completion every 2 ms and applies a 15-second dispatch deadline. Engine shutdown attempts a shared-deadline drain of pending work for up to 2 seconds. These bounds limit polling only when each CUDA Driver API call returns: an application timeout cannot interrupt a driver call that blocks inside `try_is_complete` or another CUDA API operation.

When a driver call returns an error or a backend operation panics, the mining controller can recover: `auto` starts CPU workers, while explicit `gpu` reports failure and does not substitute CPU mining. If a CUDA call never returns, the controller cannot process that recovery path. Mining shutdown requests stop and waits up to 10 seconds for the GPU controller; if it remains blocked, the controller thread is detached. If CUDA completion is uncertain, the engine leaks its bounded CUDA allocation until process exit rather than freeing buffers that may still be in use. These are best-effort safeguards, not a hard timeout guarantee against a non-returning driver call.

## Hardware validation

Physical CUDA mining and runtime testing have been performed on Linux x86_64 with an NVIDIA RTX 3070. macOS physical mining testing has been performed separately on Apple Silicon M4 using Metal. `GPU_EVIDENCE.md` records the exact local artifacts, their attribution limits, and a reproducible capture procedure; the recorded run is historical evidence for one host, not release qualification of the current commit.

Physical mining tests have been performed on Linux and macOS, including NVIDIA CUDA mining on Linux and Apple Metal mining on macOS. Physical mining and GPU runtime testing have not yet been performed on Windows. Windows builds and automated CI tests have passed, but Windows GPU functionality remains physically unverified.

Windows x86_64 native compilation and automated CI validation passed. No physical Windows mining run has been performed, and Windows physical CUDA runtime testing has not been performed. Build, PTX assembly, and CI-only checks are not physical runtime evidence. The runtime still requires a compatible driver, device, and successful self-test before CUDA is selected.

The physical kernel self-test can be run on a supported NVIDIA system when hardware is available:

```sh
cargo test --locked gpu::cuda::tests::physical_cuda_executes_canonical_sha256d_and_u128_differential_tests -- --ignored --exact --nocapture --test-threads=1
```

Then run the packaged executable's device probe, which performs the runtime kernel and canonical-work self-test without RPC or wallet access:

```sh
./target/release/astatine devices
```

```powershell
.\target\release\astatine.exe devices
```

The test performs actual CUDA kernel execution and CPU/CUDA differential checks over canonical work, target and incumbent boundaries, 128-bit nonce boundaries, varied work contexts, header padding boundaries, and deterministic workgroup minima. The Linux RTX 3070 result is historical physical evidence; Windows physical runtime remains explicitly unverified. For the existing paid Anvil lifecycle and mining-worker shutdown path, set `ASTATINE_E2E_DEVICE=gpu` for the relevant ignored transaction lifecycle test on a machine with a physical NVIDIA adapter.
