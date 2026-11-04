# Native CUDA kernel

`src/gpu/cuda/sha256d.cu` is the CUDA C++ source for the native Driver API SHA-256d backend. `src/gpu/cuda/sha256d.ptx` is the compiled PTX image embedded in Linux/Windows binaries. The kernel only computes candidate hashes; Rust re-hashes every candidate through the canonical `WorkHasher` before proof intake.

The PTX is reproducibly built with NVIDIA CUDA Toolkit 12.0.1 from the immutable official container image `nvidia/cuda@sha256:0cca95cbbdbdc5011919e5182891bc944a159b9c529999c1e434b6406fa90f53` (Linux x86_64 image). It targets the virtual architecture `compute_52`, which lets the installed NVIDIA driver JIT the PTX for compatible compute-capability-5.2-and-newer GPUs. The build does not depend on an NVIDIA GPU; the script also runs `ptxas` for `sm_86` to validate the PTX for RTX 30-series-class devices.

With Docker available, generate a comparison image and verify it against the checked-in PTX:

```sh
temporary_ptx="$(mktemp "${TMPDIR:-/tmp}/astatine-sha256d.XXXXXX.ptx")"
rm -f "$temporary_ptx"
support/cuda/build-ptx.sh "$temporary_ptx"
cmp src/gpu/cuda/sha256d.ptx "$temporary_ptx"
rm -f "$temporary_ptx"
```

The pinned image is fetched by digest on first use; subsequent builds can run offline while that image remains in the local Docker cache. No CUDA Toolkit, `nvcc`, NVRTC, Vulkan graphics stack, display server, or administrator privilege is required on a mining host. The runtime dynamically loads only the NVIDIA CUDA Driver API (`libcuda.so.1` on Linux, `nvcuda.dll` on Windows), then loads the checked-in PTX using `cuModuleLoadData` through cudarc. The cudarc `Ptx` wrapper is used only to pass precompiled PTX to the Driver API; `compile_ptx`/NVRTC are never called.

The PTX uses the same 32-bit big-endian SHA-256 words, 192-byte invariant prefix midstate, ABI nonce word location, full-width inclusive target comparison, strict incumbent comparison, and lexicographic `(hash, nonce)` workgroup reduction as the existing WGSL backend. The host ABI is defined in `src/gpu/cuda_abi.rs` and the kernel layout in `src/gpu/cuda/sha256d.cu`; change both only with differential-test updates and an independent consensus review.

The checked-in `.cu` and `.ptx` are MIT-licensed with the rest of Astatine source. The CUDA Driver API itself remains an NVIDIA system component and is not bundled or redistributed.

## Hardware validation

Run the physical kernel self-test separately on Linux x86_64 and Windows x86_64 machines with supported NVIDIA drivers:

```sh
cargo test --locked gpu::cuda::tests::physical_cuda_executes_canonical_sha256d_and_u128_differential_tests -- --ignored --exact --nocapture --test-threads=1
```

The test performs actual CUDA kernel execution and CPU/CUDA differential checks over canonical work, target and incumbent boundaries, 128-bit nonce boundaries, varied work contexts, header padding boundaries, and deterministic workgroup minima. For the existing paid Anvil lifecycle and mining-worker shutdown path, set `ASTATINE_E2E_DEVICE=gpu` for the relevant ignored transaction lifecycle test. Repeat the physical tests independently on Linux and Windows. Native compilation or PTX assembly is not physical-driver evidence; record unsupported/unavailable hardware as pending and keep Testnet.17 release approval blocked until required platform evidence is supplied.
