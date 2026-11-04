use super::{
    GPU_BATCH_SIZES, GpuBatchResult, GpuBatchTimings, GpuDeviceInfo, GpuInitializationTimings,
    MAX_GPU_OUTPUT_GROUPS, canonical_benchmark_context,
    cuda_abi::{
        CUDA_INPUT_WORDS, CUDA_MAX_WORKGROUP_SIZE, CUDA_RESULT_WORDS, decode_batch_results,
        encode_batch_input,
    },
    validate_gpu_config, verify_benchmark_batch,
};
use crate::protocol::{MAX_HEADER_LENGTH, WorkContext, WorkHasher};
use alloy_primitives::{Address, B256, U256};
use anyhow::{Context, Result, anyhow, bail};
use cudarc::{
    driver::{
        CudaContext, CudaEvent, CudaFunction, CudaModule, CudaSlice, CudaStream, LaunchConfig,
        PinnedHostSlice, PushKernelArg, result, sys,
    },
    nvrtc::Ptx,
};
use std::{
    panic::{AssertUnwindSafe, catch_unwind},
    sync::atomic::AtomicBool,
    thread,
    time::{Duration, Instant},
};

const CUDA_DRIVER_API_MIN_VERSION: i32 = 12_000;
const CUDA_MIN_COMPUTE_CAPABILITY: (i32, i32) = (5, 2);
const CUDA_POLL_INTERVAL: Duration = Duration::from_millis(2);
const CUDA_DISPATCH_TIMEOUT: Duration = Duration::from_secs(15);
const CUDA_SHUTDOWN_DRAIN_TIMEOUT: Duration = Duration::from_secs(2);
const CUDA_BUFFER_SLOTS: usize = 2;
const CUDA_OUTPUT_WORDS: usize = MAX_GPU_OUTPUT_GROUPS * CUDA_RESULT_WORDS;
const PINNED_HOST_FLAGS: u32 = 0;
const PTX: &str = include_str!("cuda/sha256d.ptx");

struct CudaBufferSlot {
    input_device: CudaSlice<u32>,
    output_device: CudaSlice<u32>,
    input_host: PinnedHostSlice<u32>,
    output_host: PinnedHostSlice<u32>,
    completion: Option<CudaEvent>,
    busy: bool,
    submission_id: Option<u64>,
}

struct CudaResources {
    _context: std::sync::Arc<CudaContext>,
    stream: std::sync::Arc<CudaStream>,
    _module: std::sync::Arc<CudaModule>,
    function: CudaFunction,
    slots: Vec<CudaBufferSlot>,
}

pub(crate) struct CudaPendingBatch {
    slot_index: usize,
    submission_id: u64,
    first_nonce: u128,
    count: usize,
    workgroup_size: usize,
    workgroup_count: usize,
    submitted_at: Instant,
    timings: GpuBatchTimings,
}

pub(crate) struct CudaEngine {
    resources: Option<CudaResources>,
    info: GpuDeviceInfo,
    initialization: GpuInitializationTimings,
    batch_size: usize,
    workgroup_size: u32,
    midstate_enabled: bool,
    next_slot: usize,
    next_submission_id: u64,
    poisoned: bool,
}

impl Drop for CudaEngine {
    fn drop(&mut self) {
        let Some(resources) = self.resources.as_ref() else {
            return;
        };
        let deadline = Instant::now() + CUDA_SHUTDOWN_DRAIN_TIMEOUT;
        let mut safe_to_release = !self.poisoned;
        if safe_to_release {
            for slot in &resources.slots {
                let Some(event) = &slot.completion else {
                    if slot.busy {
                        safe_to_release = false;
                        break;
                    }
                    continue;
                };
                if wait_for_event_until(event, deadline).is_err() {
                    safe_to_release = false;
                    break;
                }
            }
        }
        if !safe_to_release && let Some(resources) = self.resources.take() {
            // A timed-out/failed driver call may still be using these buffers. Leak the
            // bounded per-engine allocation until process exit rather than risking a
            // blocking free or use-after-free during shutdown.
            std::mem::forget(resources);
        }
    }
}

impl CudaEngine {
    pub(super) fn driver_available() -> Result<bool> {
        // `is_culib_present` only attempts to open the standard system driver names. It does
        // not initialize a CUDA context and does not require the toolkit or NVRTC.
        Ok(unsafe { sys::is_culib_present() })
    }

    pub(super) fn driver_device_count() -> Result<Option<(i32, usize)>> {
        if !Self::driver_available()? {
            return Ok(None);
        }
        let initialized = catch_unwind(AssertUnwindSafe(|| -> Result<(i32, usize)> {
            result::init().context("initialize the NVIDIA CUDA Driver API")?;
            let mut driver_version = 0_i32;
            unsafe { sys::cuDriverGetVersion(&mut driver_version) }
                .result()
                .context("query the NVIDIA CUDA driver API version")?;
            let count = CudaContext::device_count()
                .context("enumerate NVIDIA CUDA devices through the driver API")?;
            if count < 0 {
                bail!("CUDA Driver API returned a negative device count");
            }
            Ok((driver_version, usize::try_from(count)?))
        }))
        .map_err(|_| {
            anyhow!("CUDA Driver API initialization panicked while probing the driver")
        })??;
        Ok(Some(initialized))
    }

    pub(super) fn initialize(
        batch_size: usize,
        workgroup_size: u32,
        midstate_enabled: bool,
        tune_batch: bool,
    ) -> Result<Self> {
        let Some((driver_version, device_count)) = Self::driver_device_count()? else {
            bail!(
                "NVIDIA CUDA Driver API is unavailable (expected libcuda.so.1 on Linux or nvcuda.dll on Windows)"
            );
        };
        if device_count == 0 {
            bail!("CUDA Driver API loaded but no NVIDIA compute device is visible");
        }
        let mut failures = Vec::new();
        for ordinal in 0..device_count {
            match Self::initialize_on_device(
                ordinal,
                driver_version,
                batch_size,
                workgroup_size,
                midstate_enabled,
                tune_batch,
            ) {
                Ok(engine) => return Ok(engine),
                Err(error) => failures.push(format!("CUDA device {ordinal}: {error:#}")),
            }
        }
        bail!(
            "no NVIDIA CUDA device passed the native SHA-256d self-test: {}",
            failures.join("; ")
        )
    }

    pub(super) fn initialize_on_device(
        ordinal: usize,
        driver_version: i32,
        batch_size: usize,
        workgroup_size: u32,
        midstate_enabled: bool,
        tune_batch: bool,
    ) -> Result<Self> {
        catch_unwind(AssertUnwindSafe(|| {
            Self::initialize_on_device_inner(
                ordinal,
                driver_version,
                batch_size,
                workgroup_size,
                midstate_enabled,
                tune_batch,
            )
        }))
        .map_err(|_| {
            anyhow!("CUDA Driver API panicked while initializing device ordinal {ordinal}")
        })?
    }

    fn initialize_on_device_inner(
        ordinal: usize,
        driver_version: i32,
        batch_size: usize,
        workgroup_size: u32,
        midstate_enabled: bool,
        tune_batch: bool,
    ) -> Result<Self> {
        validate_gpu_config(batch_size, workgroup_size)?;
        if driver_version < CUDA_DRIVER_API_MIN_VERSION {
            bail!(
                "CUDA driver API {} is older than the required CUDA 12.0 PTX/driver API compatibility level",
                driver_api_version_text(driver_version)
            );
        }
        let started = Instant::now();
        let context = CudaContext::new(ordinal)
            .with_context(|| format!("initialize CUDA device ordinal {ordinal}"))?;
        let (capability_major, capability_minor) = context
            .compute_capability()
            .context("query NVIDIA CUDA compute capability")?;
        if (capability_major, capability_minor) < CUDA_MIN_COMPUTE_CAPABILITY {
            bail!(
                "CUDA device {} has compute capability {capability_major}.{capability_minor}; PTX compute_52 requires 5.2 or newer",
                context
                    .name()
                    .unwrap_or_else(|_| format!("ordinal {ordinal}"))
            );
        }
        let device_name = context
            .name()
            .with_context(|| format!("query CUDA device name for ordinal {ordinal}"))?;
        let total_memory = context
            .total_mem()
            .with_context(|| format!("query CUDA memory capacity for {device_name}"))?;
        let stream = context.default_stream();
        let module = context
            .load_module(Ptx::from_src(PTX))
            .context("load the embedded precompiled Astatine CUDA PTX image")?;
        let function = module
            .load_function("astatine_cuda_sha256d_batch")
            .context("resolve the Astatine CUDA SHA-256d kernel entry point")?;

        let mut slots = Vec::with_capacity(CUDA_BUFFER_SLOTS);
        for slot_index in 0..CUDA_BUFFER_SLOTS {
            let input_device = stream
                .alloc_zeros::<u32>(CUDA_INPUT_WORDS)
                .with_context(|| format!("allocate bounded CUDA input buffer {slot_index}"))?;
            let output_device = stream
                .alloc_zeros::<u32>(CUDA_OUTPUT_WORDS)
                .with_context(|| format!("allocate bounded CUDA output buffer {slot_index}"))?;
            // Pinned host buffers permit bounded asynchronous transfers. Initialize every
            // word before any API returns a slice reference to the allocation.
            let mut input_host = unsafe {
                context.alloc_pinned_with_flags::<u32>(CUDA_INPUT_WORDS, PINNED_HOST_FLAGS)
            }
            .with_context(|| format!("allocate bounded pinned CUDA input buffer {slot_index}"))?;
            input_host
                .as_mut_slice()
                .context("initialize pinned CUDA input buffer")?
                .fill(0);
            let mut output_host = unsafe {
                context.alloc_pinned_with_flags::<u32>(CUDA_OUTPUT_WORDS, PINNED_HOST_FLAGS)
            }
            .with_context(|| format!("allocate bounded pinned CUDA result buffer {slot_index}"))?;
            output_host
                .as_mut_slice()
                .context("initialize pinned CUDA result buffer")?
                .fill(0);
            slots.push(CudaBufferSlot {
                input_device,
                output_device,
                input_host,
                output_host,
                completion: None,
                busy: false,
                submission_id: None,
            });
        }

        let driver_version_text = format!(
            "CUDA Driver API {} · compute capability {capability_major}.{capability_minor} · {:.1} GiB",
            driver_api_version_text(driver_version),
            total_memory as f64 / (1024.0 * 1024.0 * 1024.0),
        );
        let resources = CudaResources {
            _context: context,
            stream,
            _module: module,
            function,
            slots,
        };
        let info = GpuDeviceInfo {
            name: device_name,
            vendor: 0x10de,
            device_type: "NVIDIA CUDA compute device".to_owned(),
            backend: "CUDA Driver API".to_owned(),
            driver: "nvidia-cuda".to_owned(),
            driver_info: driver_version_text,
            timestamp_queries: false,
            sha256_midstate: midstate_enabled,
            batch_size,
            workgroup_size,
            tuned_hashes_per_second: 0,
            cpu_comparison_hashes_per_second: 0,
            cpu_comparison_threads: 0,
        };
        let mut engine = Self {
            resources: Some(resources),
            info,
            initialization: GpuInitializationTimings {
                device_request: started.elapsed(),
                ..GpuInitializationTimings::default()
            },
            batch_size,
            workgroup_size,
            midstate_enabled,
            next_slot: 0,
            next_submission_id: 0,
            poisoned: false,
        };
        let self_test_started = Instant::now();
        engine
            .self_test()
            .context("run CUDA canonical SHA-256d self-tests")?;
        engine.initialization.self_test = self_test_started.elapsed();
        if tune_batch {
            let tune_started = Instant::now();
            engine.tune_batch_size()?;
            engine.initialization.batch_tuning = tune_started.elapsed();
        }
        engine.initialization.total = started.elapsed();
        Ok(engine)
    }

    pub(super) fn info(&self) -> &GpuDeviceInfo {
        &self.info
    }

    pub(super) fn initialization_timings(&self) -> GpuInitializationTimings {
        self.initialization
    }

    pub(super) fn batch_size(&self) -> usize {
        self.batch_size
    }

    pub(super) fn record_cpu_comparison(&mut self, hashes_per_second: u64, threads: usize) {
        self.info.cpu_comparison_hashes_per_second = hashes_per_second;
        self.info.cpu_comparison_threads = threads;
    }

    pub(super) fn observe_batch_latency(&mut self, latency: Duration) -> Option<usize> {
        let reduced_size = super::reduced_gpu_batch_size(self.batch_size, latency)?;
        self.batch_size = reduced_size;
        self.info.batch_size = reduced_size;
        Some(reduced_size)
    }

    fn resources(&self) -> Result<&CudaResources> {
        self.resources
            .as_ref()
            .context("CUDA resources were quarantined after a driver failure")
    }

    fn resources_mut(&mut self) -> Result<&mut CudaResources> {
        self.resources
            .as_mut()
            .context("CUDA resources were quarantined after a driver failure")
    }

    pub(super) fn dispatch_batch(
        &mut self,
        hasher: &WorkHasher,
        first_nonce: u128,
        count: usize,
        target: U256,
        incumbent: Option<B256>,
        stop: &AtomicBool,
    ) -> Result<CudaPendingBatch> {
        self.dispatch_batch_with_profile(hasher, first_nonce, count, target, incumbent, stop)
    }

    pub(super) fn dispatch_batch_profiled(
        &mut self,
        hasher: &WorkHasher,
        first_nonce: u128,
        count: usize,
        target: U256,
        incumbent: Option<B256>,
        stop: &AtomicBool,
    ) -> Result<CudaPendingBatch> {
        self.dispatch_batch_with_profile(hasher, first_nonce, count, target, incumbent, stop)
    }

    fn dispatch_batch_with_profile(
        &mut self,
        hasher: &WorkHasher,
        first_nonce: u128,
        count: usize,
        target: U256,
        incumbent: Option<B256>,
        stop: &AtomicBool,
    ) -> Result<CudaPendingBatch> {
        let submitted_at = Instant::now();
        if self.poisoned {
            bail!("CUDA engine is quarantined after an earlier driver failure");
        }
        if stop.load(std::sync::atomic::Ordering::Acquire) {
            bail!("CUDA batch cancelled before dispatch");
        }
        if count == 0 || count > self.batch_size {
            bail!("CUDA batch count must be within 1..={}", self.batch_size);
        }
        first_nonce
            .checked_add(u128::try_from(count - 1)?)
            .context("CUDA nonce batch would overflow the u128 nonce space")?;
        let workgroup_size = usize::try_from(self.workgroup_size)?;
        if !workgroup_size.is_power_of_two() || workgroup_size > CUDA_MAX_WORKGROUP_SIZE {
            bail!("CUDA workgroup size is outside its supported power-of-two range");
        }
        let workgroup_count = count.div_ceil(workgroup_size);
        if workgroup_count > MAX_GPU_OUTPUT_GROUPS {
            bail!("CUDA dispatch exceeds the bounded result buffer");
        }
        let host_preparation_started = Instant::now();
        let input_words = encode_batch_input(
            hasher,
            first_nonce,
            count,
            target,
            incumbent,
            self.midstate_enabled,
        )?;
        let host_preparation = host_preparation_started.elapsed();
        let slot_index = self.next_slot;
        let submission_id = self.next_submission_id;
        let launch_workgroup_size = self.workgroup_size;
        self.next_submission_id = self
            .next_submission_id
            .checked_add(1)
            .context("CUDA submission identity overflow")?;

        self.poisoned = true;
        let timings = (|| -> Result<GpuBatchTimings> {
            let resources = self.resources_mut()?;
            let slot = &mut resources.slots[slot_index];
            if slot.busy || slot.completion.is_some() {
                bail!("CUDA pipeline attempted to reuse an in-flight buffer slot");
            }

            // Any error after this point is treated as an uncertain asynchronous driver
            // state. `Drop` will quarantine, rather than free, buffers that may still be in use.
            slot.busy = true;
            slot.submission_id = Some(submission_id);

            let upload_started = Instant::now();
            let host_input = slot
                .input_host
                .as_mut_slice()
                .context("wait for the prior CUDA host-input transfer")?;
            host_input.fill(0);
            host_input[..input_words.len()].copy_from_slice(&input_words);
            resources
                .stream
                .memcpy_htod(&slot.input_host, &mut slot.input_device)
                .context("copy canonical CUDA batch input to device")?;
            let upload_enqueue = upload_started.elapsed();

            let encoding_started = Instant::now();
            let launch_config = LaunchConfig {
                grid_dim: (u32::try_from(workgroup_count)?, 1, 1),
                block_dim: (launch_workgroup_size, 1, 1),
                shared_mem_bytes: 0,
            };
            let mut launch = resources.stream.launch_builder(&resources.function);
            launch.arg(&slot.input_device);
            launch.arg(&mut slot.output_device);
            unsafe { launch.launch(launch_config) }
                .context("enqueue the precompiled CUDA SHA-256d kernel")?;
            let command_encoding = encoding_started.elapsed();

            let submit_started = Instant::now();
            let completion = resources
                .stream
                .record_event(None)
                .context("record CUDA kernel completion event")?;
            let queue_submit = submit_started.elapsed();
            slot.completion = Some(completion);
            Ok(GpuBatchTimings {
                host_preparation,
                upload_enqueue,
                command_encoding,
                queue_submit,
                ..GpuBatchTimings::default()
            })
        })();
        let timings = timings?;

        self.poisoned = false;
        self.next_slot = (slot_index + 1) % CUDA_BUFFER_SLOTS;
        Ok(CudaPendingBatch {
            slot_index,
            submission_id,
            first_nonce,
            count,
            workgroup_size,
            workgroup_count,
            submitted_at,
            timings,
        })
    }

    pub(super) fn collect_batch(
        &mut self,
        pending: CudaPendingBatch,
        stop: Option<&AtomicBool>,
    ) -> Result<GpuBatchResult> {
        if self.poisoned {
            bail!("CUDA engine is quarantined after an earlier driver failure");
        }
        let event_result = {
            let resources = self.resources()?;
            let slot = resources
                .slots
                .get(pending.slot_index)
                .context("CUDA pending batch names an invalid buffer slot")?;
            if !slot.busy || slot.submission_id != Some(pending.submission_id) {
                bail!("CUDA pending batch identity was duplicated or does not match its slot");
            }
            let event = slot
                .completion
                .as_ref()
                .context("CUDA pending batch has no recorded completion event")?;
            wait_for_event(event, CUDA_DISPATCH_TIMEOUT)
        };
        let queue_wait = match event_result {
            Ok(elapsed) => elapsed,
            Err(error) => {
                self.poisoned = true;
                return Err(error).context("wait for CUDA kernel completion");
            }
        };

        if stop.is_some_and(|stop| stop.load(std::sync::atomic::Ordering::Acquire)) {
            self.release_completed_slot(pending.slot_index, pending.submission_id)?;
            bail!("CUDA batch cancelled after the kernel reached a safe completion point");
        }

        let readback_started = Instant::now();
        let transfer = (|| -> Result<(usize, CudaEvent)> {
            let resources = self.resources_mut()?;
            let slot = &mut resources.slots[pending.slot_index];
            // The kernel completion event is complete, so removing it cannot free an
            // in-use result buffer. Keep the slot busy until the DtoH event also completes.
            slot.completion.take();
            let words_to_copy = pending
                .workgroup_count
                .checked_mul(CUDA_RESULT_WORDS)
                .context("CUDA result copy size overflow")?;
            let output_view = slot.output_device.slice(0..words_to_copy);
            resources
                .stream
                .memcpy_dtoh(&output_view, &mut slot.output_host)
                .context("enqueue CUDA result transfer to pinned host memory")?;
            let copy_event = resources
                .stream
                .record_event(None)
                .context("record CUDA result-transfer completion event")?;
            Ok((words_to_copy, copy_event))
        })();
        let (words_to_copy, copy_event) = match transfer {
            Ok(transfer) => transfer,
            Err(error) => {
                self.poisoned = true;
                return Err(error);
            }
        };
        if let Err(error) = wait_for_event(&copy_event, CUDA_DISPATCH_TIMEOUT) {
            self.poisoned = true;
            std::mem::forget(copy_event);
            return Err(error).context("wait for CUDA result transfer");
        }
        drop(copy_event);
        let copied_words = {
            let resources = self.resources()?;
            let slot = &resources.slots[pending.slot_index];
            let output = match slot.output_host.as_slice() {
                Ok(output) => output,
                Err(error) => {
                    self.poisoned = true;
                    return Err(error).context("read completed pinned CUDA result buffer");
                }
            };
            output[..words_to_copy].to_vec()
        };
        let mapped_bytes_copy = readback_started.elapsed();
        self.release_completed_slot(pending.slot_index, pending.submission_id)?;
        let result_decode_started = Instant::now();
        let candidates = decode_batch_results(
            &copied_words,
            pending.first_nonce,
            pending.count,
            pending.workgroup_size,
        )?;
        let result_decode = result_decode_started.elapsed();

        let mut timings = pending.timings;
        timings.queue_wait = queue_wait;
        timings.map_request = readback_started.elapsed();
        timings.mapped_bytes_copy = mapped_bytes_copy;
        timings.result_decode = result_decode;
        timings.submission_to_readback = pending.submitted_at.elapsed();
        Ok(GpuBatchResult {
            completed_hashes: pending.count,
            candidates,
            workgroup_size: pending.workgroup_size,
            workgroup_count: pending.workgroup_count,
            timings,
        })
    }

    fn release_completed_slot(&mut self, slot_index: usize, submission_id: u64) -> Result<()> {
        let slot = self
            .resources_mut()?
            .slots
            .get_mut(slot_index)
            .context("CUDA pending batch names an invalid buffer slot")?;
        if !slot.busy || slot.submission_id != Some(submission_id) {
            bail!("CUDA buffer slot changed before its completion was collected");
        }
        slot.completion.take();
        slot.busy = false;
        slot.submission_id = None;
        Ok(())
    }

    pub(super) fn hash_batch(
        &mut self,
        hasher: &WorkHasher,
        first_nonce: u128,
        count: usize,
        target: U256,
        incumbent: Option<B256>,
        stop: Option<&AtomicBool>,
    ) -> Result<GpuBatchResult> {
        let stop_default = AtomicBool::new(false);
        let stop = stop.unwrap_or(&stop_default);
        let pending = self.dispatch_batch(hasher, first_nonce, count, target, incumbent, stop)?;
        self.collect_batch(pending, Some(stop))
    }

    pub(super) fn hash_batch_profiled(
        &mut self,
        hasher: &WorkHasher,
        first_nonce: u128,
        count: usize,
        target: U256,
        incumbent: Option<B256>,
    ) -> Result<GpuBatchResult> {
        let stop = AtomicBool::new(false);
        let pending =
            self.dispatch_batch_profiled(hasher, first_nonce, count, target, incumbent, &stop)?;
        self.collect_batch(pending, Some(&stop))
    }

    fn tune_batch_size(&mut self) -> Result<usize> {
        const MAX_RESPONSIVE_BATCH: Duration = Duration::from_millis(100);
        const SAMPLES_PER_SIZE: usize = 3;
        let context = canonical_benchmark_context()?;
        let hasher = WorkHasher::new(&context)?;
        let mut measurements = Vec::with_capacity(GPU_BATCH_SIZES.len());
        let mut first_nonce = self.initialization.batch_tuning_nonce_count;
        for batch_size in GPU_BATCH_SIZES {
            let mut sample_durations = Vec::with_capacity(SAMPLES_PER_SIZE);
            for _ in 0..SAMPLES_PER_SIZE {
                let started = Instant::now();
                let batch =
                    self.hash_batch(&hasher, first_nonce, batch_size, U256::MAX, None, None)?;
                verify_benchmark_batch(&hasher, first_nonce, batch_size, &batch)?;
                sample_durations.push(started.elapsed());
                first_nonce = first_nonce
                    .checked_add(u128::try_from(batch_size)?)
                    .context("CUDA batch tuner nonce range overflow")?;
            }
            sample_durations.sort_unstable();
            let median = sample_durations[SAMPLES_PER_SIZE / 2];
            if median <= MAX_RESPONSIVE_BATCH {
                measurements.push((
                    batch_size,
                    median,
                    batch_size as f64 / median.as_secs_f64().max(0.000_001),
                ));
            }
        }
        let Some(best_rate) = measurements
            .iter()
            .map(|(_, _, rate)| *rate)
            .reduce(f64::max)
        else {
            bail!("no bounded CUDA batch completed within the 100 ms responsiveness limit");
        };
        let (selected_size, _, selected_rate) = measurements
            .iter()
            .filter(|(_, _, rate)| *rate >= best_rate * 0.95)
            .max_by_key(|(size, _, _)| *size)
            .copied()
            .context("no measured CUDA batch met the throughput threshold")?;
        self.batch_size = selected_size;
        self.info.batch_size = selected_size;
        self.info.tuned_hashes_per_second = selected_rate.round() as u64;
        self.initialization.batch_tuning_nonce_count = first_nonce;
        Ok(selected_size)
    }

    fn self_test(&mut self) -> Result<()> {
        let mut context = WorkContext {
            chain_id: 31_337,
            contract: "0x1234567890abcdef1234567890abcdef12345678".parse()?,
            window_id: 42,
            seed: "0x1111111111111111111111111111111111111111111111111111111111111111".parse()?,
            miner: "0x1111111111111111111111111111111111111111".parse()?,
            header: alloy_primitives::hex::decode("4153544154494e4500ff")?,
        };
        let canonical_nonce = 1_339_673_755_198_158_349_044_581_307_228_491_536_u128;
        let canonical_hash: B256 =
            "0x373d4c8d0a1f1dc9efd7e2e5d1a576718b65713f3d006f2a584cc722082323ec".parse()?;
        let hasher = WorkHasher::new(&context)?;
        if hasher.hash(canonical_nonce) != canonical_hash {
            bail!("canonical Rust work-vector setup does not match the Solidity fixture");
        }
        let previous_midstate_mode = self.midstate_enabled;
        for use_midstate in [false, true] {
            self.midstate_enabled = use_midstate;
            let vector = self.hash_batch(&hasher, canonical_nonce, 1, U256::MAX, None, None)?;
            super::assert_single_candidate(&vector, canonical_nonce, canonical_hash)?;
        }
        self.midstate_enabled = previous_midstate_mode;

        let exact_target = U256::from_be_bytes(canonical_hash.0);
        let accepted = self.hash_batch(&hasher, canonical_nonce, 1, exact_target, None, None)?;
        super::assert_single_candidate(&accepted, canonical_nonce, canonical_hash)?;
        let below_target = exact_target
            .checked_sub(U256::from(1))
            .context("canonical vector hash cannot be zero")?;
        if !self
            .hash_batch(&hasher, canonical_nonce, 1, below_target, None, None)?
            .candidates
            .is_empty()
        {
            bail!("CUDA accepted a hash above a strict lower target");
        }
        if !self
            .hash_batch(&hasher, canonical_nonce, 1, U256::ZERO, None, None)?
            .candidates
            .is_empty()
        {
            bail!("CUDA accepted a nonzero hash at the zero target");
        }
        let mut leading_zero_target_bytes = [0xff_u8; 32];
        leading_zero_target_bytes[0] = 0;
        if !self
            .hash_batch(
                &hasher,
                canonical_nonce,
                1,
                U256::from_be_bytes(leading_zero_target_bytes),
                None,
                None,
            )?
            .candidates
            .is_empty()
        {
            bail!("CUDA full-width target comparison ignored leading zero bytes");
        }
        let mut high_bit_target_bytes = [0_u8; 32];
        high_bit_target_bytes[0] = 0x80;
        let high_bit = self.hash_batch(
            &hasher,
            canonical_nonce,
            1,
            U256::from_be_bytes(high_bit_target_bytes),
            None,
            None,
        )?;
        super::assert_single_candidate(&high_bit, canonical_nonce, canonical_hash)?;
        if !self
            .hash_batch(
                &hasher,
                canonical_nonce,
                1,
                U256::MAX,
                Some(canonical_hash),
                None,
            )?
            .candidates
            .is_empty()
        {
            bail!("CUDA accepted a hash equal to its incumbent");
        }
        let greater_incumbent = B256::from(
            exact_target
                .checked_add(U256::from(1))
                .context("canonical vector hash cannot be maximum")?
                .to_be_bytes::<32>(),
        );
        let greater = self.hash_batch(
            &hasher,
            canonical_nonce,
            1,
            U256::MAX,
            Some(greater_incumbent),
            None,
        )?;
        super::assert_single_candidate(&greater, canonical_nonce, canonical_hash)?;

        let reduction_count = self.workgroup_size as usize * 4;
        let reduced = self.hash_batch(
            &hasher,
            canonical_nonce,
            reduction_count,
            U256::MAX,
            None,
            None,
        )?;
        let expected_reduction = super::cpu_group_winners(
            &hasher,
            canonical_nonce,
            reduction_count,
            U256::MAX,
            None,
            self.workgroup_size as usize,
        )?;
        if reduced.completed_hashes != reduction_count || reduced.candidates != expected_reduction {
            bail!("CUDA multi-workgroup reduction differs from the canonical CPU minima");
        }

        for (first_nonce, count) in [
            (0_u128, 2_usize),
            (u128::from(u32::MAX) - 1, 4),
            (u128::from(u64::MAX) - 1, 4),
            (u128::MAX - 1, 2),
        ] {
            let results = self.hash_batch(&hasher, first_nonce, count, U256::MAX, None, None)?;
            let expected = super::cpu_group_winners(
                &hasher,
                first_nonce,
                count,
                U256::MAX,
                None,
                self.workgroup_size as usize,
            )?;
            if results.completed_hashes != count || results.candidates != expected {
                bail!("CUDA nonce boundary or workgroup reduction differential failed");
            }
        }

        for header_length in [0, 1, 55, 56, 63, 64, 119, 120, MAX_HEADER_LENGTH] {
            context.header = (0..header_length)
                .map(|index| (index as u8).wrapping_mul(37))
                .collect();
            let header_hasher = WorkHasher::new(&context)?;
            let nonce = u128::MAX - u128::try_from(header_length)?;
            let result = self.hash_batch(&header_hasher, nonce, 1, U256::MAX, None, None)?;
            super::assert_single_candidate(&result, nonce, header_hasher.hash(nonce))?;
        }

        for index in 0..16_u8 {
            let mut seed = [0_u8; 32];
            for (byte_index, byte) in seed.iter_mut().enumerate() {
                *byte = (byte_index as u8)
                    .wrapping_mul(17)
                    .wrapping_add(index.wrapping_mul(29));
            }
            let differential_context = WorkContext {
                chain_id: 31_337 + u64::from(index),
                contract: Address::with_last_byte(index.wrapping_add(1)),
                window_id: 1_000 + u64::from(index),
                seed: B256::new(seed),
                miner: Address::with_last_byte(index.wrapping_add(33)),
                header: (0..usize::from(index) * 7)
                    .map(|byte_index| (byte_index as u8).wrapping_mul(23).wrapping_add(index))
                    .collect(),
            };
            let differential_hasher = WorkHasher::new(&differential_context)?;
            let first_nonce = match index % 4 {
                0 => (u128::from(index)) << 96,
                1 => u128::from(u32::MAX) - 15,
                2 => u128::from(u64::MAX) - 15,
                _ => u128::MAX - 31,
            };
            let count = 32;
            let result = self.hash_batch(
                &differential_hasher,
                first_nonce,
                count,
                U256::MAX,
                None,
                None,
            )?;
            let expected = super::cpu_group_winners(
                &differential_hasher,
                first_nonce,
                count,
                U256::MAX,
                None,
                self.workgroup_size as usize,
            )?;
            if result.completed_hashes != count || result.candidates != expected {
                bail!("CUDA deterministic multi-context differential test failed");
            }
        }
        Ok(())
    }
}

fn wait_for_event(event: &CudaEvent, timeout: Duration) -> Result<Duration> {
    let started = Instant::now();
    let deadline = started
        .checked_add(timeout)
        .context("CUDA event deadline overflow")?;
    wait_for_event_until(event, deadline)?;
    Ok(started.elapsed())
}

fn wait_for_event_until(event: &CudaEvent, deadline: Instant) -> Result<()> {
    loop {
        match event
            .try_is_complete()
            .context("query CUDA event completion")?
        {
            true => return Ok(()),
            false if Instant::now() < deadline => thread::sleep(CUDA_POLL_INTERVAL),
            false => bail!("CUDA work exceeded its bounded completion deadline"),
        }
    }
}

pub(super) fn driver_api_version_text(version: i32) -> String {
    format!("{}.{}", version / 1_000, (version % 1_000) / 10)
}

#[cfg(test)]
mod tests {
    use super::{CudaEngine, driver_api_version_text};
    use crate::gpu::{GPU_BATCH_SIZE, GPU_WORKGROUP_SIZE};

    #[test]
    fn cuda_driver_api_compatibility_requires_cuda_12_driver_level() {
        assert_eq!(driver_api_version_text(12_000), "12.0");
        assert_eq!(driver_api_version_text(12_080), "12.8");
    }

    #[test]
    fn cuda_driver_probe_returns_a_result_without_panicking() {
        let result = CudaEngine::driver_device_count();
        if let Ok(Some((driver_version, device_count))) = result {
            assert!(driver_version > 0);
            assert!(device_count <= i32::MAX as usize);
        }
    }

    #[test]
    #[ignore = "requires physical NVIDIA hardware and an installed CUDA driver"]
    fn physical_cuda_executes_canonical_sha256d_and_u128_differential_tests() {
        let mut engine = CudaEngine::initialize(GPU_BATCH_SIZE, GPU_WORKGROUP_SIZE, true, false)
            .expect("physical NVIDIA CUDA device and compatible driver are available");
        engine.self_test().unwrap();
    }
}
