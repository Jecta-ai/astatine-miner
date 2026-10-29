use alloy_primitives::{B256, U256, hex};
use anyhow::{Context, Result, anyhow, bail};
use sha2::{Digest, Sha256};
use std::{
    collections::HashSet,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    thread,
    time::{Duration, Instant},
};
use wgpu::{
    Adapter, AdapterInfo, Backends, Buffer, BufferDescriptor, BufferUsages, Device,
    DeviceDescriptor, DeviceType, Instance, InstanceDescriptor, MapMode, MemoryHints, PollType,
    QuerySet, Queue, ShaderSource,
};

use crate::cli::BenchmarkArgs;
use crate::protocol::{MAX_HEADER_LENGTH, WorkContext, WorkHasher};

mod benchmark;

const ABI_SHA256_PREFIX_BYTES: usize = 192;
const INPUT_HEADER_WORDS: usize = 31;
const MAX_ABI_TEMPLATE_BYTES: usize = 288 + MAX_HEADER_LENGTH.div_ceil(32) * 32;
const MAX_ABI_TEMPLATE_WORDS: usize = MAX_ABI_TEMPLATE_BYTES / 4;
const RESULT_WORDS: usize = 13;
const MIN_WORKGROUP_SIZE: usize = 32;
pub(crate) const MAX_GPU_BATCH_SIZE: usize = 262_144;
const MAX_GPU_OUTPUT_GROUPS: usize = MAX_GPU_BATCH_SIZE.div_ceil(MIN_WORKGROUP_SIZE);
const RESULT_BUFFER_BYTES: usize = MAX_GPU_OUTPUT_GROUPS * RESULT_WORDS * 4;
const TIMESTAMP_QUERY_COUNT: u32 = 4;
const TIMESTAMP_QUERY_BYTES: usize = TIMESTAMP_QUERY_COUNT as usize * 8;
const QUERY_RESOLVE_ALIGNMENT: usize = wgpu::QUERY_RESOLVE_BUFFER_ALIGNMENT as usize;
const PROFILE_TIMESTAMP_FEATURES: wgpu::Features = wgpu::Features::TIMESTAMP_QUERY
    .union(wgpu::Features::TIMESTAMP_QUERY_INSIDE_ENCODERS)
    .union(wgpu::Features::TIMESTAMP_QUERY_INSIDE_PASSES);
const INPUT_BUFFER_BYTES: usize = (INPUT_HEADER_WORDS + MAX_ABI_TEMPLATE_WORDS) * 4;
const GPU_DISPATCH_TIMEOUT: Duration = Duration::from_secs(15);
const GPU_POLL_WAIT_QUANTUM: Duration = Duration::from_millis(2);
const SELF_TEST_TIMEOUT: Duration = Duration::from_secs(20);
const GPU_BATCH_SIZES: [usize; 7] = [2_048, 8_192, 16_384, 32_768, 65_536, 131_072, 262_144];

pub(crate) const GPU_BATCH_SIZE: usize = 2_048;
pub(crate) const GPU_WORKGROUP_SIZE: u32 = 32;
const SUPPORTED_WORKGROUP_SIZES: [u32; 4] = [32, 64, 128, 256];

const WGSL: &str = include_str!("shader.wgsl");

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct GpuDeviceInfo {
    pub(crate) name: String,
    pub(crate) vendor: u32,
    pub(crate) device_type: String,
    pub(crate) backend: String,
    pub(crate) driver: String,
    pub(crate) driver_info: String,
    pub(crate) timestamp_queries: bool,
    pub(crate) sha256_midstate: bool,
    pub(crate) batch_size: usize,
    pub(crate) workgroup_size: u32,
    pub(crate) tuned_hashes_per_second: u64,
    pub(crate) cpu_comparison_hashes_per_second: u64,
    pub(crate) cpu_comparison_threads: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct GpuCandidate {
    pub(crate) nonce: u128,
    pub(crate) hash: B256,
    pub(crate) workgroup_index: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct GpuBatchIdentity {
    pub(crate) node_id: u8,
    pub(crate) generation: u64,
    pub(crate) window_id: u64,
    pub(crate) first_nonce: u128,
    pub(crate) nonce_count: usize,
}

impl GpuBatchIdentity {
    pub(crate) fn contains(self, nonce: u128) -> bool {
        nonce
            .checked_sub(self.first_nonce)
            .is_some_and(|offset| offset < self.nonce_count as u128)
    }
}

#[derive(Debug)]
pub(crate) struct GpuBatchResult {
    pub(crate) completed_hashes: usize,
    pub(crate) candidates: Vec<GpuCandidate>,
    pub(crate) workgroup_size: usize,
    pub(crate) workgroup_count: usize,
    pub(crate) timings: GpuBatchTimings,
}

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct GpuBatchTimings {
    pub(crate) host_preparation: Duration,
    pub(crate) upload_enqueue: Duration,
    pub(crate) command_encoding: Duration,
    pub(crate) queue_submit: Duration,
    pub(crate) queue_wait: Duration,
    pub(crate) map_request: Duration,
    pub(crate) mapped_bytes_copy: Duration,
    pub(crate) result_decode: Duration,
    pub(crate) submission_to_readback: Duration,
    pub(crate) gpu_compute: Option<Duration>,
    pub(crate) gpu_output_copy: Option<Duration>,
}

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct GpuInitializationTimings {
    pub(crate) shader_validation: Duration,
    pub(crate) adapter_enumeration: Duration,
    pub(crate) device_request: Duration,
    pub(crate) pipeline_creation: Duration,
    pub(crate) self_test: Duration,
    pub(crate) batch_tuning: Duration,
    pub(crate) batch_tuning_nonce_count: u128,
    pub(crate) total: Duration,
}

struct TimestampResources {
    query_set: QuerySet,
    resolve_buffer: Buffer,
}

struct MappedReadback {
    bytes: Vec<u8>,
    map_request: Duration,
    queue_wait: Duration,
    mapped_copy: Duration,
}

struct GpuBatchParams<'a> {
    hasher: &'a WorkHasher,
    first_nonce: u128,
    count: usize,
    target: U256,
    incumbent: Option<B256>,
    stop: Option<&'a AtomicBool>,
    profile: bool,
}

pub(crate) struct PendingGpuBatch {
    readback_slot: usize,
    first_nonce: u128,
    count: usize,
    workgroup_size: usize,
    workgroup_count: usize,
    bytes_to_map: usize,
    timestamp_offset: Option<usize>,
    submission: wgpu::SubmissionIndex,
    submitted_at: Instant,
    timings: GpuBatchTimings,
}

pub(crate) struct GpuEngine {
    _instance: Instance,
    device: Device,
    queue: Queue,
    pipeline: wgpu::ComputePipeline,
    raw_sha_pipeline: wgpu::ComputePipeline,
    input: Buffer,
    output: Buffer,
    readback: [Buffer; 2],
    info: GpuDeviceInfo,
    timestamps: Option<[TimestampResources; 2]>,
    initialization: GpuInitializationTimings,
    batch_size: usize,
    workgroup_size: u32,
    midstate_enabled: bool,
    next_readback_slot: usize,
    readback_in_flight: [bool; 2],
    device_lost: Arc<AtomicBool>,
    uncaptured_error: Arc<Mutex<Option<String>>>,
}

impl GpuEngine {
    pub(crate) fn initialize() -> Result<Self> {
        Self::initialize_with_config(MAX_GPU_BATCH_SIZE, GPU_WORKGROUP_SIZE, true, false, true)
    }

    pub(crate) fn initialize_auto_profiled() -> Result<Self> {
        Self::initialize_with_config(MAX_GPU_BATCH_SIZE, GPU_WORKGROUP_SIZE, true, true, true)
    }

    pub(crate) fn initialize_profiled(batch_size: usize, workgroup_size: u32) -> Result<Self> {
        Self::initialize_profiled_mode(batch_size, workgroup_size, true)
    }

    pub(crate) fn initialize_profiled_mode(
        batch_size: usize,
        workgroup_size: u32,
        midstate_enabled: bool,
    ) -> Result<Self> {
        Self::initialize_with_config(batch_size, workgroup_size, midstate_enabled, true, false)
    }

    fn initialize_with_config(
        batch_size: usize,
        workgroup_size: u32,
        midstate_enabled: bool,
        timestamp_profile: bool,
        tune_batch: bool,
    ) -> Result<Self> {
        validate_gpu_config(batch_size, workgroup_size)?;
        let started = Instant::now();
        let mut engine = pollster::block_on(Self::initialize_async(
            batch_size,
            workgroup_size,
            midstate_enabled,
            timestamp_profile,
            tune_batch,
        ))?;
        engine.initialization.total = started.elapsed();
        Ok(engine)
    }

    async fn initialize_async(
        batch_size: usize,
        workgroup_size: u32,
        midstate_enabled: bool,
        timestamp_profile: bool,
        tune_batch: bool,
    ) -> Result<Self> {
        let validation_started = Instant::now();
        validate_shader()?;
        let shader_validation = validation_started.elapsed();
        let enumeration_started = Instant::now();
        let instance = Instance::new(InstanceDescriptor::new_without_display_handle());
        let mut adapters = instance.enumerate_adapters(Backends::all()).await;
        let adapter_enumeration = enumeration_started.elapsed();
        adapters.sort_by_key(|adapter| adapter_priority(&adapter.get_info()));

        let mut failures = Vec::new();
        for adapter in adapters {
            let adapter_info = adapter.get_info();
            if is_software_adapter(&adapter_info) {
                continue;
            }
            match Self::from_adapter(
                instance.clone(),
                adapter,
                adapter_info.clone(),
                batch_size,
                workgroup_size,
                midstate_enabled,
                timestamp_profile,
            )
            .await
            {
                Ok(mut engine) => {
                    engine.initialization.shader_validation = shader_validation;
                    engine.initialization.adapter_enumeration = adapter_enumeration;
                    let self_test_started = Instant::now();
                    match engine.self_test() {
                        Ok(()) => {
                            engine.initialization.self_test = self_test_started.elapsed();
                            if tune_batch {
                                let tuning_started = Instant::now();
                                let tuning_context = canonical_benchmark_context()?;
                                let tuning_hasher = WorkHasher::new(&tuning_context)?;
                                engine.tune_batch_size(&tuning_hasher)?;
                                engine.initialization.batch_tuning = tuning_started.elapsed();
                            }
                            return Ok(engine);
                        }
                        Err(error) => {
                            failures.push(format!(
                                "{} ({:?}): GPU SHA-256d self-test failed: {error:#}",
                                engine.info.name, engine.info.backend
                            ));
                        }
                    }
                }
                Err(error) => failures.push(format!(
                    "{} ({:?}): {error:#}",
                    adapter_info.name, adapter_info.backend
                )),
            }
        }

        if failures.is_empty() {
            bail!("no compatible physical GPU adapter was found");
        }
        bail!(
            "no physical GPU passed the Astatine SHA-256d self-test: {}",
            failures.join("; ")
        )
    }

    async fn from_adapter(
        instance: Instance,
        adapter: Adapter,
        adapter_info: AdapterInfo,
        batch_size: usize,
        workgroup_size: u32,
        midstate_enabled: bool,
        timestamp_profile: bool,
    ) -> Result<Self> {
        let limits = adapter.limits();
        if limits.max_compute_workgroup_size_x < workgroup_size
            || limits.max_compute_invocations_per_workgroup < workgroup_size
            || limits.max_compute_workgroups_per_dimension == 0
        {
            bail!(
                "adapter does not support the selected {workgroup_size}-invocation compute workgroup"
            );
        }
        let input_bytes = u64::try_from(INPUT_BUFFER_BYTES)?;
        let result_bytes = u64::try_from(RESULT_BUFFER_BYTES)?;
        let readback_bytes = result_bytes
            .checked_add(QUERY_RESOLVE_ALIGNMENT as u64)
            .and_then(|bytes| bytes.checked_add(TIMESTAMP_QUERY_BYTES as u64))
            .context("GPU profiling readback-buffer size overflow")?;
        if limits.max_storage_buffer_binding_size < input_bytes
            || limits.max_storage_buffer_binding_size < result_bytes
            || limits.max_buffer_size < input_bytes.max(result_bytes)
        {
            bail!("adapter storage-buffer limits are below the bounded Astatine batch buffers");
        }

        let timestamp_queries = adapter.features().contains(PROFILE_TIMESTAMP_FEATURES);
        let requested_features = if timestamp_profile && timestamp_queries {
            PROFILE_TIMESTAMP_FEATURES
        } else {
            wgpu::Features::empty()
        };
        let device_request_started = Instant::now();
        let (device, queue) = adapter
            .request_device(&DeviceDescriptor {
                label: Some("Astatine SHA-256d compute device"),
                required_features: requested_features,
                required_limits: wgpu::Limits::downlevel_defaults(),
                experimental_features: wgpu::ExperimentalFeatures::disabled(),
                memory_hints: MemoryHints::MemoryUsage,
                trace: wgpu::Trace::Off,
            })
            .await
            .context("request a wgpu compute device")?;
        let device_request = device_request_started.elapsed();

        let uncaptured_error = Arc::new(Mutex::new(None::<String>));
        let error_slot = Arc::clone(&uncaptured_error);
        device.on_uncaptured_error(Arc::new(move |error| {
            *error_slot
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(error.to_string());
        }));
        let device_lost = Arc::new(AtomicBool::new(false));
        let lost_flag = Arc::clone(&device_lost);
        device.set_device_lost_callback(move |_reason, _message| {
            lost_flag.store(true, Ordering::Release);
        });

        let input = device.create_buffer(&BufferDescriptor {
            label: Some("Astatine canonical work and dispatch parameters"),
            size: input_bytes,
            usage: BufferUsages::STORAGE | BufferUsages::COPY_DST,
            mapped_at_creation: false,
        });
        let output = device.create_buffer(&BufferDescriptor {
            label: Some("Astatine bounded per-invocation results"),
            size: result_bytes,
            usage: BufferUsages::STORAGE | BufferUsages::COPY_SRC,
            mapped_at_creation: false,
        });
        let readback = std::array::from_fn(|slot| {
            device.create_buffer(&BufferDescriptor {
                label: Some(if slot == 0 {
                    "Astatine bounded compute readback A"
                } else {
                    "Astatine bounded compute readback B"
                }),
                size: readback_bytes,
                usage: BufferUsages::COPY_DST | BufferUsages::MAP_READ,
                mapped_at_creation: false,
            })
        });

        let pipeline_started = Instant::now();
        let shader = device.create_shader_module(wgpu::ShaderModuleDescriptor {
            label: Some("Astatine canonical SHA-256d WGSL"),
            source: ShaderSource::Wgsl(WGSL.into()),
        });
        let pipeline_constants = [
            ("WORKGROUP_SIZE", f64::from(workgroup_size)),
            ("USE_MIDSTATE", f64::from(u8::from(midstate_enabled))),
        ];
        let error_scope = device.push_error_scope(wgpu::ErrorFilter::Validation);
        let pipeline = device.create_compute_pipeline(&wgpu::ComputePipelineDescriptor {
            label: Some("Astatine SHA-256d pipeline"),
            layout: None,
            module: &shader,
            entry_point: Some("main"),
            compilation_options: wgpu::PipelineCompilationOptions {
                constants: &pipeline_constants,
                zero_initialize_workgroup_memory: false,
            },
            cache: None,
        });
        let raw_sha_pipeline = device.create_compute_pipeline(&wgpu::ComputePipelineDescriptor {
            label: Some("Astatine raw SHA-256 boundary-test pipeline"),
            layout: None,
            module: &shader,
            entry_point: Some("sha256_raw_test"),
            compilation_options: Default::default(),
            cache: None,
        });
        let _ = device.poll(PollType::Wait {
            submission_index: None,
            timeout: Some(SELF_TEST_TIMEOUT),
        });
        if let Some(error) = pollster::block_on(error_scope.pop()) {
            bail!("wgpu rejected the Astatine SHA-256d compute pipeline: {error}");
        }
        let pipeline_creation = pipeline_started.elapsed();

        let timestamps = (timestamp_profile && timestamp_queries).then(|| {
            std::array::from_fn(|slot| {
                let query_set = device.create_query_set(&wgpu::QuerySetDescriptor {
                    label: Some(if slot == 0 {
                        "Astatine GPU profile timestamps A"
                    } else {
                        "Astatine GPU profile timestamps B"
                    }),
                    ty: wgpu::QueryType::Timestamp,
                    count: TIMESTAMP_QUERY_COUNT,
                });
                let resolve_buffer = device.create_buffer(&BufferDescriptor {
                    label: Some(if slot == 0 {
                        "Astatine GPU profile timestamp resolve A"
                    } else {
                        "Astatine GPU profile timestamp resolve B"
                    }),
                    size: TIMESTAMP_QUERY_BYTES as u64,
                    usage: BufferUsages::QUERY_RESOLVE | BufferUsages::COPY_SRC,
                    mapped_at_creation: false,
                });
                TimestampResources {
                    query_set,
                    resolve_buffer,
                }
            })
        });

        let info = GpuDeviceInfo {
            name: adapter_info.name,
            vendor: adapter_info.vendor,
            device_type: format!("{:?}", adapter_info.device_type),
            backend: format!("{:?}", adapter_info.backend),
            driver: adapter_info.driver,
            driver_info: adapter_info.driver_info,
            timestamp_queries,
            sha256_midstate: midstate_enabled,
            batch_size,
            workgroup_size,
            tuned_hashes_per_second: 0,
            cpu_comparison_hashes_per_second: 0,
            cpu_comparison_threads: 0,
        };
        Ok(Self {
            _instance: instance,
            device,
            queue,
            pipeline,
            raw_sha_pipeline,
            input,
            output,
            readback,
            info,
            timestamps,
            batch_size,
            workgroup_size,
            midstate_enabled,
            next_readback_slot: 0,
            readback_in_flight: [false, false],
            initialization: GpuInitializationTimings {
                device_request,
                pipeline_creation,
                ..GpuInitializationTimings::default()
            },
            device_lost,
            uncaptured_error,
        })
    }

    pub(crate) fn info(&self) -> &GpuDeviceInfo {
        &self.info
    }

    pub(crate) fn record_cpu_comparison(&mut self, hashes_per_second: u64, threads: usize) {
        self.info.cpu_comparison_hashes_per_second = hashes_per_second;
        self.info.cpu_comparison_threads = threads;
    }

    pub(crate) fn observe_batch_latency(&mut self, latency: Duration) -> Option<usize> {
        let reduced_size = reduced_gpu_batch_size(self.batch_size, latency)?;
        self.batch_size = reduced_size;
        self.info.batch_size = reduced_size;
        Some(reduced_size)
    }

    pub(crate) fn initialization_timings(&self) -> GpuInitializationTimings {
        self.initialization
    }

    pub(crate) fn batch_size(&self) -> usize {
        self.batch_size
    }

    fn tune_batch_size(&mut self, hasher: &WorkHasher) -> Result<usize> {
        const MAX_RESPONSIVE_BATCH: Duration = Duration::from_millis(100);
        const SAMPLES_PER_SIZE: usize = 3;
        let mut measurements = Vec::with_capacity(GPU_BATCH_SIZES.len());
        let mut first_nonce = self.initialization.batch_tuning_nonce_count;
        for batch_size in GPU_BATCH_SIZES {
            let mut sample_durations = Vec::with_capacity(SAMPLES_PER_SIZE);
            for _ in 0..SAMPLES_PER_SIZE {
                let started = Instant::now();
                let result =
                    self.hash_batch(hasher, first_nonce, batch_size, U256::MAX, None, None)?;
                verify_benchmark_batch(hasher, first_nonce, batch_size, &result)?;
                sample_durations.push(started.elapsed());
                first_nonce = first_nonce
                    .checked_add(u128::try_from(batch_size)?)
                    .context("GPU batch tuner nonce range overflow")?;
            }
            sample_durations.sort_unstable();
            let median = sample_durations[SAMPLES_PER_SIZE / 2];
            if median <= MAX_RESPONSIVE_BATCH {
                let hashes_per_second = batch_size as f64 / median.as_secs_f64().max(0.000_001);
                measurements.push((batch_size, median, hashes_per_second));
            }
        }

        let Some(best_rate) = measurements
            .iter()
            .map(|(_, _, rate)| *rate)
            .reduce(f64::max)
        else {
            bail!("no bounded GPU batch completed within the 100 ms responsiveness limit");
        };
        let (selected_size, _, selected_rate) = measurements
            .iter()
            .filter(|(_, _, rate)| *rate >= best_rate * 0.95)
            .max_by_key(|(size, _, _)| *size)
            .copied()
            .context("no validated GPU batch met the measured throughput threshold")?;
        self.batch_size = selected_size;
        self.info.batch_size = selected_size;
        self.info.tuned_hashes_per_second = selected_rate.round() as u64;
        self.initialization.batch_tuning_nonce_count = first_nonce;
        Ok(selected_size)
    }

    pub(crate) fn hash_batch(
        &mut self,
        hasher: &WorkHasher,
        first_nonce: u128,
        count: usize,
        target: U256,
        incumbent: Option<B256>,
        stop: Option<&AtomicBool>,
    ) -> Result<GpuBatchResult> {
        self.hash_batch_with_profiling(GpuBatchParams {
            hasher,
            first_nonce,
            count,
            target,
            incumbent,
            stop,
            profile: false,
        })
    }

    pub(crate) fn hash_batch_profiled(
        &mut self,
        hasher: &WorkHasher,
        first_nonce: u128,
        count: usize,
        target: U256,
        incumbent: Option<B256>,
    ) -> Result<GpuBatchResult> {
        self.hash_batch_with_profiling(GpuBatchParams {
            hasher,
            first_nonce,
            count,
            target,
            incumbent,
            stop: None,
            profile: true,
        })
    }

    fn hash_batch_with_profiling(&mut self, params: GpuBatchParams<'_>) -> Result<GpuBatchResult> {
        let stop = params.stop;
        let readback_slot = self.next_readback_slot;
        if self.readback_in_flight[readback_slot] {
            bail!("GPU readback ring slot {readback_slot} is still in flight");
        }
        let pending = self.submit_batch_with_profiling(params, readback_slot)?;
        self.readback_in_flight[readback_slot] = true;
        self.next_readback_slot = 1 - readback_slot;
        self.collect_batch(pending, stop)
    }

    pub(crate) fn dispatch_batch(
        &mut self,
        hasher: &WorkHasher,
        first_nonce: u128,
        count: usize,
        target: U256,
        incumbent: Option<B256>,
        stop: &AtomicBool,
    ) -> Result<PendingGpuBatch> {
        self.dispatch_batch_with_profile(GpuBatchParams {
            hasher,
            first_nonce,
            count,
            target,
            incumbent,
            stop: Some(stop),
            profile: false,
        })
    }

    pub(crate) fn dispatch_batch_profiled(
        &mut self,
        hasher: &WorkHasher,
        first_nonce: u128,
        count: usize,
        target: U256,
        incumbent: Option<B256>,
        stop: &AtomicBool,
    ) -> Result<PendingGpuBatch> {
        self.dispatch_batch_with_profile(GpuBatchParams {
            hasher,
            first_nonce,
            count,
            target,
            incumbent,
            stop: Some(stop),
            profile: true,
        })
    }

    fn dispatch_batch_with_profile(
        &mut self,
        params: GpuBatchParams<'_>,
    ) -> Result<PendingGpuBatch> {
        let readback_slot = self.next_readback_slot;
        if self.readback_in_flight[readback_slot] {
            bail!("GPU readback ring slot {readback_slot} is still in flight");
        }
        let pending = self.submit_batch_with_profiling(params, readback_slot)?;
        self.readback_in_flight[readback_slot] = true;
        self.next_readback_slot = 1 - readback_slot;
        Ok(pending)
    }

    pub(crate) fn collect_batch(
        &mut self,
        pending: PendingGpuBatch,
        stop: Option<&AtomicBool>,
    ) -> Result<GpuBatchResult> {
        let readback_slot = pending.readback_slot;
        if !self.readback_in_flight[readback_slot] {
            bail!("GPU readback ring slot was collected more than once");
        }
        let result = self.collect_batch_inner(pending, stop)?;
        self.readback_in_flight[readback_slot] = false;
        Ok(result)
    }

    fn submit_batch_with_profiling(
        &mut self,
        params: GpuBatchParams<'_>,
        readback_slot: usize,
    ) -> Result<PendingGpuBatch> {
        let dispatch_started = Instant::now();
        let GpuBatchParams {
            hasher,
            first_nonce,
            count,
            target,
            incumbent,
            stop,
            profile,
        } = params;
        if stop.is_some_and(|stop| stop.load(Ordering::Acquire)) {
            bail!("GPU batch cancelled before dispatch");
        }
        if self.device_lost.load(Ordering::Acquire) {
            bail!("GPU device was lost");
        }
        if let Some(error) = self
            .uncaptured_error
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take()
        {
            bail!("wgpu reported an uncaptured GPU error: {error}");
        }
        if count == 0 || count > self.batch_size {
            bail!("GPU batch count must be within 1..={}", self.batch_size);
        }
        let last_offset = u128::try_from(count - 1)?;
        first_nonce
            .checked_add(last_offset)
            .context("GPU nonce batch would overflow the u128 nonce space")?;

        let host_prepare_started = Instant::now();
        let template = hasher.abi_template();
        if template.len() < ABI_SHA256_PREFIX_BYTES
            || !template.len().is_multiple_of(4)
            || template.len() > MAX_ABI_TEMPLATE_BYTES
        {
            bail!("canonical ABI work template has an unsupported byte length");
        }
        let payload = if self.midstate_enabled {
            &template[ABI_SHA256_PREFIX_BYTES..]
        } else {
            template
        };
        let mut input_bytes = Vec::with_capacity(INPUT_HEADER_WORDS * 4 + payload.len());
        push_u32(&mut input_bytes, u32::try_from(template.len())?);
        push_u32(&mut input_bytes, u32::try_from(count)?);
        for chunk in first_nonce.to_be_bytes().as_chunks::<4>().0 {
            push_u32(&mut input_bytes, u32::from_be_bytes(*chunk));
        }
        let target_bytes = target.to_be_bytes::<32>();
        for chunk in target_bytes.as_chunks::<4>().0 {
            push_u32(&mut input_bytes, u32::from_be_bytes(*chunk));
        }
        push_u32(&mut input_bytes, u32::from(incumbent.is_some()));
        let incumbent_bytes = incumbent.unwrap_or(B256::ZERO);
        for chunk in incumbent_bytes.0.as_chunks::<4>().0 {
            push_u32(&mut input_bytes, u32::from_be_bytes(*chunk));
        }
        let midstate = if self.midstate_enabled {
            hasher.sha256_prefix_midstate()
        } else {
            [0; 8]
        };
        for word in midstate {
            push_u32(&mut input_bytes, word);
        }
        for chunk in payload.as_chunks::<4>().0 {
            push_u32(&mut input_bytes, u32::from_be_bytes(*chunk));
        }
        if input_bytes.len() > INPUT_BUFFER_BYTES {
            bail!("canonical work dispatch exceeds the bounded GPU input buffer");
        }
        let host_preparation = host_prepare_started.elapsed();
        let upload_started = Instant::now();
        self.queue.write_buffer(&self.input, 0, &input_bytes);
        let upload_enqueue = upload_started.elapsed();

        let workgroup_size = self.workgroup_size as usize;
        let workgroup_count = count.div_ceil(workgroup_size);
        let bytes_to_read = workgroup_count
            .checked_mul(RESULT_WORDS)
            .and_then(|words| words.checked_mul(4))
            .context("GPU result-buffer size overflow")?;
        let timestamp_resources = if profile {
            self.timestamps.as_ref().map(|slots| &slots[readback_slot])
        } else {
            None
        };
        let timestamp_offset = if timestamp_resources.is_some() {
            Some(align_up(bytes_to_read, QUERY_RESOLVE_ALIGNMENT)?)
        } else {
            None
        };
        let bytes_to_map = timestamp_offset
            .map(|offset| offset + TIMESTAMP_QUERY_BYTES)
            .unwrap_or(bytes_to_read);
        let encoding_started = Instant::now();
        let mut encoder = self
            .device
            .create_command_encoder(&wgpu::CommandEncoderDescriptor {
                label: Some("Astatine SHA-256d batch commands"),
            });
        {
            let mut pass = encoder.begin_compute_pass(&wgpu::ComputePassDescriptor {
                label: Some("Astatine SHA-256d nonce batch"),
                timestamp_writes: timestamp_resources.map(|timestamps| {
                    wgpu::ComputePassTimestampWrites {
                        query_set: &timestamps.query_set,
                        beginning_of_pass_write_index: Some(0),
                        end_of_pass_write_index: Some(1),
                    }
                }),
            });
            pass.set_pipeline(&self.pipeline);
            let bind_group = self.device.create_bind_group(&wgpu::BindGroupDescriptor {
                label: Some("Astatine SHA-256d batch bindings"),
                layout: &self.pipeline.get_bind_group_layout(0),
                entries: &[
                    wgpu::BindGroupEntry {
                        binding: 0,
                        resource: self.input.as_entire_binding(),
                    },
                    wgpu::BindGroupEntry {
                        binding: 1,
                        resource: self.output.as_entire_binding(),
                    },
                ],
            });
            pass.set_bind_group(0, &bind_group, &[]);
            let groups = u32::try_from(workgroup_count)?;
            if groups > self.device.limits().max_compute_workgroups_per_dimension {
                bail!("GPU dispatch exceeds the adapter's workgroup limit");
            }
            pass.dispatch_workgroups(groups, 1, 1);
        }
        if let Some(timestamps) = timestamp_resources {
            encoder.write_timestamp(&timestamps.query_set, 2);
        }
        encoder.copy_buffer_to_buffer(
            &self.output,
            0,
            &self.readback[readback_slot],
            0,
            u64::try_from(bytes_to_read)?,
        );
        if let (Some(timestamps), Some(timestamp_offset)) = (timestamp_resources, timestamp_offset)
        {
            encoder.write_timestamp(&timestamps.query_set, 3);
            encoder.resolve_query_set(
                &timestamps.query_set,
                0..TIMESTAMP_QUERY_COUNT,
                &timestamps.resolve_buffer,
                0,
            );
            encoder.copy_buffer_to_buffer(
                &timestamps.resolve_buffer,
                0,
                &self.readback[readback_slot],
                u64::try_from(timestamp_offset)?,
                u64::try_from(TIMESTAMP_QUERY_BYTES)?,
            );
        }
        let command_buffer = encoder.finish();
        let command_encoding = encoding_started.elapsed();
        let submit_started = Instant::now();
        let submission = self.queue.submit([command_buffer]);
        let queue_submit = submit_started.elapsed();
        let timings = GpuBatchTimings {
            host_preparation,
            upload_enqueue,
            command_encoding,
            queue_submit,
            ..GpuBatchTimings::default()
        };
        Ok(PendingGpuBatch {
            readback_slot,
            first_nonce,
            count,
            workgroup_size,
            workgroup_count,
            bytes_to_map,
            timestamp_offset,
            submission,
            submitted_at: dispatch_started,
            timings,
        })
    }

    fn collect_batch_inner(
        &mut self,
        pending: PendingGpuBatch,
        stop: Option<&AtomicBool>,
    ) -> Result<GpuBatchResult> {
        let PendingGpuBatch {
            readback_slot,
            first_nonce,
            count,
            workgroup_size,
            workgroup_count,
            bytes_to_map,
            timestamp_offset,
            submission,
            submitted_at,
            mut timings,
        } = pending;
        let mapped = self.read_mapped_buffer(readback_slot, bytes_to_map, stop, submission)?;
        timings.submission_to_readback = submitted_at.elapsed();
        timings.queue_wait = mapped.queue_wait;
        timings.map_request = mapped.map_request;
        timings.mapped_bytes_copy = mapped.mapped_copy;
        let gpu_compute = timestamp_offset
            .map(|offset| {
                timestamp_duration(
                    &mapped.bytes,
                    offset,
                    0,
                    1,
                    self.queue.get_timestamp_period(),
                )
            })
            .transpose()?;
        let gpu_output_copy = timestamp_offset
            .map(|offset| {
                timestamp_duration(
                    &mapped.bytes,
                    offset,
                    2,
                    3,
                    self.queue.get_timestamp_period(),
                )
            })
            .transpose()?;
        let host_decode_started = Instant::now();
        let mut candidates = Vec::new();
        for index in 0..workgroup_count {
            let base = index * RESULT_WORDS * 4;
            if read_u32(&mapped.bytes, base)? == 0 {
                continue;
            }
            let mut digest = [0_u8; 32];
            for word in 0..8 {
                let value = read_u32(&mapped.bytes, base + (word + 1) * 4)?;
                digest[word * 4..word * 4 + 4].copy_from_slice(&value.to_be_bytes());
            }
            let mut nonce_bytes = [0_u8; 16];
            for word in 0..4 {
                let value = read_u32(&mapped.bytes, base + (word + 9) * 4)?;
                nonce_bytes[word * 4..word * 4 + 4].copy_from_slice(&value.to_be_bytes());
            }
            let candidate = GpuCandidate {
                nonce: u128::from_be_bytes(nonce_bytes),
                hash: B256::from(digest),
                workgroup_index: index,
            };
            let offset = candidate
                .nonce
                .checked_sub(first_nonce)
                .context("GPU workgroup winner nonce precedes its reserved batch")?;
            if offset >= count as u128 || usize::try_from(offset)? / workgroup_size != index {
                bail!("GPU workgroup reduction returned a nonce attributed to another group");
            }
            candidates.push(candidate);
        }
        let host_decode_elapsed = host_decode_started.elapsed();
        Ok(GpuBatchResult {
            completed_hashes: count,
            candidates,
            workgroup_size,
            workgroup_count,
            timings: GpuBatchTimings {
                result_decode: host_decode_elapsed,
                gpu_compute,
                gpu_output_copy,
                ..timings
            },
        })
    }

    fn read_mapped_buffer(
        &self,
        readback_slot: usize,
        bytes_to_read: usize,
        stop: Option<&AtomicBool>,
        submission: wgpu::SubmissionIndex,
    ) -> Result<MappedReadback> {
        let readback = &self.readback[readback_slot];
        let slice = readback.slice(0..u64::try_from(bytes_to_read)?);
        let (mapped_sender, mapped_receiver) = std::sync::mpsc::channel();
        let map_request_started = Instant::now();
        slice.map_async(MapMode::Read, move |result| {
            let _ = mapped_sender.send(result);
        });
        let map_request = map_request_started.elapsed();
        let queue_wait_started = Instant::now();
        let deadline = Instant::now() + GPU_DISPATCH_TIMEOUT;
        loop {
            if let Some(stop) = stop
                && stop.load(Ordering::Acquire)
            {
                bail!("GPU batch cancelled during shutdown");
            }
            if self.device_lost.load(Ordering::Acquire) {
                bail!("GPU device was lost while a batch was in flight");
            }
            if let Some(error) = self
                .uncaptured_error
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .take()
            {
                bail!("wgpu reported an uncaptured GPU error: {error}");
            }
            match self.device.poll(PollType::Wait {
                submission_index: Some(submission.clone()),
                timeout: Some(GPU_POLL_WAIT_QUANTUM),
            }) {
                Ok(_) => {}
                Err(wgpu::PollError::Timeout) => {}
                Err(error) => return Err(error).context("poll GPU batch completion"),
            }
            match mapped_receiver.try_recv() {
                Ok(result) => {
                    result.context("map GPU SHA-256d readback buffer")?;
                    break;
                }
                Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                    bail!("GPU result mapping callback disconnected");
                }
                Err(std::sync::mpsc::TryRecvError::Empty) => {}
            }
            if Instant::now() >= deadline {
                bail!("GPU SHA-256d dispatch exceeded its 15-second timeout");
            }
        }

        let queue_wait = queue_wait_started.elapsed();
        let mapped_copy_started = Instant::now();
        let view = slice
            .get_mapped_range()
            .context("read mapped GPU SHA-256d results")?;
        let result = view.to_vec();
        drop(view);
        readback.unmap();
        Ok(MappedReadback {
            bytes: result,
            map_request,
            queue_wait,
            mapped_copy: mapped_copy_started.elapsed(),
        })
    }

    fn raw_sha256(&self, message: &[u8]) -> Result<[u8; 32]> {
        if message.len() > MAX_ABI_TEMPLATE_BYTES {
            bail!("raw SHA-256 self-test message exceeds its bounded input buffer");
        }
        let mut input_bytes =
            Vec::with_capacity(INPUT_HEADER_WORDS * 4 + message.len().div_ceil(4) * 4);
        push_u32(&mut input_bytes, u32::try_from(message.len())?);
        push_u32(&mut input_bytes, 1);
        for _ in 0..(INPUT_HEADER_WORDS - 2) {
            push_u32(&mut input_bytes, 0);
        }
        for chunk in message.chunks(4) {
            let mut word = [0_u8; 4];
            word[..chunk.len()].copy_from_slice(chunk);
            push_u32(&mut input_bytes, u32::from_be_bytes(word));
        }
        self.queue.write_buffer(&self.input, 0, &input_bytes);
        let result_bytes = 9 * 4;
        let mut encoder = self
            .device
            .create_command_encoder(&wgpu::CommandEncoderDescriptor {
                label: Some("Astatine raw SHA-256 boundary self-test"),
            });
        {
            let mut pass = encoder.begin_compute_pass(&wgpu::ComputePassDescriptor {
                label: Some("Astatine raw SHA-256 test"),
                timestamp_writes: None,
            });
            pass.set_pipeline(&self.raw_sha_pipeline);
            let bind_group = self.device.create_bind_group(&wgpu::BindGroupDescriptor {
                label: Some("Astatine raw SHA-256 test bindings"),
                layout: &self.raw_sha_pipeline.get_bind_group_layout(0),
                entries: &[
                    wgpu::BindGroupEntry {
                        binding: 0,
                        resource: self.input.as_entire_binding(),
                    },
                    wgpu::BindGroupEntry {
                        binding: 1,
                        resource: self.output.as_entire_binding(),
                    },
                ],
            });
            pass.set_bind_group(0, &bind_group, &[]);
            pass.dispatch_workgroups(1, 1, 1);
        }
        encoder.copy_buffer_to_buffer(
            &self.output,
            0,
            &self.readback[0],
            0,
            u64::try_from(result_bytes)?,
        );
        let submission = self.queue.submit([encoder.finish()]);
        let mapped = self.read_mapped_buffer(0, result_bytes, None, submission)?;
        if read_u32(&mapped.bytes, 0)? != 1 {
            bail!("GPU raw SHA-256 test shader did not write its result");
        }
        let mut digest = [0_u8; 32];
        for word in 0..8 {
            digest[word * 4..word * 4 + 4]
                .copy_from_slice(&read_u32(&mapped.bytes, (word + 1) * 4)?.to_be_bytes());
        }
        Ok(digest)
    }

    pub(crate) fn self_test(&mut self) -> Result<()> {
        let mut context = WorkContext {
            chain_id: 31_337,
            contract: "0x1234567890abcdef1234567890abcdef12345678".parse()?,
            window_id: 42,
            seed: "0x1111111111111111111111111111111111111111111111111111111111111111".parse()?,
            miner: "0x1111111111111111111111111111111111111111".parse()?,
            header: hex::decode("4153544154494e4500ff")?,
        };
        let canonical_nonce = 1_339_673_755_198_158_349_044_581_307_228_491_536_u128;
        let canonical_hash: B256 =
            "0x373d4c8d0a1f1dc9efd7e2e5d1a576718b65713f3d006f2a584cc722082323ec".parse()?;
        let hasher = WorkHasher::new(&context)?;
        let vector = self.hash_batch(&hasher, canonical_nonce, 1, U256::MAX, None, None)?;
        assert_single_candidate(&vector, canonical_nonce, canonical_hash)?;
        if hasher.hash(canonical_nonce) != canonical_hash {
            bail!("canonical CPU work-vector setup does not match the Solidity fixture");
        }

        let canonical_target = U256::from_be_bytes(canonical_hash.0);
        let exact_target =
            self.hash_batch(&hasher, canonical_nonce, 1, canonical_target, None, None)?;
        assert_single_candidate(&exact_target, canonical_nonce, canonical_hash)?;
        let below_target = canonical_target
            .checked_sub(U256::from(1))
            .context("canonical vector hash cannot be zero")?;
        let rejected = self.hash_batch(&hasher, canonical_nonce, 1, below_target, None, None)?;
        if !rejected.candidates.is_empty() {
            bail!("GPU target comparison accepted a hash above a strict lower target");
        }
        let zero_target = self.hash_batch(&hasher, canonical_nonce, 1, U256::ZERO, None, None)?;
        if !zero_target.candidates.is_empty() {
            bail!("GPU target comparison accepted a nonzero hash at the zero target");
        }
        let mut leading_zero_target_bytes = [0xff_u8; 32];
        leading_zero_target_bytes[0] = 0;
        let leading_zero_target = U256::from_be_bytes(leading_zero_target_bytes);
        let leading_zero_rejected =
            self.hash_batch(&hasher, canonical_nonce, 1, leading_zero_target, None, None)?;
        if !leading_zero_rejected.candidates.is_empty() {
            bail!("GPU full-width target comparison ignored leading zero target bytes");
        }
        let mut high_bit_target_bytes = [0_u8; 32];
        high_bit_target_bytes[0] = 0x80;
        let high_bit_target = U256::from_be_bytes(high_bit_target_bytes);
        let high_bit_accepted =
            self.hash_batch(&hasher, canonical_nonce, 1, high_bit_target, None, None)?;
        assert_single_candidate(&high_bit_accepted, canonical_nonce, canonical_hash)?;
        let equal_incumbent = self.hash_batch(
            &hasher,
            canonical_nonce,
            1,
            U256::MAX,
            Some(canonical_hash),
            None,
        )?;
        if !equal_incumbent.candidates.is_empty() {
            bail!("GPU incumbent comparison accepted a hash equal to the incumbent");
        }
        let lower_incumbent = self.hash_batch(
            &hasher,
            canonical_nonce,
            1,
            U256::MAX,
            Some(B256::from(
                canonical_target
                    .checked_sub(U256::from(1))
                    .context("canonical vector hash cannot be zero")?
                    .to_be_bytes::<32>(),
            )),
            None,
        )?;
        if !lower_incumbent.candidates.is_empty() {
            bail!("GPU incumbent comparison accepted a hash above the incumbent");
        }
        let greater_incumbent = self.hash_batch(
            &hasher,
            canonical_nonce,
            1,
            U256::MAX,
            Some(B256::from(
                canonical_target
                    .checked_add(U256::from(1))
                    .context("canonical vector hash cannot be maximum")?
                    .to_be_bytes::<32>(),
            )),
            None,
        )?;
        assert_single_candidate(&greater_incumbent, canonical_nonce, canonical_hash)?;

        for length in [55, 56, 63, 64, 119, 120] {
            let message = (0..length)
                .map(|index| (index as u8).wrapping_mul(19))
                .collect::<Vec<_>>();
            let expected = Sha256::digest(&message);
            if self.raw_sha256(&message)? != expected.as_slice() {
                bail!("WGSL SHA-256 failed the raw {length}-byte padding-boundary vector");
            }
        }

        let nonce_ranges = [
            (0_u128, 3_usize),
            (u128::from(u32::MAX) - 1, 4),
            (u128::from(u64::MAX) - 1, 4),
            (u128::MAX - 1, 2),
        ];
        for (first, count) in nonce_ranges {
            for offset in 0..count {
                let nonce = first
                    .checked_add(u128::try_from(offset)?)
                    .context("self-test nonce overflow")?;
                let result = self.hash_batch(&hasher, nonce, 1, U256::MAX, None, None)?;
                assert_single_candidate(&result, nonce, hasher.hash(nonce)).with_context(
                    || "GPU SHA-256d self-test failed across a 128-bit nonce boundary",
                )?;
            }
        }

        let reduction_count = self.workgroup_size as usize * 4;
        let reduced = self.hash_batch(
            &hasher,
            canonical_nonce,
            reduction_count,
            U256::MAX,
            None,
            None,
        )?;
        let expected = cpu_group_winners(
            &hasher,
            canonical_nonce,
            reduction_count,
            U256::MAX,
            None,
            self.workgroup_size as usize,
        )?;
        if reduced.completed_hashes != reduction_count
            || reduced.workgroup_count != 4
            || reduced.candidates != expected
        {
            bail!("GPU workgroup reduction did not return each group's canonical minimum");
        }

        let mut second_context = context.clone();
        second_context.chain_id += 1;
        second_context.window_id += 1;
        second_context.header = (0..64)
            .map(|index| (index as u8).wrapping_mul(41))
            .collect();
        let second_hasher = WorkHasher::new(&second_context)?;
        let boundary_count = self.workgroup_size as usize * 4;
        let first_a = u128::MAX - u128::try_from(boundary_count)?;
        let first_b = u128::from(u64::MAX) - u128::try_from(boundary_count)?;
        let stop = AtomicBool::new(false);
        let pending_a =
            self.dispatch_batch(&hasher, first_a, boundary_count, U256::MAX, None, &stop)?;
        let pending_b = self.dispatch_batch(
            &second_hasher,
            first_b,
            boundary_count,
            U256::MAX,
            None,
            &stop,
        )?;
        let result_a = self.collect_batch(pending_a, None)?;
        let result_b = self.collect_batch(pending_b, None)?;
        if result_a.completed_hashes != boundary_count
            || result_b.completed_hashes != boundary_count
            || result_a.workgroup_count != 4
            || result_b.workgroup_count != 4
            || result_a.candidates
                != cpu_group_winners(
                    &hasher,
                    first_a,
                    boundary_count,
                    U256::MAX,
                    None,
                    self.workgroup_size as usize,
                )?
            || result_b.candidates
                != cpu_group_winners(
                    &second_hasher,
                    first_b,
                    boundary_count,
                    U256::MAX,
                    None,
                    self.workgroup_size as usize,
                )?
        {
            bail!("overlapped GPU batches lost their node/context or readback identity");
        }

        for length in [0, 1, 55, 56, 63, 64, 119, 120, MAX_HEADER_LENGTH] {
            context.header = (0..length)
                .map(|index| (index as u8).wrapping_mul(37))
                .collect();
            let header_hasher = WorkHasher::new(&context)?;
            let nonce = u128::MAX - u128::try_from(length)?;
            let result = self.hash_batch(&header_hasher, nonce, 1, U256::MAX, None, None)?;
            let expected = header_hasher.hash(nonce);
            assert_single_candidate(&result, nonce, expected).with_context(|| {
                format!("GPU self-test failed for an ABI header of {length} bytes")
            })?;
        }

        let header_lengths = [
            0,
            1,
            31,
            32,
            55,
            56,
            63,
            64,
            127,
            128,
            255,
            MAX_HEADER_LENGTH,
        ];
        for (context_index, header_length) in header_lengths.into_iter().enumerate() {
            let mut seed = [0_u8; 32];
            for (index, byte) in seed.iter_mut().enumerate() {
                *byte = (index as u8)
                    .wrapping_mul(17)
                    .wrapping_add((context_index as u8).wrapping_mul(29));
            }
            let differential_context = WorkContext {
                chain_id: 31_337 + context_index as u64,
                contract: alloy_primitives::Address::with_last_byte(context_index as u8 + 1),
                window_id: 1_000 + context_index as u64,
                seed: B256::new(seed),
                miner: alloy_primitives::Address::with_last_byte(context_index as u8 + 33),
                header: (0..header_length)
                    .map(|index| {
                        (index as u8)
                            .wrapping_mul(23)
                            .wrapping_add(context_index as u8)
                    })
                    .collect(),
            };
            let differential_hasher = WorkHasher::new(&differential_context)?;
            let first_nonce = match context_index % 4 {
                0 => (context_index as u128) << 96,
                1 => u128::from(u32::MAX) - 15,
                2 => u128::from(u64::MAX) - 15,
                _ => u128::MAX - 31,
            };
            let count = 32;
            let results = self.hash_batch(
                &differential_hasher,
                first_nonce,
                count,
                U256::MAX,
                None,
                None,
            )?;
            let expected = cpu_group_winners(
                &differential_hasher,
                first_nonce,
                count,
                U256::MAX,
                None,
                self.workgroup_size as usize,
            )?;
            if results.completed_hashes != count || results.candidates != expected {
                bail!("deterministic CPU/GPU workgroup-minimum differential mismatch");
            }
        }
        Ok(())
    }
}

pub(crate) fn print_devices() -> Result<()> {
    println!("ASTATINE · DEVICES");
    println!();
    println!("CPU");
    println!("  Available: Yes");
    println!(
        "  Threads: {}",
        std::thread::available_parallelism().map_or(1, |count| count.get())
    );

    let instance = Instance::new(InstanceDescriptor::new_without_display_handle());
    let adapters = pollster::block_on(instance.enumerate_adapters(Backends::all()));
    let tuning_context = canonical_benchmark_context()?;
    let tuning_hasher = WorkHasher::new(&tuning_context)?;
    let mut physical = 0usize;
    let mut self_tested = 0usize;
    for adapter in adapters {
        let adapter_info = adapter.get_info();
        println!();
        println!("GPU · {}", adapter_info.name);
        println!("  Vendor ID: {:#06x}", adapter_info.vendor);
        println!("  Type: {:?}", adapter_info.device_type);
        println!("  Backend: {:?}", adapter_info.backend);
        let limits = adapter.limits();
        println!(
            "  Adapter limits: {} compute invocations/workgroup · {} workgroups/dimension · {} MiB storage binding",
            limits.max_compute_invocations_per_workgroup,
            limits.max_compute_workgroups_per_dimension,
            limits.max_storage_buffer_binding_size / (1024 * 1024),
        );
        let driver = match (
            adapter_info.driver.is_empty(),
            adapter_info.driver_info.is_empty(),
        ) {
            (true, true) => "not reported by wgpu".to_owned(),
            (true, false) => adapter_info.driver_info.clone(),
            (false, true) => adapter_info.driver.clone(),
            (false, false) => format!("{} {}", adapter_info.driver, adapter_info.driver_info),
        };
        println!("  Driver: {driver}");
        println!(
            "  GPU timestamp queries: {}",
            if adapter.features().contains(PROFILE_TIMESTAMP_FEATURES) {
                "available"
            } else {
                "unavailable · using wall-time fallback"
            }
        );
        if is_software_adapter(&adapter_info) {
            println!("  SHA-256d self-test: NOT RUN · software/virtual adapter");
            continue;
        }
        physical += 1;
        match pollster::block_on(GpuEngine::from_adapter(
            instance.clone(),
            adapter,
            adapter_info,
            MAX_GPU_BATCH_SIZE,
            GPU_WORKGROUP_SIZE,
            true,
            false,
        )) {
            Ok(mut engine) => match engine.self_test() {
                Ok(()) => {
                    println!("  Compute: PASS · WGSL + storage buffers");
                    println!("  SHA-256d self-test: PASS · WGSL executed on this adapter");
                    match engine.tune_batch_size(&tuning_hasher) {
                        Ok(batch_size) => {
                            self_tested += 1;
                            println!(
                                "  Recommended mining batch: {batch_size} · workgroup {} · measured {:.3} MH/s",
                                engine.workgroup_size,
                                engine.info.tuned_hashes_per_second as f64 / 1_000_000.0,
                            );
                        }
                        Err(error) => println!("  Batch calibration: unavailable · {error:#}"),
                    }
                }
                Err(error) => println!("  SHA-256d self-test: FAIL · {error:#}"),
            },
            Err(error) => println!("  SHA-256d self-test: FAIL · {error:#}"),
        }
    }
    println!();
    if physical == 0 {
        println!("Recommended backend: CPU · no physical compute adapter was found");
    } else if self_tested > 0 {
        println!("Recommended backend: GPU · {self_tested} physical adapter(s) passed self-test");
    } else {
        println!("Recommended backend: CPU · no physical adapter passed self-test");
    }
    Ok(())
}

pub(crate) fn run_benchmark(args: BenchmarkArgs) -> Result<()> {
    benchmark::run(args)
}

fn canonical_benchmark_context() -> Result<WorkContext> {
    Ok(WorkContext {
        chain_id: 31_337,
        contract: "0x1234567890abcdef1234567890abcdef12345678".parse()?,
        window_id: 42,
        seed: "0x1111111111111111111111111111111111111111111111111111111111111111".parse()?,
        miner: "0x1111111111111111111111111111111111111111".parse()?,
        header: hex::decode("4153544154494e4500ff")?,
    })
}

pub(crate) fn benchmark_cpu_from(
    hasher: &WorkHasher,
    threads: usize,
    duration: Duration,
    nonce_base: u128,
) -> Result<(u64, Duration)> {
    let stop = Arc::new(AtomicBool::new(false));
    let start_gate = Arc::new(AtomicBool::new(false));
    let completed = Arc::new(AtomicU64::new(0));
    let failed = Arc::new(AtomicBool::new(false));
    let mut workers = Vec::with_capacity(threads);
    for worker_index in 0..threads {
        let worker_start = nonce_base
            .checked_add(u128::try_from(worker_index)?)
            .context("CPU benchmark nonce start overflow")?;
        let worker_stop = Arc::clone(&stop);
        let start_gate = Arc::clone(&start_gate);
        let completed = Arc::clone(&completed);
        let failed = Arc::clone(&failed);
        let hasher = hasher.clone();
        let worker = thread::Builder::new()
            .name(format!("astatine-benchmark-cpu-{worker_index}"))
            .spawn(move || {
                let mut nonce = worker_start;
                let stride = threads as u128;
                let mut scratch = vec![0_u8; hasher.scratch_len()];
                let mut local_completed = 0_u64;
                while !start_gate.load(Ordering::Acquire) {
                    if worker_stop.load(Ordering::Acquire) {
                        return;
                    }
                    thread::yield_now();
                }
                while !worker_stop.load(Ordering::Relaxed) {
                    let Ok(hash) = hasher.hash_into(nonce, &mut scratch) else {
                        failed.store(true, Ordering::Release);
                        break;
                    };
                    std::hint::black_box(hash);
                    local_completed = local_completed.saturating_add(1);
                    let Some(next_nonce) = nonce.checked_add(stride) else {
                        break;
                    };
                    nonce = next_nonce;
                }
                completed.fetch_add(local_completed, Ordering::Relaxed);
            });
        match worker {
            Ok(worker) => workers.push(worker),
            Err(error) => {
                stop.store(true, Ordering::Release);
                for worker in workers {
                    let _ = worker.join();
                }
                return Err(error).context("start CPU benchmark worker");
            }
        }
    }
    let started = Instant::now();
    start_gate.store(true, Ordering::Release);
    thread::sleep(duration);
    stop.store(true, Ordering::Release);
    for worker in workers {
        worker
            .join()
            .map_err(|_| anyhow!("CPU benchmark worker panicked"))?;
    }
    let elapsed = started.elapsed();
    if failed.load(Ordering::Acquire) {
        bail!("CPU WorkHasher failed during the benchmark");
    }
    Ok((completed.load(Ordering::Relaxed), elapsed))
}

pub(crate) fn benchmark_cpu_reference(threads: usize) -> Result<u64> {
    if threads == 0 || threads > 256 {
        bail!("CPU comparison thread count must be within 1..=256");
    }
    let context = canonical_benchmark_context()?;
    let hasher = WorkHasher::new(&context)?;
    let mut nonce_base = 1_u128 << 121;
    let _ = benchmark_cpu_from(&hasher, threads, Duration::from_millis(250), nonce_base)?;
    let mut rates = Vec::with_capacity(3);
    for run in 0..3_u32 {
        nonce_base = (1_u128 << 120) + (u128::from(run) << 96);
        let (hashes, elapsed) =
            benchmark_cpu_from(&hasher, threads, Duration::from_millis(750), nonce_base)?;
        rates.push(hashes as f64 / elapsed.as_secs_f64().max(0.001));
    }
    rates.sort_by(f64::total_cmp);
    Ok(rates[1].round() as u64)
}

fn verify_benchmark_batch(
    hasher: &WorkHasher,
    first_nonce: u128,
    batch_size: usize,
    batch: &GpuBatchResult,
) -> Result<()> {
    if batch.completed_hashes != batch_size
        || batch.workgroup_count != batch_size.div_ceil(batch.workgroup_size)
        || batch.candidates.len() != batch.workgroup_count
    {
        bail!("U256::MAX benchmark target must return one winner per completed workgroup");
    }
    let batch_end = first_nonce
        .checked_add(u128::try_from(batch_size)?)
        .context("GPU benchmark nonce range overflow")?;
    let mut seen_workgroups = HashSet::with_capacity(batch.workgroup_count);
    let mut best: Option<&GpuCandidate> = None;
    for candidate in &batch.candidates {
        if candidate.workgroup_index >= batch.workgroup_count
            || !seen_workgroups.insert(candidate.workgroup_index)
        {
            bail!("GPU benchmark returned duplicate or out-of-range workgroup winners");
        }
        let offset = candidate
            .nonce
            .checked_sub(first_nonce)
            .context("GPU benchmark winner precedes its nonce range")?;
        if candidate.nonce >= batch_end
            || usize::try_from(offset)? / batch.workgroup_size != candidate.workgroup_index
        {
            bail!("GPU benchmark workgroup winner failed its nonce attribution check");
        }
        if best.is_none_or(|previous| {
            candidate
                .hash
                .cmp(&previous.hash)
                .then(candidate.nonce.cmp(&previous.nonce))
                .is_lt()
        }) {
            best = Some(candidate);
        }
    }
    let best = best.context("GPU benchmark returned no valid workgroup winners")?;
    if hasher.hash(best.nonce) != best.hash {
        bail!("GPU benchmark's selected candidate failed canonical CPU verification");
    }
    Ok(())
}

fn validate_gpu_config(batch_size: usize, workgroup_size: u32) -> Result<()> {
    if !GPU_BATCH_SIZES.contains(&batch_size) {
        bail!("GPU batch size must be one of {GPU_BATCH_SIZES:?}");
    }
    if !SUPPORTED_WORKGROUP_SIZES.contains(&workgroup_size) {
        bail!("GPU workgroup size must be one of {SUPPORTED_WORKGROUP_SIZES:?}");
    }
    if batch_size > MAX_GPU_BATCH_SIZE {
        bail!("GPU batch size exceeds the bounded maximum of {MAX_GPU_BATCH_SIZE}");
    }
    Ok(())
}

fn reduced_gpu_batch_size(current: usize, latency: Duration) -> Option<usize> {
    const RESPONSIVE_BATCH_LIMIT: Duration = Duration::from_millis(100);
    if latency <= RESPONSIVE_BATCH_LIMIT {
        return None;
    }
    let current_index = GPU_BATCH_SIZES.iter().position(|size| *size == current)?;
    GPU_BATCH_SIZES.get(current_index.checked_sub(1)?).copied()
}

fn adapter_priority(info: &AdapterInfo) -> u8 {
    match info.device_type {
        DeviceType::DiscreteGpu => 0,
        DeviceType::IntegratedGpu => 1,
        DeviceType::VirtualGpu => 2,
        DeviceType::Other => 3,
        DeviceType::Cpu => 4,
    }
}

fn is_software_adapter(info: &AdapterInfo) -> bool {
    if matches!(info.device_type, DeviceType::Cpu | DeviceType::VirtualGpu) {
        return true;
    }
    let searchable =
        format!("{} {} {}", info.name, info.driver, info.driver_info).to_ascii_lowercase();
    [
        "llvmpipe",
        "lavapipe",
        "swiftshader",
        "software rasterizer",
        "microsoft basic render",
        "warp",
    ]
    .iter()
    .any(|marker| searchable.contains(marker))
}

fn validate_shader() -> Result<()> {
    let module = wgpu::naga::front::wgsl::parse_str(WGSL)
        .map_err(|error| anyhow!(error.emit_to_string(WGSL)))?;
    wgpu::naga::valid::Validator::new(
        wgpu::naga::valid::ValidationFlags::all(),
        wgpu::naga::valid::Capabilities::all(),
    )
    .validate(&module)
    .map_err(|error| anyhow!(error.emit_to_string(WGSL)))?;
    Ok(())
}

#[cfg(test)]
fn is_software_name(info: &AdapterInfo) -> bool {
    is_software_adapter(info)
}

fn push_u32(buffer: &mut Vec<u8>, value: u32) {
    // Storage-buffer words are serialized explicitly; this is not a host-native cast.
    buffer.extend_from_slice(&value.to_le_bytes());
}

fn read_u32(buffer: &[u8], offset: usize) -> Result<u32> {
    let bytes = buffer
        .get(offset..offset + 4)
        .context("GPU result buffer was shorter than its declared layout")?;
    Ok(u32::from_le_bytes(bytes.try_into()?))
}

fn read_u64(buffer: &[u8], offset: usize) -> Result<u64> {
    let bytes = buffer
        .get(offset..offset + 8)
        .context("GPU timestamp buffer was shorter than its declared layout")?;
    Ok(u64::from_le_bytes(bytes.try_into()?))
}

fn align_up(value: usize, alignment: usize) -> Result<usize> {
    value
        .checked_add(alignment - 1)
        .map(|aligned| aligned / alignment * alignment)
        .context("GPU timestamp readback offset overflow")
}

fn timestamp_duration(
    mapped_bytes: &[u8],
    base_offset: usize,
    start_query: u32,
    end_query: u32,
    timestamp_period_ns: f32,
) -> Result<Duration> {
    let start_offset = base_offset
        .checked_add(usize::try_from(start_query)? * 8)
        .context("GPU timestamp start offset overflow")?;
    let end_offset = base_offset
        .checked_add(usize::try_from(end_query)? * 8)
        .context("GPU timestamp end offset overflow")?;
    let ticks =
        read_u64(mapped_bytes, end_offset)?.saturating_sub(read_u64(mapped_bytes, start_offset)?);
    let nanoseconds = ticks as f64 * f64::from(timestamp_period_ns);
    if !nanoseconds.is_finite() || nanoseconds > u64::MAX as f64 {
        bail!("GPU timestamp duration is outside the representable range");
    }
    Ok(Duration::from_nanos(nanoseconds.round() as u64))
}

fn assert_single_candidate(result: &GpuBatchResult, nonce: u128, hash: B256) -> Result<()> {
    if result.completed_hashes != 1 || result.candidates.len() != 1 {
        bail!("GPU did not return the exact expected canonical nonce/hash result");
    }
    if result.candidates[0]
        != (GpuCandidate {
            nonce,
            hash,
            workgroup_index: 0,
        })
    {
        bail!("GPU did not return the exact expected canonical nonce/hash result");
    }
    Ok(())
}

fn cpu_group_winners(
    hasher: &WorkHasher,
    first_nonce: u128,
    count: usize,
    target: U256,
    incumbent: Option<B256>,
    workgroup_size: usize,
) -> Result<Vec<GpuCandidate>> {
    let mut winners = Vec::new();
    for workgroup_index in 0..count.div_ceil(workgroup_size) {
        let start = workgroup_index * workgroup_size;
        let end = (start + workgroup_size).min(count);
        let mut best: Option<GpuCandidate> = None;
        for offset in start..end {
            let nonce = first_nonce
                .checked_add(u128::try_from(offset)?)
                .context("CPU differential nonce range overflow")?;
            let hash = hasher.hash(nonce);
            if U256::from_be_bytes(hash.0) > target
                || incumbent.is_some_and(|incumbent| hash >= incumbent)
            {
                continue;
            }
            let candidate = GpuCandidate {
                nonce,
                hash,
                workgroup_index,
            };
            if best.is_none_or(|previous| {
                candidate
                    .hash
                    .cmp(&previous.hash)
                    .then(candidate.nonce.cmp(&previous.nonce))
                    .is_lt()
            }) {
                best = Some(candidate);
            }
        }
        if let Some(best) = best {
            winners.push(best);
        }
    }
    Ok(winners)
}

#[cfg(test)]
mod tests {
    use super::{
        GpuEngine, is_software_name, reduced_gpu_batch_size, validate_gpu_config, validate_shader,
    };
    use wgpu::{AdapterInfo, Backend, DeviceType};

    #[test]
    fn wgsl_shader_parses_and_validates_without_gpu_hardware() {
        validate_shader().unwrap();
    }

    #[test]
    fn software_and_cpu_adapters_are_never_selected_for_mining() {
        let mut info = AdapterInfo::new(DeviceType::Cpu, Backend::Vulkan);
        info.name = "llvmpipe (LLVM 21)".to_owned();
        assert!(is_software_name(&info));

        info.device_type = DeviceType::VirtualGpu;
        info.name = "Paravirtual Graphics Adapter".to_owned();
        assert!(is_software_name(&info));

        info.device_type = DeviceType::IntegratedGpu;
        info.name = "Apple M4".to_owned();
        assert!(!is_software_name(&info));

        info.name = "Microsoft Basic Render Driver".to_owned();
        assert!(is_software_name(&info));
    }

    #[test]
    fn gpu_configuration_is_limited_to_benchmarked_batch_and_workgroup_sizes() {
        for batch_size in [2_048, 8_192, 16_384, 32_768, 65_536, 131_072, 262_144] {
            for workgroup_size in [32, 64, 128, 256] {
                assert!(validate_gpu_config(batch_size, workgroup_size).is_ok());
            }
        }
        assert!(validate_gpu_config(1_024, 32).is_err());
        assert!(validate_gpu_config(524_288, 32).is_err());
        assert!(validate_gpu_config(2_048, 16).is_err());
    }

    #[test]
    fn high_batch_latency_only_reduces_to_a_bounded_supported_size() {
        use std::time::Duration;

        assert_eq!(
            reduced_gpu_batch_size(262_144, Duration::from_millis(100)),
            None
        );
        assert_eq!(
            reduced_gpu_batch_size(262_144, Duration::from_millis(101)),
            Some(131_072)
        );
        assert_eq!(
            reduced_gpu_batch_size(2_048, Duration::from_millis(101)),
            None
        );
    }

    #[test]
    fn physical_gpu_executes_canonical_sha256d_and_u128_nonce_self_tests() {
        if std::env::var("ASTATINE_REQUIRE_GPU").as_deref() != Ok("1") {
            eprintln!(
                "GPU hardware test not run; set ASTATINE_REQUIRE_GPU=1 to require a physical adapter"
            );
            return;
        }
        let mut engine = GpuEngine::initialize().expect("a physical GPU should be available");
        engine.self_test().unwrap();
    }
}
