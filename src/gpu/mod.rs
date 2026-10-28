use alloy_primitives::{B256, U256, hex};
use anyhow::{Context, Result, anyhow, bail};
use sha2::{Digest, Sha256};
use std::{
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
    Queue, ShaderSource,
};

use crate::protocol::{MAX_HEADER_LENGTH, WorkContext, WorkHasher};
use crate::{cli::BenchmarkArgs, config::conservative_thread_budget};

const INPUT_HEADER_WORDS: usize = 23;
const MAX_ABI_TEMPLATE_BYTES: usize = 288 + MAX_HEADER_LENGTH.div_ceil(32) * 32;
const MAX_ABI_TEMPLATE_WORDS: usize = MAX_ABI_TEMPLATE_BYTES / 4;
const RESULT_WORDS: usize = 13;
const RESULT_BUFFER_BYTES: usize = GPU_BATCH_SIZE * RESULT_WORDS * 4;
const INPUT_BUFFER_BYTES: usize = (INPUT_HEADER_WORDS + MAX_ABI_TEMPLATE_WORDS) * 4;
const WORKGROUP_SIZE: u32 = 64;
const GPU_DISPATCH_TIMEOUT: Duration = Duration::from_secs(15);
const SELF_TEST_TIMEOUT: Duration = Duration::from_secs(20);

pub(crate) const GPU_BATCH_SIZE: usize = 2_048;

const WGSL: &str = include_str!("shader.wgsl");

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct GpuDeviceInfo {
    pub(crate) name: String,
    pub(crate) vendor: u32,
    pub(crate) device_type: String,
    pub(crate) backend: String,
    pub(crate) driver: String,
    pub(crate) driver_info: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct GpuCandidate {
    pub(crate) nonce: u128,
    pub(crate) hash: B256,
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
    pub(crate) host_processing: Duration,
}

pub(crate) struct GpuEngine {
    _instance: Instance,
    device: Device,
    queue: Queue,
    pipeline: wgpu::ComputePipeline,
    raw_sha_pipeline: wgpu::ComputePipeline,
    input: Buffer,
    output: Buffer,
    readback: Buffer,
    info: GpuDeviceInfo,
    device_lost: Arc<AtomicBool>,
    uncaptured_error: Arc<Mutex<Option<String>>>,
}

impl GpuEngine {
    pub(crate) fn initialize() -> Result<Self> {
        pollster::block_on(Self::initialize_async())
    }

    async fn initialize_async() -> Result<Self> {
        validate_shader()?;
        let instance = Instance::new(InstanceDescriptor::new_without_display_handle());
        let mut adapters = instance.enumerate_adapters(Backends::all()).await;
        adapters.sort_by_key(|adapter| adapter_priority(&adapter.get_info()));

        let mut failures = Vec::new();
        for adapter in adapters {
            let adapter_info = adapter.get_info();
            if is_software_adapter(&adapter_info) {
                continue;
            }
            match Self::from_adapter(instance.clone(), adapter, adapter_info.clone()).await {
                Ok(mut engine) => match engine.self_test() {
                    Ok(()) => return Ok(engine),
                    Err(error) => failures.push(format!(
                        "{} ({:?}): GPU SHA-256d self-test failed: {error:#}",
                        engine.info.name, engine.info.backend
                    )),
                },
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
    ) -> Result<Self> {
        let limits = adapter.limits();
        if limits.max_compute_workgroup_size_x < WORKGROUP_SIZE
            || limits.max_compute_invocations_per_workgroup < WORKGROUP_SIZE
            || limits.max_compute_workgroups_per_dimension == 0
        {
            bail!("adapter does not support the portable 64-invocation compute workgroup");
        }
        let input_bytes = u64::try_from(INPUT_BUFFER_BYTES)?;
        let result_bytes = u64::try_from(RESULT_BUFFER_BYTES)?;
        if limits.max_storage_buffer_binding_size < input_bytes
            || limits.max_storage_buffer_binding_size < result_bytes
            || limits.max_buffer_size < input_bytes.max(result_bytes)
        {
            bail!("adapter storage-buffer limits are below the bounded Astatine batch buffers");
        }

        let (device, queue) = adapter
            .request_device(&DeviceDescriptor {
                label: Some("Astatine SHA-256d compute device"),
                required_features: wgpu::Features::empty(),
                required_limits: wgpu::Limits::downlevel_defaults(),
                experimental_features: wgpu::ExperimentalFeatures::disabled(),
                memory_hints: MemoryHints::MemoryUsage,
                trace: wgpu::Trace::Off,
            })
            .await
            .context("request a wgpu compute device")?;

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
        let readback = device.create_buffer(&BufferDescriptor {
            label: Some("Astatine bounded compute readback"),
            size: result_bytes,
            usage: BufferUsages::COPY_DST | BufferUsages::MAP_READ,
            mapped_at_creation: false,
        });

        let shader = device.create_shader_module(wgpu::ShaderModuleDescriptor {
            label: Some("Astatine canonical SHA-256d WGSL"),
            source: ShaderSource::Wgsl(WGSL.into()),
        });
        let error_scope = device.push_error_scope(wgpu::ErrorFilter::Validation);
        let pipeline = device.create_compute_pipeline(&wgpu::ComputePipelineDescriptor {
            label: Some("Astatine SHA-256d pipeline"),
            layout: None,
            module: &shader,
            entry_point: Some("main"),
            compilation_options: Default::default(),
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

        let info = GpuDeviceInfo {
            name: adapter_info.name,
            vendor: adapter_info.vendor,
            device_type: format!("{:?}", adapter_info.device_type),
            backend: format!("{:?}", adapter_info.backend),
            driver: adapter_info.driver,
            driver_info: adapter_info.driver_info,
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
            device_lost,
            uncaptured_error,
        })
    }

    pub(crate) fn info(&self) -> &GpuDeviceInfo {
        &self.info
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
        if count == 0 || count > GPU_BATCH_SIZE {
            bail!("GPU batch count must be within 1..={GPU_BATCH_SIZE}");
        }
        let last_offset = u128::try_from(count - 1)?;
        first_nonce
            .checked_add(last_offset)
            .context("GPU nonce batch would overflow the u128 nonce space")?;

        let template = hasher.abi_template();
        if template.is_empty()
            || !template.len().is_multiple_of(4)
            || template.len() > MAX_ABI_TEMPLATE_BYTES
        {
            bail!("canonical ABI work template has an unsupported byte length");
        }
        let host_prepare_started = Instant::now();
        let mut input_bytes = Vec::with_capacity(INPUT_HEADER_WORDS * 4 + template.len());
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
        for chunk in template.as_chunks::<4>().0 {
            push_u32(&mut input_bytes, u32::from_be_bytes(*chunk));
        }
        if input_bytes.len() > INPUT_BUFFER_BYTES {
            bail!("canonical work dispatch exceeds the bounded GPU input buffer");
        }
        self.queue.write_buffer(&self.input, 0, &input_bytes);

        let bytes_to_read = count
            .checked_mul(RESULT_WORDS)
            .and_then(|words| words.checked_mul(4))
            .context("GPU result-buffer size overflow")?;
        let mut encoder = self
            .device
            .create_command_encoder(&wgpu::CommandEncoderDescriptor {
                label: Some("Astatine SHA-256d batch commands"),
            });
        {
            let mut pass = encoder.begin_compute_pass(&wgpu::ComputePassDescriptor {
                label: Some("Astatine SHA-256d nonce batch"),
                timestamp_writes: None,
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
            let groups = u32::try_from(count.div_ceil(WORKGROUP_SIZE as usize))?;
            if groups > self.device.limits().max_compute_workgroups_per_dimension {
                bail!("GPU dispatch exceeds the adapter's workgroup limit");
            }
            pass.dispatch_workgroups(groups, 1, 1);
        }
        encoder.copy_buffer_to_buffer(
            &self.output,
            0,
            &self.readback,
            0,
            u64::try_from(bytes_to_read)?,
        );
        self.queue.submit([encoder.finish()]);
        let host_prepare_elapsed = host_prepare_started.elapsed();

        let result_bytes = self.read_mapped_buffer(bytes_to_read, stop)?;
        let host_decode_started = Instant::now();
        let mut candidates = Vec::new();
        for index in 0..count {
            let base = index * RESULT_WORDS * 4;
            if read_u32(&result_bytes, base)? == 0 {
                continue;
            }
            let mut digest = [0_u8; 32];
            for word in 0..8 {
                let value = read_u32(&result_bytes, base + (word + 1) * 4)?;
                digest[word * 4..word * 4 + 4].copy_from_slice(&value.to_be_bytes());
            }
            let mut nonce_bytes = [0_u8; 16];
            for word in 0..4 {
                let value = read_u32(&result_bytes, base + (word + 9) * 4)?;
                nonce_bytes[word * 4..word * 4 + 4].copy_from_slice(&value.to_be_bytes());
            }
            candidates.push(GpuCandidate {
                nonce: u128::from_be_bytes(nonce_bytes),
                hash: B256::from(digest),
            });
        }
        let host_decode_elapsed = host_decode_started.elapsed();
        Ok(GpuBatchResult {
            completed_hashes: count,
            candidates,
            host_processing: host_prepare_elapsed.saturating_add(host_decode_elapsed),
        })
    }

    fn read_mapped_buffer(
        &self,
        bytes_to_read: usize,
        stop: Option<&AtomicBool>,
    ) -> Result<Vec<u8>> {
        let slice = self.readback.slice(0..u64::try_from(bytes_to_read)?);
        let (mapped_sender, mapped_receiver) = std::sync::mpsc::channel();
        slice.map_async(MapMode::Read, move |result| {
            let _ = mapped_sender.send(result);
        });
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
            match self.device.poll(PollType::Poll) {
                Ok(_) => {}
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
            std::thread::sleep(Duration::from_millis(1));
        }

        let view = slice
            .get_mapped_range()
            .context("read mapped GPU SHA-256d results")?;
        let result = view.to_vec();
        drop(view);
        self.readback.unmap();
        Ok(result)
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
            &self.readback,
            0,
            u64::try_from(result_bytes)?,
        );
        self.queue.submit([encoder.finish()]);
        let words = self.read_mapped_buffer(result_bytes, None)?;
        if read_u32(&words, 0)? != 1 {
            bail!("GPU raw SHA-256 test shader did not write its result");
        }
        let mut digest = [0_u8; 32];
        for word in 0..8 {
            digest[word * 4..word * 4 + 4]
                .copy_from_slice(&read_u32(&words, (word + 1) * 4)?.to_be_bytes());
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
            let result = self.hash_batch(&hasher, first, count, U256::MAX, None, None)?;
            if result.completed_hashes != count || result.candidates.len() != count {
                bail!("GPU self-test lost an all-valid nonce near a 32/64/128-bit boundary");
            }
            let mut actual = result.candidates;
            actual.sort_by_key(|candidate| candidate.nonce);
            for (offset, candidate) in actual.into_iter().enumerate() {
                let nonce = first
                    .checked_add(u128::try_from(offset)?)
                    .context("self-test nonce overflow")?;
                if candidate.nonce != nonce || candidate.hash != hasher.hash(nonce) {
                    bail!("GPU SHA-256d self-test failed across a 128-bit nonce boundary");
                }
            }
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
            if results.completed_hashes != count || results.candidates.len() != count {
                bail!("deterministic CPU/GPU differential batch lost a candidate");
            }
            let mut results = results.candidates;
            results.sort_by_key(|candidate| candidate.nonce);
            for (offset, candidate) in results.into_iter().enumerate() {
                let nonce = first_nonce
                    .checked_add(u128::try_from(offset)?)
                    .context("differential test nonce overflow")?;
                if candidate.nonce != nonce || candidate.hash != differential_hasher.hash(nonce) {
                    bail!("deterministic CPU/GPU differential vector mismatch");
                }
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
        if is_software_adapter(&adapter_info) {
            println!("  SHA-256d self-test: NOT RUN · software/virtual adapter");
            continue;
        }
        physical += 1;
        match pollster::block_on(GpuEngine::from_adapter(
            instance.clone(),
            adapter,
            adapter_info,
        )) {
            Ok(mut engine) => match engine.self_test() {
                Ok(()) => {
                    self_tested += 1;
                    println!("  Compute: PASS · WGSL + storage buffers");
                    println!("  SHA-256d self-test: PASS · WGSL executed on this adapter");
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
    let seconds = Duration::from_secs(u64::from(args.seconds));
    let threads = args
        .threads
        .map_or_else(conservative_thread_budget, |n| n.get());
    if threads > 256 {
        bail!("CPU benchmark thread count must not exceed 256");
    }
    let logical_cpus = std::thread::available_parallelism().map_or(1, |count| count.get());
    let context = WorkContext {
        chain_id: 31_337,
        contract: "0x1234567890abcdef1234567890abcdef12345678".parse()?,
        window_id: 42,
        seed: "0x1111111111111111111111111111111111111111111111111111111111111111".parse()?,
        miner: "0x1111111111111111111111111111111111111111".parse()?,
        header: hex::decode("4153544154494e4500ff")?,
    };
    let hasher = WorkHasher::new(&context)?;
    println!("ASTATINE · SHA-256d BENCHMARK");
    println!(
        "Canonical work context · chain={} window={} header={} bytes · batch={} · workgroup={}",
        context.chain_id,
        context.window_id,
        context.header.len(),
        GPU_BATCH_SIZE,
        WORKGROUP_SIZE
    );
    println!("Duration per backend: {} seconds", args.seconds);
    println!();

    let (cpu_hashes, cpu_elapsed) = benchmark_cpu(&hasher, threads, seconds)?;
    let cpu_rate = cpu_hashes as f64 / cpu_elapsed.as_secs_f64().max(0.001);
    let cpu_capacity = threads.min(logical_cpus) as f64 / logical_cpus as f64 * 100.0;
    println!("CPU");
    println!("  Worker threads: {threads}");
    println!("  Completed hashes: {cpu_hashes}");
    println!("  Effective rate: {:.3} MH/s", cpu_rate / 1_000_000.0);
    println!(
        "  Approx CPU utilization: {:.1}% of {logical_cpus} logical CPUs by configured worker capacity",
        cpu_capacity
    );
    println!("  Measurement duration: {:.3} s", cpu_elapsed.as_secs_f64());
    println!();

    let initialization_started = Instant::now();
    let mut engine = match GpuEngine::initialize() {
        Ok(engine) => engine,
        Err(error) => {
            println!("GPU");
            println!("  Benchmark not run: no physical adapter passed the SHA-256d self-test.");
            println!("  Detail: {error:#}");
            return Ok(());
        }
    };
    let initialization_elapsed = initialization_started.elapsed();
    let warmup = engine.hash_batch(&hasher, 0, GPU_BATCH_SIZE, U256::MAX, None, None)?;
    verify_benchmark_batch(&hasher, 0, &warmup)?;

    let gpu_started = Instant::now();
    let mut next_nonce = u128::try_from(GPU_BATCH_SIZE)?;
    let mut completed_hashes = 0_u64;
    let mut dispatches = 0_u64;
    let mut gpu_batch_wall = Duration::ZERO;
    let mut cpu_result_processing = Duration::ZERO;
    while gpu_started.elapsed() < seconds {
        let batch_started = Instant::now();
        let batch =
            engine.hash_batch(&hasher, next_nonce, GPU_BATCH_SIZE, U256::MAX, None, None)?;
        let batch_wall = batch_started.elapsed();
        gpu_batch_wall = gpu_batch_wall.saturating_add(batch_wall);
        cpu_result_processing = cpu_result_processing.saturating_add(batch.host_processing);
        let process_started = Instant::now();
        verify_benchmark_batch(&hasher, next_nonce, &batch)?;
        cpu_result_processing = cpu_result_processing.saturating_add(process_started.elapsed());
        completed_hashes = completed_hashes
            .checked_add(u64::try_from(batch.completed_hashes)?)
            .context("GPU benchmark hash counter overflow")?;
        dispatches = dispatches
            .checked_add(1)
            .context("GPU benchmark dispatch counter overflow")?;
        next_nonce = next_nonce
            .checked_add(u128::try_from(GPU_BATCH_SIZE)?)
            .context("GPU benchmark nonce range overflow")?;
        if batch_wall.is_zero() {
            bail!("GPU benchmark observed a zero-duration completed dispatch");
        }
    }
    let gpu_elapsed = gpu_started.elapsed();
    let gpu_rate = completed_hashes as f64 / gpu_elapsed.as_secs_f64().max(0.001);
    let average_dispatch_ms = gpu_batch_wall.as_secs_f64() * 1_000.0 / dispatches.max(1) as f64;
    let cpu_processing_fraction = cpu_result_processing.as_secs_f64()
        / gpu_elapsed.as_secs_f64().max(0.001)
        / logical_cpus as f64
        * 100.0;
    let info = engine.info().clone();
    println!("GPU");
    println!("  Adapter: {}", info.name);
    println!("  Backend: {}", info.backend);
    println!("  Device type: {}", info.device_type);
    println!(
        "  wgpu initialization + shader self-test: {:.3} s",
        initialization_elapsed.as_secs_f64()
    );
    println!("  Completed hashes: {completed_hashes}");
    println!("  Effective rate: {:.3} MH/s", gpu_rate / 1_000_000.0);
    println!(
        "  Dispatch + compute + readback wall: {:.3} ms/batch average",
        average_dispatch_ms
    );
    println!(
        "  CPU dispatch/readback + verification/collection time: {:.3} s",
        cpu_result_processing.as_secs_f64()
    );
    println!(
        "  Approx CPU utilization from measured host work: {:.2}% of {logical_cpus} logical CPUs",
        cpu_processing_fraction
    );
    println!(
        "  Measurement duration (excluding initialization): {:.3} s",
        gpu_elapsed.as_secs_f64()
    );
    println!(
        "\nGPU/CPU effective-rate ratio: {:.2}x",
        gpu_rate / cpu_rate.max(1.0)
    );
    Ok(())
}

fn benchmark_cpu(
    hasher: &WorkHasher,
    threads: usize,
    duration: Duration,
) -> Result<(u64, Duration)> {
    let stop = Arc::new(AtomicBool::new(false));
    let start_gate = Arc::new(AtomicBool::new(false));
    let completed = Arc::new(AtomicU64::new(0));
    let failed = Arc::new(AtomicBool::new(false));
    let mut workers = Vec::with_capacity(threads);
    for worker_index in 0..threads {
        let worker_stop = Arc::clone(&stop);
        let start_gate = Arc::clone(&start_gate);
        let completed = Arc::clone(&completed);
        let failed = Arc::clone(&failed);
        let hasher = hasher.clone();
        let worker = thread::Builder::new()
            .name(format!("astatine-benchmark-cpu-{worker_index}"))
            .spawn(move || {
                let mut nonce = worker_index as u128;
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
    let elapsed = started.elapsed();
    for worker in workers {
        worker
            .join()
            .map_err(|_| anyhow!("CPU benchmark worker panicked"))?;
    }
    if failed.load(Ordering::Acquire) {
        bail!("CPU WorkHasher failed during the benchmark");
    }
    Ok((completed.load(Ordering::Relaxed), elapsed))
}

fn verify_benchmark_batch(
    hasher: &WorkHasher,
    first_nonce: u128,
    batch: &GpuBatchResult,
) -> Result<()> {
    if batch.completed_hashes != GPU_BATCH_SIZE || batch.candidates.len() != GPU_BATCH_SIZE {
        bail!("U256::MAX benchmark target must return every completed GPU nonce");
    }
    let best = batch
        .candidates
        .iter()
        .min_by(|left, right| {
            left.hash
                .cmp(&right.hash)
                .then(left.nonce.cmp(&right.nonce))
        })
        .context("GPU benchmark returned no candidate hashes")?;
    let batch_end = first_nonce
        .checked_add(u128::try_from(GPU_BATCH_SIZE)?)
        .context("GPU benchmark nonce range overflow")?;
    if best.nonce < first_nonce || best.nonce >= batch_end || hasher.hash(best.nonce) != best.hash {
        bail!("GPU benchmark candidate failed canonical CPU verification");
    }
    Ok(())
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

fn assert_single_candidate(result: &GpuBatchResult, nonce: u128, hash: B256) -> Result<()> {
    if result.completed_hashes != 1 || result.candidates.len() != 1 {
        bail!("GPU did not return the exact expected canonical nonce/hash result");
    }
    if result.candidates[0] != (GpuCandidate { nonce, hash }) {
        bail!("GPU did not return the exact expected canonical nonce/hash result");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{GpuEngine, is_software_name, validate_shader};
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
