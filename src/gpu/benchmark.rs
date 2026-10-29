use super::{
    GPU_BATCH_SIZE, GPU_BATCH_SIZES, GPU_WORKGROUP_SIZE, GpuBatchResult, GpuBatchTimings,
    GpuDeviceInfo, GpuEngine, GpuInitializationTimings, PendingGpuBatch, SUPPORTED_WORKGROUP_SIZES,
    benchmark_cpu_from, canonical_benchmark_context, verify_benchmark_batch,
};
use crate::{cli::BenchmarkArgs, config::conservative_thread_budget, protocol::WorkHasher};
use alloy_primitives::U256;
use anyhow::{Context, Result, bail};
use serde_json::{Value, json};
use std::{
    path::PathBuf,
    sync::atomic::AtomicBool,
    time::{Duration, Instant},
};

const CPU_WARMUP: Duration = Duration::from_millis(500);
const GPU_WARMUP_BATCHES: usize = 2;
const TESTNET10_GPU_MHS: f64 = 1.334;
const TESTNET10_CPU_MHS: f64 = 22.910;

#[derive(Clone, Debug)]
struct CpuSample {
    completed_hashes: u64,
    elapsed: Duration,
}

impl CpuSample {
    fn rate(&self) -> f64 {
        self.completed_hashes as f64 / self.elapsed.as_secs_f64().max(0.001)
    }
}

#[derive(Clone, Debug)]
struct GpuSample {
    completed_hashes: u64,
    elapsed: Duration,
    dispatches: u64,
    batch_wall: Duration,
    candidate_verification: Duration,
    timings: GpuBatchTimings,
    timestamp_samples: u64,
    gpu_compute: Duration,
    gpu_output_copy: Duration,
}

impl GpuSample {
    fn rate(&self) -> f64 {
        self.completed_hashes as f64 / self.elapsed.as_secs_f64().max(0.001)
    }

    fn average_batch_latency(&self) -> Duration {
        divide_duration(self.batch_wall, self.dispatches)
    }

    fn host_processing(&self) -> Duration {
        self.timings
            .host_preparation
            .saturating_add(self.timings.upload_enqueue)
            .saturating_add(self.timings.command_encoding)
            .saturating_add(self.timings.queue_submit)
            .saturating_add(self.timings.map_request)
            .saturating_add(self.timings.mapped_bytes_copy)
            .saturating_add(self.timings.result_decode)
            .saturating_add(self.candidate_verification)
    }
}

#[derive(Clone, Debug)]
struct GpuConfigurationResult {
    info: GpuDeviceInfo,
    midstate_enabled: bool,
    pipeline_enabled: bool,
    initialization: GpuInitializationTimings,
    samples: Vec<GpuSample>,
}

struct RawBenchmarkReport<'a> {
    path: Option<&'a PathBuf>,
    context: &'a crate::protocol::WorkContext,
    threads: usize,
    seconds: u8,
    runs: u8,
    profile: bool,
    compare_full_sha: bool,
    serial: bool,
    cpu_samples: &'a [CpuSample],
    gpu_configurations: &'a [GpuConfigurationResult],
}

pub(crate) fn run(args: BenchmarkArgs) -> Result<()> {
    let threads = args
        .threads
        .map_or_else(conservative_thread_budget, |threads| threads.get());
    if threads == 0 || threads > 256 {
        bail!("CPU benchmark thread count must be within 1..=256");
    }
    let logical_cpus = std::thread::available_parallelism().map_or(1, |count| count.get());
    let duration = Duration::from_secs(u64::from(args.seconds));
    let context = canonical_benchmark_context()?;
    let hasher = WorkHasher::new(&context)?;

    println!("ASTATINE · SHA-256d PERFORMANCE BENCHMARK");
    println!(
        "Canonical work · chain={} window={} header={} bytes · CPU threads={} · {} measured runs × {} s",
        context.chain_id,
        context.window_id,
        context.header.len(),
        threads,
        args.runs,
        args.seconds,
    );
    println!(
        "Testnet.10 reference · CPU {:.3} MH/s · GPU {:.3} MH/s · GPU batch {:.3} ms · M4/Metal",
        TESTNET10_CPU_MHS, TESTNET10_GPU_MHS, 1.518,
    );
    if args.profile || args.compare_full_sha {
        println!("Mode · bounded GPU configuration sweep; CPU baseline measured once");
    }
    println!();

    let warmup = benchmark_cpu_from(&hasher, threads, CPU_WARMUP, 1_u128 << 121)?;
    std::hint::black_box(warmup);

    let mut gpu_configurations = Vec::new();
    let mut cpu_samples = Vec::with_capacity(args.runs as usize);
    if args.profile || args.compare_full_sha {
        cpu_samples = run_cpu_samples(&hasher, threads, args.runs, duration)?;
        let batch_sizes = if args.profile && args.batch_size.is_none() {
            GPU_BATCH_SIZES.to_vec()
        } else {
            vec![args.batch_size.unwrap_or(GPU_BATCH_SIZE)]
        };
        let workgroup_sizes = if args.profile && args.workgroup_size.is_none() {
            SUPPORTED_WORKGROUP_SIZES.to_vec()
        } else {
            vec![args.workgroup_size.unwrap_or(GPU_WORKGROUP_SIZE)]
        };
        let midstate_modes = if args.compare_full_sha {
            vec![false, true]
        } else {
            vec![true]
        };
        for batch_size in batch_sizes {
            for &workgroup_size in &workgroup_sizes {
                for &midstate_enabled in &midstate_modes {
                    match run_gpu_configuration(
                        batch_size,
                        workgroup_size,
                        midstate_enabled,
                        !args.serial,
                        args.runs,
                        duration,
                        &hasher,
                    ) {
                        Ok(configuration) => gpu_configurations.push(configuration),
                        Err(error) => {
                            println!(
                                "GPU config batch={batch_size} workgroup={workgroup_size} midstate={midstate_enabled}: unavailable · {error:#}"
                            );
                        }
                    }
                }
            }
        }
    } else {
        let auto_config = args.batch_size.is_none() && args.workgroup_size.is_none();
        let batch_size = args.batch_size.unwrap_or(GPU_BATCH_SIZE);
        let workgroup_size = args.workgroup_size.unwrap_or(GPU_WORKGROUP_SIZE);
        let engine = if auto_config {
            GpuEngine::initialize_auto_profiled()
        } else {
            GpuEngine::initialize_profiled(batch_size, workgroup_size)
        };
        let mut engine = match engine {
            Ok(engine) => engine,
            Err(error) => {
                cpu_samples = run_cpu_samples(&hasher, threads, args.runs, duration)?;
                print_cpu_samples(&cpu_samples, threads, logical_cpus);
                println!("GPU benchmark unavailable: {error:#}");
                write_report_if_requested(RawBenchmarkReport {
                    path: args.output_json.as_ref(),
                    context: &context,
                    threads,
                    seconds: args.seconds,
                    runs: args.runs,
                    profile: args.profile,
                    compare_full_sha: args.compare_full_sha,
                    serial: args.serial,
                    cpu_samples: &cpu_samples,
                    gpu_configurations: &gpu_configurations,
                })?;
                return Ok(());
            }
        };
        let selected_batch = engine.batch_size();
        let tuning_nonce_count = engine.initialization_timings().batch_tuning_nonce_count;
        let mut next_nonce = warm_gpu(&mut engine, &hasher, selected_batch, tuning_nonce_count)?;
        let mut samples = Vec::with_capacity(args.runs as usize);
        for run_index in 0..args.runs {
            if run_index % 2 == 0 {
                let sample_index = cpu_samples.len();
                cpu_samples.push(run_cpu_sample(&hasher, threads, duration, sample_index)?);
                let (sample, next_nonce_after_sample) = run_gpu_sample(
                    &mut engine,
                    &hasher,
                    selected_batch,
                    duration,
                    next_nonce,
                    !args.serial,
                )?;
                next_nonce = next_nonce_after_sample;
                samples.push(sample);
            } else {
                let (sample, next_nonce_after_sample) = run_gpu_sample(
                    &mut engine,
                    &hasher,
                    selected_batch,
                    duration,
                    next_nonce,
                    !args.serial,
                )?;
                next_nonce = next_nonce_after_sample;
                samples.push(sample);
                let sample_index = cpu_samples.len();
                cpu_samples.push(run_cpu_sample(&hasher, threads, duration, sample_index)?);
            }
        }
        gpu_configurations.push(GpuConfigurationResult {
            info: engine.info().clone(),
            midstate_enabled: true,
            pipeline_enabled: !args.serial,
            initialization: engine.initialization_timings(),
            samples,
        });
    }

    print_cpu_samples(&cpu_samples, threads, logical_cpus);
    for configuration in &gpu_configurations {
        print_gpu_configuration(configuration, logical_cpus, &cpu_samples);
    }
    if gpu_configurations.is_empty() {
        println!("No supported GPU batch/workgroup configuration completed profiling.");
    }
    write_report_if_requested(RawBenchmarkReport {
        path: args.output_json.as_ref(),
        context: &context,
        threads,
        seconds: args.seconds,
        runs: args.runs,
        profile: args.profile,
        compare_full_sha: args.compare_full_sha,
        serial: args.serial,
        cpu_samples: &cpu_samples,
        gpu_configurations: &gpu_configurations,
    })?;
    Ok(())
}

fn run_cpu_sample(
    hasher: &WorkHasher,
    threads: usize,
    duration: Duration,
    sample_index: usize,
) -> Result<CpuSample> {
    let nonce_base = (1_u128 << 120) + (u128::try_from(sample_index)? << 96);
    let (completed_hashes, elapsed) = benchmark_cpu_from(hasher, threads, duration, nonce_base)?;
    Ok(CpuSample {
        completed_hashes,
        elapsed,
    })
}

fn run_cpu_samples(
    hasher: &WorkHasher,
    threads: usize,
    runs: u8,
    duration: Duration,
) -> Result<Vec<CpuSample>> {
    (0..runs)
        .map(|index| run_cpu_sample(hasher, threads, duration, usize::from(index)))
        .collect()
}

fn run_gpu_configuration(
    batch_size: usize,
    workgroup_size: u32,
    midstate_enabled: bool,
    pipeline_enabled: bool,
    runs: u8,
    duration: Duration,
    hasher: &WorkHasher,
) -> Result<GpuConfigurationResult> {
    let mut engine =
        GpuEngine::initialize_profiled_mode(batch_size, workgroup_size, midstate_enabled)?;
    let initialization = engine.initialization_timings();
    let info = engine.info().clone();
    let mut samples = Vec::with_capacity(runs as usize);
    let mode_nonce_base = if midstate_enabled {
        1_u128 << 125
    } else {
        1_u128 << 124
    };
    let mut next_nonce =
        mode_nonce_base | (u128::try_from(batch_size)? << 96) | (u128::from(workgroup_size) << 64);
    next_nonce = warm_gpu(&mut engine, hasher, batch_size, next_nonce)?;
    for _ in 0..runs {
        let (sample, next_nonce_after_sample) = run_gpu_sample(
            &mut engine,
            hasher,
            batch_size,
            duration,
            next_nonce,
            pipeline_enabled,
        )?;
        next_nonce = next_nonce_after_sample;
        samples.push(sample);
    }
    Ok(GpuConfigurationResult {
        info,
        midstate_enabled,
        pipeline_enabled,
        initialization,
        samples,
    })
}

fn warm_gpu(
    engine: &mut GpuEngine,
    hasher: &WorkHasher,
    batch_size: usize,
    mut first_nonce: u128,
) -> Result<u128> {
    for _ in 0..GPU_WARMUP_BATCHES {
        let batch = engine.hash_batch(hasher, first_nonce, batch_size, U256::MAX, None, None)?;
        verify_benchmark_batch(hasher, first_nonce, batch_size, &batch)?;
        first_nonce = first_nonce
            .checked_add(u128::try_from(batch_size)?)
            .context("GPU warmup nonce range overflow")?;
    }
    Ok(first_nonce)
}

fn run_gpu_sample(
    engine: &mut GpuEngine,
    hasher: &WorkHasher,
    batch_size: usize,
    duration: Duration,
    first_nonce: u128,
    pipeline_enabled: bool,
) -> Result<(GpuSample, u128)> {
    let started = Instant::now();
    let mut next_nonce = first_nonce;
    let stop = AtomicBool::new(false);
    let mut pending: Option<(PendingGpuBatch, u128)> = None;
    let mut sample = GpuSample {
        completed_hashes: 0,
        elapsed: Duration::ZERO,
        dispatches: 0,
        batch_wall: Duration::ZERO,
        candidate_verification: Duration::ZERO,
        timings: GpuBatchTimings::default(),
        timestamp_samples: 0,
        gpu_compute: Duration::ZERO,
        gpu_output_copy: Duration::ZERO,
    };
    while started.elapsed() < duration {
        if !pipeline_enabled {
            let first = next_nonce;
            let batch = engine.hash_batch_profiled(hasher, first, batch_size, U256::MAX, None)?;
            record_gpu_sample_batch(hasher, batch_size, first, batch, &mut sample)?;
            next_nonce = next_nonce
                .checked_add(u128::try_from(batch_size)?)
                .context("GPU benchmark nonce range overflow")?;
            continue;
        }
        let submitted_nonce = next_nonce;
        let submitted = if engine.info().timestamp_queries {
            engine.dispatch_batch_profiled(
                hasher,
                next_nonce,
                batch_size,
                U256::MAX,
                None,
                &stop,
            )?
        } else {
            engine.dispatch_batch(hasher, next_nonce, batch_size, U256::MAX, None, &stop)?
        };
        next_nonce = next_nonce
            .checked_add(u128::try_from(batch_size)?)
            .context("GPU benchmark nonce range overflow")?;
        if let Some((previous, previous_nonce)) = pending.replace((submitted, submitted_nonce)) {
            collect_gpu_sample_batch(
                engine,
                hasher,
                batch_size,
                previous_nonce,
                previous,
                &mut sample,
            )?;
        }
    }
    if let Some((last, last_nonce)) = pending {
        collect_gpu_sample_batch(engine, hasher, batch_size, last_nonce, last, &mut sample)?;
    }
    sample.elapsed = started.elapsed();
    if sample.dispatches == 0 {
        bail!("GPU benchmark completed no dispatches in the requested sample interval");
    }
    Ok((sample, next_nonce))
}

fn collect_gpu_sample_batch(
    engine: &mut GpuEngine,
    hasher: &WorkHasher,
    batch_size: usize,
    first_nonce: u128,
    pending: PendingGpuBatch,
    sample: &mut GpuSample,
) -> Result<()> {
    let batch = engine.collect_batch(pending, None)?;
    record_gpu_sample_batch(hasher, batch_size, first_nonce, batch, sample)
}

fn record_gpu_sample_batch(
    hasher: &WorkHasher,
    batch_size: usize,
    first_nonce: u128,
    batch: GpuBatchResult,
    sample: &mut GpuSample,
) -> Result<()> {
    sample.batch_wall = sample
        .batch_wall
        .saturating_add(batch.timings.submission_to_readback);
    accumulate_timings(&mut sample.timings, batch.timings);
    if let (Some(compute), Some(copy)) = (batch.timings.gpu_compute, batch.timings.gpu_output_copy)
    {
        sample.timestamp_samples += 1;
        sample.gpu_compute = sample.gpu_compute.saturating_add(compute);
        sample.gpu_output_copy = sample.gpu_output_copy.saturating_add(copy);
    }
    let verification_started = Instant::now();
    verify_benchmark_batch(hasher, first_nonce, batch_size, &batch)?;
    sample.candidate_verification = sample
        .candidate_verification
        .saturating_add(verification_started.elapsed());
    sample.completed_hashes = sample
        .completed_hashes
        .checked_add(u64::try_from(batch.completed_hashes)?)
        .context("GPU benchmark hash counter overflow")?;
    sample.dispatches += 1;
    Ok(())
}

fn accumulate_timings(total: &mut GpuBatchTimings, sample: GpuBatchTimings) {
    total.host_preparation = total
        .host_preparation
        .saturating_add(sample.host_preparation);
    total.upload_enqueue = total.upload_enqueue.saturating_add(sample.upload_enqueue);
    total.command_encoding = total
        .command_encoding
        .saturating_add(sample.command_encoding);
    total.queue_submit = total.queue_submit.saturating_add(sample.queue_submit);
    total.queue_wait = total.queue_wait.saturating_add(sample.queue_wait);
    total.map_request = total.map_request.saturating_add(sample.map_request);
    total.mapped_bytes_copy = total
        .mapped_bytes_copy
        .saturating_add(sample.mapped_bytes_copy);
    total.result_decode = total.result_decode.saturating_add(sample.result_decode);
}

fn print_cpu_samples(samples: &[CpuSample], threads: usize, logical_cpus: usize) {
    let rates = samples.iter().map(CpuSample::rate).collect::<Vec<_>>();
    println!("CPU baseline · {threads} worker(s), {logical_cpus} logical CPUs");
    for (index, sample) in samples.iter().enumerate() {
        println!(
            "  Run {} · {:.3} MH/s · {} hashes · {:.3} s",
            index + 1,
            sample.rate() / 1_000_000.0,
            sample.completed_hashes,
            sample.elapsed.as_secs_f64(),
        );
    }
    if !rates.is_empty() {
        println!(
            "  Median effective rate: {:.3} MH/s",
            median(rates) / 1_000_000.0
        );
    }
    println!(
        "  Approx CPU capacity: {:.1}% of {logical_cpus} logical CPUs",
        threads.min(logical_cpus) as f64 / logical_cpus as f64 * 100.0
    );
}

fn print_gpu_configuration(
    configuration: &GpuConfigurationResult,
    logical_cpus: usize,
    cpu_samples: &[CpuSample],
) {
    let rates = configuration
        .samples
        .iter()
        .map(GpuSample::rate)
        .collect::<Vec<_>>();
    let info = &configuration.info;
    println!(
        "\nGPU config · {} · {} · batch={} · workgroup={} · SHA midstate={} · pipeline={}",
        info.name,
        info.backend,
        info.batch_size,
        info.workgroup_size,
        configuration.midstate_enabled,
        configuration.pipeline_enabled,
    );
    println!("  Type: {}", info.device_type);
    if info.tuned_hashes_per_second > 0 {
        println!(
            "  Mining batch calibration: {:.3} MH/s median · {}-nonce batch retained within the 100 ms latency bound",
            info.tuned_hashes_per_second as f64 / 1_000_000.0,
            info.batch_size,
        );
    }
    println!(
        "  Timestamp queries: {}",
        if info.timestamp_queries {
            "available"
        } else {
            "unavailable; GPU compute time not isolated"
        }
    );
    println!(
        "  Initialization stages: validate {:.3} s · enumerate {:.3} s · device {:.3} s · pipeline {:.3} s · self-test {:.3} s · tune {:.3} s · total {:.3} s",
        configuration.initialization.shader_validation.as_secs_f64(),
        configuration
            .initialization
            .adapter_enumeration
            .as_secs_f64(),
        configuration.initialization.device_request.as_secs_f64(),
        configuration.initialization.pipeline_creation.as_secs_f64(),
        configuration.initialization.self_test.as_secs_f64(),
        configuration.initialization.batch_tuning.as_secs_f64(),
        configuration.initialization.total.as_secs_f64(),
    );
    for (index, sample) in configuration.samples.iter().enumerate() {
        println!(
            "  Run {} · {:.3} MH/s · {} hashes · {} dispatches · {:.3} ms dispatch-to-readback/batch",
            index + 1,
            sample.rate() / 1_000_000.0,
            sample.completed_hashes,
            sample.dispatches,
            sample.average_batch_latency().as_secs_f64() * 1_000.0,
        );
    }
    if !rates.is_empty() {
        let gpu_median = median(rates);
        println!(
            "  Median effective rate: {:.3} MH/s",
            gpu_median / 1_000_000.0
        );
        println!(
            "  Relative to established Testnet.10 GPU baseline: {:.2}x",
            gpu_median / (TESTNET10_GPU_MHS * 1_000_000.0)
        );
        let cpu_rates = cpu_samples.iter().map(CpuSample::rate).collect::<Vec<_>>();
        if !cpu_rates.is_empty() {
            let cpu_median = median(cpu_rates);
            println!(
                "  Median GPU/CPU effective-rate ratio: {:.3}x",
                gpu_median / cpu_median
            );
        }
    }
    let mut ordered_samples = configuration.samples.iter().collect::<Vec<_>>();
    ordered_samples.sort_by(|left, right| left.rate().total_cmp(&right.rate()));
    if let Some(sample) = ordered_samples.get(ordered_samples.len() / 2).copied() {
        let average =
            |duration: Duration| duration.as_secs_f64() * 1_000.0 / sample.dispatches.max(1) as f64;
        println!(
            "  Median-run host stages/batch: prepare {:.3} ms · upload enqueue {:.3} ms · encode {:.3} ms · submit {:.3} ms",
            average(sample.timings.host_preparation),
            average(sample.timings.upload_enqueue),
            average(sample.timings.command_encoding),
            average(sample.timings.queue_submit),
        );
        println!(
            "  Median-run completion/batch: queue wait {:.3} ms · map request {:.3} ms · mapped copy {:.3} ms · decode {:.3} ms · CPU verify {:.3} ms",
            average(sample.timings.queue_wait),
            average(sample.timings.map_request),
            average(sample.timings.mapped_bytes_copy),
            average(sample.timings.result_decode),
            average(sample.candidate_verification),
        );
        if sample.timestamp_samples > 0 {
            println!(
                "  GPU timestamp averages: compute {:.3} ms · output copy {:.3} ms",
                sample.gpu_compute.as_secs_f64() * 1_000.0 / sample.timestamp_samples as f64,
                sample.gpu_output_copy.as_secs_f64() * 1_000.0 / sample.timestamp_samples as f64,
            );
        }
        let cpu_used = sample.host_processing().as_secs_f64()
            / sample.elapsed.as_secs_f64().max(0.001)
            / logical_cpus as f64
            * 100.0;
        println!("  Approx measured host CPU utilization: {cpu_used:.2}%");
    }
}

fn median(mut values: Vec<f64>) -> f64 {
    values.sort_by(f64::total_cmp);
    let middle = values.len() / 2;
    if values.is_empty() {
        0.0
    } else if values.len().is_multiple_of(2) {
        (values[middle - 1] + values[middle]) / 2.0
    } else {
        values[middle]
    }
}

fn divide_duration(total: Duration, divisor: u64) -> Duration {
    if divisor == 0 {
        return Duration::ZERO;
    }
    Duration::from_secs_f64(total.as_secs_f64() / divisor as f64)
}

fn write_report_if_requested(report: RawBenchmarkReport<'_>) -> Result<()> {
    let RawBenchmarkReport {
        path,
        context,
        threads,
        seconds,
        runs,
        profile,
        compare_full_sha,
        serial,
        cpu_samples,
        gpu_configurations,
    } = report;
    let Some(path) = path else {
        return Ok(());
    };
    let cpu = cpu_samples
        .iter()
        .enumerate()
        .map(|(index, sample)| {
            json!({
                "run": index + 1,
                "completed_hashes": sample.completed_hashes,
                "elapsed_seconds": sample.elapsed.as_secs_f64(),
                "effective_hashes_per_second": sample.rate(),
            })
        })
        .collect::<Vec<Value>>();
    let gpu = gpu_configurations
        .iter()
        .map(|configuration| {
            let samples = configuration
                .samples
                .iter()
                .enumerate()
                .map(|(index, sample)| {
                    let average_ms = |duration: Duration| {
                        duration.as_secs_f64() * 1_000.0 / sample.dispatches.max(1) as f64
                    };
                    json!({
                        "run": index + 1,
                        "completed_hashes": sample.completed_hashes,
                        "elapsed_seconds": sample.elapsed.as_secs_f64(),
                        "effective_hashes_per_second": sample.rate(),
                        "dispatches": sample.dispatches,
                        "dispatch_to_readback_latency_ms": sample.average_batch_latency().as_secs_f64() * 1_000.0,
                        "host_stage_average_ms": {
                            "preparation": average_ms(sample.timings.host_preparation),
                            "upload_enqueue": average_ms(sample.timings.upload_enqueue),
                            "command_encoding": average_ms(sample.timings.command_encoding),
                            "queue_submit": average_ms(sample.timings.queue_submit),
                            "map_request": average_ms(sample.timings.map_request),
                            "mapped_copy": average_ms(sample.timings.mapped_bytes_copy),
                            "result_decode": average_ms(sample.timings.result_decode),
                            "candidate_cpu_verification": average_ms(sample.candidate_verification),
                        },
                        "queue_wait_average_ms": average_ms(sample.timings.queue_wait),
                        "gpu_compute_average_ms": if sample.timestamp_samples == 0 {
                            Value::Null
                        } else {
                            json!(sample.gpu_compute.as_secs_f64() * 1_000.0 / sample.timestamp_samples as f64)
                        },
                        "gpu_output_copy_average_ms": if sample.timestamp_samples == 0 {
                            Value::Null
                        } else {
                            json!(sample.gpu_output_copy.as_secs_f64() * 1_000.0 / sample.timestamp_samples as f64)
                        },
                    })
                })
                .collect::<Vec<Value>>();
            json!({
                "adapter": {
                    "name": configuration.info.name,
                    "vendor_id": configuration.info.vendor,
                    "device_type": configuration.info.device_type,
                    "backend": configuration.info.backend,
                    "driver": configuration.info.driver,
                    "driver_info": configuration.info.driver_info,
                    "timestamp_queries": configuration.info.timestamp_queries,
                    "sha256_midstate": configuration.midstate_enabled,
                    "cpu_comparison_hashes_per_second": configuration.info.cpu_comparison_hashes_per_second,
                    "cpu_comparison_threads": configuration.info.cpu_comparison_threads,
                },
                "batch_size": configuration.info.batch_size,
                "workgroup_size": configuration.info.workgroup_size,
                "pipeline_enabled": configuration.pipeline_enabled,
                "tuned_hashes_per_second": configuration.info.tuned_hashes_per_second,
                "initialization_seconds": {
                    "shader_validation": configuration.initialization.shader_validation.as_secs_f64(),
                    "adapter_enumeration": configuration.initialization.adapter_enumeration.as_secs_f64(),
                    "device_request": configuration.initialization.device_request.as_secs_f64(),
                    "pipeline_creation": configuration.initialization.pipeline_creation.as_secs_f64(),
                    "self_test": configuration.initialization.self_test.as_secs_f64(),
                    "batch_tuning": configuration.initialization.batch_tuning.as_secs_f64(),
                    "batch_tuning_nonce_count": configuration.initialization.batch_tuning_nonce_count,
                    "total": configuration.initialization.total.as_secs_f64(),
                },
                "samples": samples,
            })
        })
        .collect::<Vec<Value>>();
    let report = json!({
        "schema": "astatine-gpu-benchmark-v1",
        "version": env!("CARGO_PKG_VERSION"),
        "work": {
            "chain_id": context.chain_id,
            "window_id": context.window_id,
            "header_length": context.header.len(),
            "algorithm": "canonical SHA-256d / WORK_DOMAIN_V2",
        },
        "testnet10_reference": {
            "hardware": "Apple M4 / Metal",
            "cpu_mh_s": TESTNET10_CPU_MHS,
            "gpu_mh_s": TESTNET10_GPU_MHS,
            "gpu_to_cpu_ratio": 0.0582,
            "gpu_batch_wall_ms": 1.518,
            "initialization_seconds": 0.102,
            "host_processing_seconds_per_10s": 1.366,
        },
        "settings": {
            "cpu_threads": threads,
            "sample_seconds": seconds,
            "runs": runs,
            "profile_sweep": profile,
            "compare_full_sha": compare_full_sha,
            "serial": serial,
            "cpu_warmup_ms": CPU_WARMUP.as_millis(),
            "gpu_warmup_batches": GPU_WARMUP_BATCHES,
        },
        "cpu_samples": cpu,
        "gpu_configurations": gpu,
    });
    let serialized =
        serde_json::to_vec_pretty(&report).context("serialize raw GPU benchmark report")?;
    std::fs::write(path, serialized)
        .with_context(|| format!("write benchmark JSON report to {}", path.display()))?;
    println!("Raw benchmark samples written to {}", path.display());
    Ok(())
}
