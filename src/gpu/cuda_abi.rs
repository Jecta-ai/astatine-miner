use super::{GpuCandidate, MAX_ABI_TEMPLATE_WORDS};
use crate::protocol::WorkHasher;
use alloy_primitives::{B256, U256};
use anyhow::{Context, Result, bail};

pub(crate) const CUDA_INPUT_HEADER_WORDS: usize = 32;
pub(crate) const CUDA_INPUT_WORDS: usize = CUDA_INPUT_HEADER_WORDS + MAX_ABI_TEMPLATE_WORDS;
pub(crate) const CUDA_RESULT_WORDS: usize = 13;
pub(crate) const CUDA_MAX_WORKGROUP_SIZE: usize = 256;

const MESSAGE_LENGTH_WORD: usize = 0;
const HASH_COUNT_WORD: usize = 1;
const FIRST_NONCE_WORD: usize = 2;
const TARGET_WORD: usize = 6;
const INCUMBENT_VALID_WORD: usize = 14;
const INCUMBENT_WORD: usize = 15;
const PREFIX_MIDSTATE_WORD: usize = 23;
const USE_MIDSTATE_WORD: usize = 31;
const ABI_NONCE_WORD: usize = 52;

pub(crate) fn encode_batch_input(
    hasher: &WorkHasher,
    first_nonce: u128,
    count: usize,
    target: U256,
    incumbent: Option<B256>,
    use_midstate: bool,
) -> Result<Vec<u32>> {
    if count == 0 {
        bail!("CUDA batch count must be nonzero");
    }
    let count_u32 = u32::try_from(count).context("CUDA batch count exceeds the kernel ABI")?;
    first_nonce
        .checked_add(u128::try_from(count - 1)?)
        .context("CUDA nonce batch would overflow the u128 nonce space")?;

    let template = hasher.abi_template();
    if template.len() < (ABI_NONCE_WORD + 4) * 4
        || template.len() > MAX_ABI_TEMPLATE_WORDS * 4
        || !template.len().is_multiple_of(4)
    {
        bail!("canonical ABI work template has an unsupported CUDA layout");
    }
    let message_length = u32::try_from(template.len())
        .context("canonical ABI work template exceeds the CUDA message-length field")?;

    let mut words = vec![0_u32; CUDA_INPUT_WORDS];
    words[MESSAGE_LENGTH_WORD] = message_length;
    words[HASH_COUNT_WORD] = count_u32;
    copy_bytes_to_be_words(
        &first_nonce.to_be_bytes(),
        &mut words[FIRST_NONCE_WORD..][..4],
    )?;
    copy_bytes_to_be_words(&target.to_be_bytes::<32>(), &mut words[TARGET_WORD..][..8])?;
    if let Some(incumbent) = incumbent {
        words[INCUMBENT_VALID_WORD] = 1;
        copy_bytes_to_be_words(&incumbent.0, &mut words[INCUMBENT_WORD..][..8])?;
    }
    for (index, state_word) in hasher.sha256_prefix_midstate().into_iter().enumerate() {
        words[PREFIX_MIDSTATE_WORD + index] = state_word;
    }
    words[USE_MIDSTATE_WORD] = u32::from(use_midstate);

    for (index, bytes) in template.as_chunks::<4>().0.iter().enumerate() {
        words[CUDA_INPUT_HEADER_WORDS + index] = u32::from_be_bytes(*bytes);
    }
    if words[CUDA_INPUT_HEADER_WORDS + ABI_NONCE_WORD..CUDA_INPUT_HEADER_WORDS + ABI_NONCE_WORD + 4]
        .iter()
        .any(|word| *word != 0)
    {
        bail!("canonical ABI template unexpectedly contains a nonzero nonce");
    }
    Ok(words)
}

pub(crate) fn decode_batch_results(
    result_words: &[u32],
    first_nonce: u128,
    count: usize,
    workgroup_size: usize,
) -> Result<Vec<GpuCandidate>> {
    if count == 0
        || workgroup_size == 0
        || !workgroup_size.is_power_of_two()
        || workgroup_size > CUDA_MAX_WORKGROUP_SIZE
    {
        bail!("CUDA result decoder received an invalid batch or workgroup size");
    }
    let workgroup_count = count.div_ceil(workgroup_size);
    let expected_words = workgroup_count
        .checked_mul(CUDA_RESULT_WORDS)
        .context("CUDA result-buffer word count overflow")?;
    if result_words.len() != expected_words {
        bail!(
            "CUDA returned {} result words; expected {expected_words}",
            result_words.len()
        );
    }

    let mut candidates = Vec::with_capacity(workgroup_count);
    for workgroup_index in 0..workgroup_count {
        let base = workgroup_index * CUDA_RESULT_WORDS;
        match result_words[base] {
            0 => continue,
            1 => {}
            status => bail!("CUDA result group {workgroup_index} has invalid status {status}"),
        }
        let hash = words_to_hash(&result_words[base + 1..base + 9])?;
        let nonce = words_to_nonce(&result_words[base + 9..base + 13])?;
        let offset = nonce
            .checked_sub(first_nonce)
            .context("CUDA result nonce precedes its reserved batch")?;
        if offset >= count as u128 || usize::try_from(offset)? / workgroup_size != workgroup_index {
            bail!("CUDA workgroup reduction returned a nonce attributed to another group");
        }
        candidates.push(GpuCandidate {
            nonce,
            hash,
            workgroup_index,
        });
    }
    Ok(candidates)
}

fn copy_bytes_to_be_words(bytes: &[u8], words: &mut [u32]) -> Result<()> {
    if bytes.len() != words.len() * 4 {
        bail!("CUDA batch ABI byte/word lengths do not match");
    }
    for (word, chunk) in words.iter_mut().zip(bytes.as_chunks::<4>().0) {
        *word = u32::from_be_bytes(*chunk);
    }
    Ok(())
}

fn words_to_hash(words: &[u32]) -> Result<B256> {
    if words.len() != 8 {
        bail!("CUDA result hash does not contain exactly eight words");
    }
    let mut bytes = [0_u8; 32];
    for (index, word) in words.iter().enumerate() {
        bytes[index * 4..index * 4 + 4].copy_from_slice(&word.to_be_bytes());
    }
    Ok(B256::from(bytes))
}

fn words_to_nonce(words: &[u32]) -> Result<u128> {
    if words.len() != 4 {
        bail!("CUDA result nonce does not contain exactly four words");
    }
    let mut bytes = [0_u8; 16];
    for (index, word) in words.iter().enumerate() {
        bytes[index * 4..index * 4 + 4].copy_from_slice(&word.to_be_bytes());
    }
    Ok(u128::from_be_bytes(bytes))
}

#[cfg(test)]
mod tests {
    use super::{
        ABI_NONCE_WORD, CUDA_INPUT_HEADER_WORDS, CUDA_INPUT_WORDS, CUDA_MAX_WORKGROUP_SIZE,
        CUDA_RESULT_WORDS, decode_batch_results, encode_batch_input,
    };
    use crate::gpu::MAX_ABI_TEMPLATE_WORDS;
    use crate::{
        gpu::GpuCandidate,
        protocol::{WorkContext, WorkHasher},
    };
    use alloy_primitives::{Address, B256, U256};

    fn context(header_length: usize) -> WorkContext {
        WorkContext {
            chain_id: 1_439,
            contract: Address::with_last_byte(9),
            window_id: 17,
            seed: B256::with_last_byte(0x5a),
            miner: Address::with_last_byte(0xa5),
            header: (0..header_length)
                .map(|index| (index as u8).wrapping_mul(13))
                .collect(),
        }
    }

    #[test]
    fn cuda_host_and_kernel_abi_layouts_are_aligned() {
        let kernel = include_str!("cuda/sha256d.cu");
        assert_eq!(CUDA_INPUT_HEADER_WORDS, 32);
        assert_eq!(MAX_ABI_TEMPLATE_WORDS, 328);
        assert_eq!(CUDA_RESULT_WORDS, 13);
        assert_eq!(CUDA_MAX_WORKGROUP_SIZE, 256);
        assert_eq!(ABI_NONCE_WORD, 52);
        for definition in [
            "#define INPUT_HEADER_WORDS 32u",
            "#define TEMPLATE_WORDS 328u",
            "#define NONCE_WORD_START 52u",
            "#define RESULT_WORDS 13u",
            "#define MAX_WORKGROUP_SIZE 256u",
        ] {
            assert!(
                kernel.contains(definition),
                "kernel ABI is missing {definition}"
            );
        }
    }

    #[test]
    fn cuda_batch_encoding_preserves_abi_context_and_big_endian_nonce_limbs() {
        for header_length in [0, 1, 55, 56, 63, 64, 119, 120, 1_024] {
            let hasher = WorkHasher::new(&context(header_length)).unwrap();
            let nonce = u128::MAX - 7;
            let target = U256::from_be_bytes([0x7a; 32]);
            let incumbent_value = B256::with_last_byte(0xd3);
            let incumbent = Some(incumbent_value);
            let encoded = encode_batch_input(&hasher, nonce, 8, target, incumbent, true).unwrap();
            assert_eq!(encoded.len(), CUDA_INPUT_WORDS);
            assert_eq!(encoded[0], hasher.abi_template().len() as u32);
            assert_eq!(encoded[1], 8);
            let expected_nonce_words = nonce
                .to_be_bytes()
                .as_chunks::<4>()
                .0
                .iter()
                .map(|bytes| u32::from_be_bytes(*bytes))
                .collect::<Vec<_>>();
            assert_eq!(&encoded[2..6], expected_nonce_words.as_slice());
            assert_eq!(
                &encoded[6..14],
                target
                    .to_be_bytes::<32>()
                    .as_chunks::<4>()
                    .0
                    .iter()
                    .map(|bytes| u32::from_be_bytes(*bytes))
                    .collect::<Vec<_>>()
                    .as_slice()
            );
            assert_eq!(encoded[14], 1);
            assert_eq!(
                &encoded[15..23],
                incumbent_value
                    .0
                    .as_chunks::<4>()
                    .0
                    .iter()
                    .map(|bytes| u32::from_be_bytes(*bytes))
                    .collect::<Vec<_>>()
                    .as_slice()
            );
            assert_eq!(encoded[31], 1);
            assert_eq!(
                encoded[CUDA_INPUT_HEADER_WORDS + ABI_NONCE_WORD
                    ..CUDA_INPUT_HEADER_WORDS + ABI_NONCE_WORD + 4],
                [0; 4]
            );
            for (word, bytes) in encoded[CUDA_INPUT_HEADER_WORDS..]
                .iter()
                .zip(hasher.abi_template().as_chunks::<4>().0)
            {
                assert_eq!(*word, u32::from_be_bytes(*bytes));
            }
        }
    }

    #[test]
    fn cuda_batch_encoding_rejects_zero_and_overflowing_nonce_ranges() {
        let hasher = WorkHasher::new(&context(0)).unwrap();
        assert!(encode_batch_input(&hasher, 0, 0, U256::MAX, None, true).is_err());
        assert!(encode_batch_input(&hasher, u128::MAX, 2, U256::MAX, None, true).is_err());
        assert!(encode_batch_input(&hasher, u128::MAX, 1, U256::MAX, None, true).is_ok());
        let without_incumbent = encode_batch_input(&hasher, 0, 1, U256::MAX, None, false).unwrap();
        assert_eq!(without_incumbent[14], 0);
        assert!(without_incumbent[15..23].iter().all(|word| *word == 0));
        assert_eq!(without_incumbent[31], 0);
    }

    #[test]
    fn cuda_result_decoding_checks_hash_nonce_group_and_status() {
        let first_nonce = u128::from(u64::MAX) - 3;
        let hash = B256::with_last_byte(0x7c);
        let mut words = vec![0_u32; CUDA_RESULT_WORDS * 2];
        words[0] = 1;
        for (index, bytes) in hash.0.as_chunks::<4>().0.iter().enumerate() {
            words[1 + index] = u32::from_be_bytes(*bytes);
        }
        let nonce = first_nonce + 2;
        for (index, bytes) in nonce.to_be_bytes().as_chunks::<4>().0.iter().enumerate() {
            words[9 + index] = u32::from_be_bytes(*bytes);
        }
        let candidates = decode_batch_results(&words, first_nonce, 64, 32).unwrap();
        assert_eq!(
            candidates,
            [GpuCandidate {
                nonce,
                hash,
                workgroup_index: 0
            }]
        );

        words[0] = 2;
        assert!(decode_batch_results(&words, first_nonce, 64, 32).is_err());
        words[0] = 1;
        words[9] = u32::MAX;
        words[10] = u32::MAX;
        words[11] = u32::MAX;
        words[12] = u32::MAX;
        assert!(decode_batch_results(&words, first_nonce, 64, 32).is_err());
        assert!(decode_batch_results(&words[..words.len() - 1], first_nonce, 64, 32).is_err());
    }
}
