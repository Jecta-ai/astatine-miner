use alloy_primitives::{Address, B256, Bytes, U256};
use alloy_sol_types::SolValue;
use anyhow::{Result, bail};
use sha2::{Digest, Sha256, block_api::compress256};

pub const MAX_HEADER_LENGTH: usize = 1_024;
const NONCE_WORD_OFFSET: usize = 6 * 32;
const SHA256_PREFIX_BLOCKS: usize = NONCE_WORD_OFFSET / 64;
const SHA256_PREFIX_BYTES: usize = SHA256_PREFIX_BLOCKS * 64;
const WORK_DOMAIN_V2: [u8; 32] = *b"ASTATINE_WORK_V2\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";
const SHA256_INITIAL_STATE: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

pub fn work_domain_v2() -> B256 {
    B256::from(WORK_DOMAIN_V2)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkContext {
    pub chain_id: u64,
    pub contract: Address,
    pub window_id: u64,
    pub seed: B256,
    pub miner: Address,
    pub header: Vec<u8>,
}

/// A pre-encoded ABI work tuple whose only per-hash mutation is the nonce word.
#[derive(Clone, Debug)]
pub struct WorkHasher {
    template: Vec<u8>,
    sha256_prefix_midstate: [u32; 8],
}

impl WorkHasher {
    pub fn new(context: &WorkContext) -> Result<Self> {
        if context.header.len() > MAX_HEADER_LENGTH {
            bail!("work header exceeds the protocol maximum of {MAX_HEADER_LENGTH} bytes");
        }

        let template = (
            work_domain_v2(),
            U256::from(context.chain_id),
            context.contract,
            context.window_id,
            context.seed,
            context.miner,
            0u128,
            Bytes::copy_from_slice(&context.header),
        )
            .abi_encode_params();

        if template.len() < NONCE_WORD_OFFSET + 32 || template.len() < SHA256_PREFIX_BYTES {
            bail!("Alloy produced a malformed Astatine work ABI tuple");
        }
        let mut sha256_prefix_midstate = SHA256_INITIAL_STATE;
        let prefix_blocks = template[..SHA256_PREFIX_BYTES].as_chunks::<64>().0;
        if prefix_blocks.len() != SHA256_PREFIX_BLOCKS {
            bail!("Alloy produced an ABI prefix that is not a whole SHA-256 block count");
        }
        compress256(&mut sha256_prefix_midstate, prefix_blocks);
        Ok(Self {
            template,
            sha256_prefix_midstate,
        })
    }

    pub fn hash_into(&self, nonce: u128, scratch: &mut [u8]) -> Result<B256> {
        if scratch.len() < self.template.len() {
            bail!("work hash scratch space is too small");
        }
        let encoded = &mut scratch[..self.template.len()];
        encoded.copy_from_slice(&self.template);
        encoded[NONCE_WORD_OFFSET..NONCE_WORD_OFFSET + 16].fill(0);
        encoded[NONCE_WORD_OFFSET + 16..NONCE_WORD_OFFSET + 32]
            .copy_from_slice(&nonce.to_be_bytes());

        let first = Sha256::digest(encoded);
        let second = Sha256::digest(first);
        Ok(B256::from_slice(&second))
    }

    pub fn hash(&self, nonce: u128) -> B256 {
        let mut scratch = vec![0u8; self.template.len()];
        self.hash_into(nonce, &mut scratch)
            .expect("scratch buffer is sized from the encoded work tuple")
    }

    pub fn scratch_len(&self) -> usize {
        self.template.len()
    }

    /// Canonical ABI encoding with the nonce word set to zero.
    ///
    /// GPU backends use this template and replace only the four big-endian
    /// 32-bit words that encode the low 128 bits of the ABI `uint128` nonce.
    pub(crate) fn abi_template(&self) -> &[u8] {
        &self.template
    }

    /// SHA-256 chaining state after the three invariant 64-byte ABI blocks
    /// preceding the nonce word. GPU hashing must resume at byte offset 192;
    /// this is an internal compression state, not a finalized digest.
    pub(crate) fn sha256_prefix_midstate(&self) -> [u32; 8] {
        self.sha256_prefix_midstate
    }
}

pub fn meets_target(hash: B256, target: U256) -> bool {
    U256::from_be_bytes(hash.0) <= target
}

pub fn beats_incumbent(hash: B256, incumbent: B256) -> bool {
    hash < incumbent
}

#[cfg(test)]
mod tests {
    use super::{WorkContext, WorkHasher, beats_incumbent, meets_target};
    use alloy_primitives::{Address, B256, U256};
    use std::str::FromStr;

    // Canonical fixture: astatineEVM/evm/test/vectors/v2_work_vectors.json
    // (read-only reference; no Go implementation or dependency source is copied here).
    fn canonical_work() -> (WorkContext, u128, B256) {
        (
            WorkContext {
                chain_id: 31_337,
                contract: Address::from_str("0x1234567890abcdef1234567890abcdef12345678").unwrap(),
                window_id: 42,
                seed: B256::from_str(
                    "0x1111111111111111111111111111111111111111111111111111111111111111",
                )
                .unwrap(),
                miner: Address::from_str("0x1111111111111111111111111111111111111111").unwrap(),
                header: hex_header("4153544154494e4500ff"),
            },
            1_339_673_755_198_158_349_044_581_307_228_491_536,
            B256::from_str("0x373d4c8d0a1f1dc9efd7e2e5d1a576718b65713f3d006f2a584cc722082323ec")
                .unwrap(),
        )
    }

    fn hex_header(value: &str) -> Vec<u8> {
        (0..value.len())
            .step_by(2)
            .map(|index| u8::from_str_radix(&value[index..index + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn work_hash_matches_canonical_solidity_vector() {
        let (context, nonce, expected) = canonical_work();
        let hasher = WorkHasher::new(&context).unwrap();
        let mut scratch = vec![0u8; hasher.template.len()];
        assert_eq!(hasher.hash_into(nonce, &mut scratch).unwrap(), expected);
    }

    #[test]
    fn target_comparison_is_full_width_inclusive_and_incumbent_is_strict() {
        let (_, _, hash) = canonical_work();
        assert!(meets_target(hash, U256::MAX));
        assert!(meets_target(hash, U256::from_be_bytes(hash.0)));
        assert!(!meets_target(hash, U256::ZERO));
        assert!(!beats_incumbent(hash, hash));
        assert!(beats_incumbent(B256::ZERO, hash));
    }

    #[test]
    fn abi_hash_context_is_domain_separated() {
        let (context, nonce, expected) = canonical_work();
        let mut changed = context.clone();
        changed.chain_id += 1;
        assert_ne!(WorkHasher::new(&changed).unwrap().hash(nonce), expected);
        changed = context;
        changed.header.push(0);
        assert_ne!(WorkHasher::new(&changed).unwrap().hash(nonce), expected);
    }

    #[test]
    fn sha256_midstate_tracks_the_abi_prefix_and_ignores_dynamic_header_bytes() {
        let (context, _, _) = canonical_work();
        let original = WorkHasher::new(&context).unwrap().sha256_prefix_midstate();

        let mut changed_header = context.clone();
        changed_header.header.push(0x5a);
        assert_eq!(
            WorkHasher::new(&changed_header)
                .unwrap()
                .sha256_prefix_midstate(),
            original,
            "dynamic header bytes follow the nonce and must not affect the 192-byte prefix"
        );

        let mut changed_chain = context;
        changed_chain.chain_id += 1;
        assert_ne!(
            WorkHasher::new(&changed_chain)
                .unwrap()
                .sha256_prefix_midstate(),
            original,
            "a work-context change in the ABI prefix must invalidate the cached midstate"
        );
    }
}
