const INPUT_HEADER_WORDS: u32 = 31u;
// WorkHasher's ABI uint128 is at byte offset 6*32. Its upper 64 bits occupy
// words 48..51 (zero); nonce limbs, most-significant first, occupy 52..55.
const NONCE_WORD_START: u32 = 52u;
// SHA-256 can resume from the cached state after the three invariant ABI blocks.
const SHA256_PREFIX_BLOCKS: u32 = 3u;
const SHA256_PREFIX_WORDS: u32 = SHA256_PREFIX_BLOCKS * 16u;
const MIDSTATE_WORD_START: u32 = 23u;
const RESULT_WORDS: u32 = 13u;
override WORKGROUP_SIZE: u32 = 32u;
override USE_MIDSTATE: u32 = 1u;

const INITIAL_STATE: array<u32, 8> = array<u32, 8>(
    0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au,
    0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u,
);

const ROUND_CONSTANTS: array<u32, 64> = array<u32, 64>(
    0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u,
    0x3956c25bu, 0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u,
    0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u,
    0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u,
    0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu,
    0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
    0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u,
    0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u,
    0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u,
    0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
    0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u,
    0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
    0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u,
    0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u,
    0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u,
    0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u,
);

@group(0) @binding(0)
var<storage, read> input_words: array<u32>;

@group(0) @binding(1)
var<storage, read_write> result_words: array<u32>;

var<workgroup> candidate_valid: array<u32, WORKGROUP_SIZE>;
var<workgroup> candidate_hashes: array<u32, WORKGROUP_SIZE * 8u>;
var<workgroup> candidate_nonces: array<u32, WORKGROUP_SIZE * 4u>;

fn rotate_right(value: u32, shift: u32) -> u32 {
    return (value >> shift) | (value << (32u - shift));
}

fn compress_sha256(state: array<u32, 8>, block: array<u32, 16>) -> array<u32, 8> {
    var schedule: array<u32, 64>;
    for (var i = 0u; i < 16u; i = i + 1u) {
        schedule[i] = block[i];
    }
    for (var i = 16u; i < 64u; i = i + 1u) {
        let x = schedule[i - 15u];
        let y = schedule[i - 2u];
        let small0 = rotate_right(x, 7u) ^ rotate_right(x, 18u) ^ (x >> 3u);
        let small1 = rotate_right(y, 17u) ^ rotate_right(y, 19u) ^ (y >> 10u);
        schedule[i] = schedule[i - 16u] + small0 + schedule[i - 7u] + small1;
    }

    var a = state[0];
    var b = state[1];
    var c = state[2];
    var d = state[3];
    var e = state[4];
    var f = state[5];
    var g = state[6];
    var h = state[7];
    for (var i = 0u; i < 64u; i = i + 1u) {
        let big1 = rotate_right(e, 6u) ^ rotate_right(e, 11u) ^ rotate_right(e, 25u);
        let choose = (e & f) ^ ((~e) & g);
        let temp1 = h + big1 + choose + ROUND_CONSTANTS[i] + schedule[i];
        let big0 = rotate_right(a, 2u) ^ rotate_right(a, 13u) ^ rotate_right(a, 22u);
        let majority = (a & b) ^ (a & c) ^ (b & c);
        let temp2 = big0 + majority;
        h = g;
        g = f;
        f = e;
        e = d + temp1;
        d = c;
        c = b;
        b = a;
        a = temp1 + temp2;
    }

    return array<u32, 8>(
        state[0] + a, state[1] + b, state[2] + c, state[3] + d,
        state[4] + e, state[5] + f, state[6] + g, state[7] + h,
    );
}

fn nonce_for(invocation: u32) -> array<u32, 4> {
    var nonce = array<u32, 4>(input_words[2], input_words[3], input_words[4], input_words[5]);
    var carry = invocation;
    for (var limb = 0u; limb < 4u; limb = limb + 1u) {
        let index = 3u - limb;
        let previous = nonce[index];
        let sum = previous + carry;
        nonce[index] = sum;
        carry = select(0u, 1u, sum < previous);
        if (carry == 0u) {
            break;
        }
    }
    return nonce;
}

fn hash_work(nonce: array<u32, 4>) -> array<u32, 8> {
    let message_bytes = input_words[0];
    let message_words = message_bytes / 4u;
    let block_count = (message_bytes + 72u) / 64u;
    var state = INITIAL_STATE;
    var first_block = 0u;
    var template_prefix_words = 0u;
    if (USE_MIDSTATE != 0u) {
        state = array<u32, 8>(
            input_words[MIDSTATE_WORD_START],
            input_words[MIDSTATE_WORD_START + 1u],
            input_words[MIDSTATE_WORD_START + 2u],
            input_words[MIDSTATE_WORD_START + 3u],
            input_words[MIDSTATE_WORD_START + 4u],
            input_words[MIDSTATE_WORD_START + 5u],
            input_words[MIDSTATE_WORD_START + 6u],
            input_words[MIDSTATE_WORD_START + 7u],
        );
        first_block = SHA256_PREFIX_BLOCKS;
        template_prefix_words = SHA256_PREFIX_WORDS;
    }

    for (var block_index = first_block; block_index < block_count; block_index = block_index + 1u) {
        var block: array<u32, 16>;
        for (var word_index = 0u; word_index < 16u; word_index = word_index + 1u) {
            let absolute_word = block_index * 16u + word_index;
            var word = 0u;
            if (absolute_word < message_words) {
                if (absolute_word >= NONCE_WORD_START && absolute_word < NONCE_WORD_START + 4u) {
                    word = nonce[absolute_word - NONCE_WORD_START];
                } else {
                    word = input_words[INPUT_HEADER_WORDS + absolute_word - template_prefix_words];
                }
            } else if (absolute_word == message_words) {
                word = 0x80000000u;
            } else if (absolute_word == block_count * 16u - 1u) {
                word = message_bytes * 8u;
            }
            block[word_index] = word;
        }
        state = compress_sha256(state, block);
    }

    var second_block: array<u32, 16>;
    for (var i = 0u; i < 16u; i = i + 1u) {
        second_block[i] = 0u;
    }
    for (var i = 0u; i < 8u; i = i + 1u) {
        second_block[i] = state[i];
    }
    second_block[8] = 0x80000000u;
    second_block[15] = 256u;
    return compress_sha256(INITIAL_STATE, second_block);
}

fn hash_raw_sha256(message_bytes: u32) -> array<u32, 8> {
    let message_words = (message_bytes + 3u) / 4u;
    let block_count = (message_bytes + 72u) / 64u;
    var state = INITIAL_STATE;
    for (var block_index = 0u; block_index < block_count; block_index = block_index + 1u) {
        var block: array<u32, 16>;
        for (var word_index = 0u; word_index < 16u; word_index = word_index + 1u) {
            let absolute_word = block_index * 16u + word_index;
            var word = 0u;
            if (absolute_word < message_words) {
                word = input_words[INPUT_HEADER_WORDS + absolute_word];
                if absolute_word == message_bytes / 4u && message_bytes % 4u != 0u {
                    let pad_shift = (3u - (message_bytes % 4u)) * 8u;
                    word = word | (0x80u << pad_shift);
                }
            } else if absolute_word == message_words && message_bytes % 4u == 0u {
                word = 0x80000000u;
            } else if absolute_word == block_count * 16u - 2u {
                word = 0u;
            } else if absolute_word == block_count * 16u - 1u {
                word = message_bytes * 8u;
            }
            block[word_index] = word;
        }
        state = compress_sha256(state, block);
    }
    return state;
}

fn hash_meets_target(hash: array<u32, 8>) -> bool {
    for (var i = 0u; i < 8u; i = i + 1u) {
        let target_word = input_words[6u + i];
        if (hash[i] < target_word) {
            return true;
        }
        if (hash[i] > target_word) {
            return false;
        }
    }
    return true;
}

fn beats_incumbent(hash: array<u32, 8>) -> bool {
    if (input_words[14] == 0u) {
        return true;
    }
    for (var i = 0u; i < 8u; i = i + 1u) {
        let incumbent = input_words[15u + i];
        if (hash[i] < incumbent) {
            return true;
        }
        if (hash[i] > incumbent) {
            return false;
        }
    }
    return false;
}

fn candidate_is_better(left: u32, right: u32) -> bool {
    for (var word = 0u; word < 8u; word = word + 1u) {
        let left_word = candidate_hashes[left * 8u + word];
        let right_word = candidate_hashes[right * 8u + word];
        if (left_word < right_word) {
            return true;
        }
        if (left_word > right_word) {
            return false;
        }
    }
    for (var limb = 0u; limb < 4u; limb = limb + 1u) {
        let left_limb = candidate_nonces[left * 4u + limb];
        let right_limb = candidate_nonces[right * 4u + limb];
        if (left_limb < right_limb) {
            return true;
        }
        if (left_limb > right_limb) {
            return false;
        }
    }
    return false;
}

fn copy_candidate(destination: u32, source: u32) {
    candidate_valid[destination] = candidate_valid[source];
    for (var word = 0u; word < 8u; word = word + 1u) {
        candidate_hashes[destination * 8u + word] = candidate_hashes[source * 8u + word];
    }
    for (var limb = 0u; limb < 4u; limb = limb + 1u) {
        candidate_nonces[destination * 4u + limb] = candidate_nonces[source * 4u + limb];
    }
}

@compute @workgroup_size(WORKGROUP_SIZE)
fn main(
    @builtin(global_invocation_id) global_id: vec3<u32>,
    @builtin(local_invocation_index) local_index: u32,
    @builtin(workgroup_id) workgroup_id: vec3<u32>,
) {
    let invocation = global_id.x;
    candidate_valid[local_index] = 0u;
    if (invocation < input_words[1]) {
        let nonce = nonce_for(invocation);
        let hash = hash_work(nonce);
        if (hash_meets_target(hash) && beats_incumbent(hash)) {
            candidate_valid[local_index] = 1u;
            for (var word = 0u; word < 8u; word = word + 1u) {
                candidate_hashes[local_index * 8u + word] = hash[word];
            }
            for (var limb = 0u; limb < 4u; limb = limb + 1u) {
                candidate_nonces[local_index * 4u + limb] = nonce[limb];
            }
        }
    }

    workgroupBarrier();
    var reduction_stride = WORKGROUP_SIZE / 2u;
    loop {
        if (local_index < reduction_stride) {
            let other = local_index + reduction_stride;
            if (candidate_valid[other] != 0u
                && (candidate_valid[local_index] == 0u || candidate_is_better(other, local_index))) {
                copy_candidate(local_index, other);
            }
        }
        workgroupBarrier();
        if (reduction_stride == 1u) {
            break;
        }
        reduction_stride = reduction_stride / 2u;
    }

    if (local_index == 0u) {
        let result_offset = workgroup_id.x * RESULT_WORDS;
        result_words[result_offset] = candidate_valid[0];
        if (candidate_valid[0] != 0u) {
            for (var word = 0u; word < 8u; word = word + 1u) {
                result_words[result_offset + 1u + word] = candidate_hashes[word];
            }
            for (var limb = 0u; limb < 4u; limb = limb + 1u) {
                result_words[result_offset + 9u + limb] = candidate_nonces[limb];
            }
        }
    }
}

@compute @workgroup_size(1)
fn sha256_raw_test(@builtin(global_invocation_id) global_id: vec3<u32>) {
    if (global_id.x != 0u) {
        return;
    }
    result_words[0] = 1u;
    let digest = hash_raw_sha256(input_words[0]);
    for (var i = 0u; i < 8u; i = i + 1u) {
        result_words[i + 1u] = digest[i];
    }
}
