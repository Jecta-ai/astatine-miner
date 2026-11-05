// SPDX-License-Identifier: MIT

typedef unsigned int u32;

#define INPUT_HEADER_WORDS 32u
#define TEMPLATE_WORDS 328u
#define NONCE_WORD_START 52u
#define SHA256_PREFIX_BLOCKS 3u
#define RESULT_WORDS 13u
#define MAX_WORKGROUP_SIZE 256u

__constant__ u32 SHA256_INITIAL_STATE[8] = {
    0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au,
    0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u,
};

__constant__ u32 SHA256_ROUND_CONSTANTS[64] = {
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
};

__device__ __forceinline__ u32 rotate_right(u32 value, u32 shift) {
    return (value >> shift) | (value << (32u - shift));
}

__device__ __forceinline__ u32 small_sigma0(u32 value) {
    return rotate_right(value, 7u) ^ rotate_right(value, 18u) ^ (value >> 3u);
}

__device__ __forceinline__ u32 small_sigma1(u32 value) {
    return rotate_right(value, 17u) ^ rotate_right(value, 19u) ^ (value >> 10u);
}

__device__ __forceinline__ u32 big_sigma0(u32 value) {
    return rotate_right(value, 2u) ^ rotate_right(value, 13u) ^ rotate_right(value, 22u);
}

__device__ __forceinline__ u32 big_sigma1(u32 value) {
    return rotate_right(value, 6u) ^ rotate_right(value, 11u) ^ rotate_right(value, 25u);
}

__device__ __forceinline__ void compress_sha256(u32 state[8], const u32 block[16]) {
    u32 schedule[16];
#pragma unroll
    for (u32 i = 0u; i < 16u; ++i) {
        schedule[i] = block[i];
    }

    u32 a = state[0];
    u32 b = state[1];
    u32 c = state[2];
    u32 d = state[3];
    u32 e = state[4];
    u32 f = state[5];
    u32 g = state[6];
    u32 h = state[7];

#pragma unroll 64
    for (u32 round = 0u; round < 64u; ++round) {
        if (round >= 16u) {
            const u32 x = schedule[(round - 15u) & 15u];
            const u32 y = schedule[(round - 2u) & 15u];
            schedule[round & 15u] = schedule[(round - 16u) & 15u]
                + small_sigma0(x)
                + schedule[(round - 7u) & 15u]
                + small_sigma1(y);
        }
        const u32 word = schedule[round & 15u];
        const u32 choose = (e & f) ^ ((~e) & g);
        const u32 temp1 = h + big_sigma1(e) + choose + SHA256_ROUND_CONSTANTS[round] + word;
        const u32 majority = (a & b) ^ (a & c) ^ (b & c);
        const u32 temp2 = big_sigma0(a) + majority;
        h = g;
        g = f;
        f = e;
        e = d + temp1;
        d = c;
        c = b;
        b = a;
        a = temp1 + temp2;
    }

    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
    state[4] += e;
    state[5] += f;
    state[6] += g;
    state[7] += h;
}

__device__ __forceinline__ void add_nonce_offset(
    const u32 first_nonce[4],
    u32 offset,
    u32 nonce[4]
) {
    nonce[0] = first_nonce[0];
    nonce[1] = first_nonce[1];
    nonce[2] = first_nonce[2];
    nonce[3] = first_nonce[3];
    u32 carry = offset;
#pragma unroll
    for (int limb = 3; limb >= 0; --limb) {
        const u32 previous = nonce[limb];
        const u32 sum = previous + carry;
        nonce[limb] = sum;
        carry = (sum < previous) ? 1u : 0u;
        if (carry == 0u) {
            break;
        }
    }
}

__device__ __forceinline__ void hash_work(
    const u32* input,
    const u32 nonce[4],
    u32 digest[8]
) {
    const u32 message_bytes = input[0];
    const u32 message_words = message_bytes / 4u;
    const u32 block_count = (message_bytes + 72u) / 64u;
    const bool use_midstate = input[31] != 0u;
    u32 state[8];
    u32 first_block = 0u;

    if (use_midstate) {
#pragma unroll
        for (u32 i = 0u; i < 8u; ++i) {
            state[i] = input[23u + i];
        }
        first_block = SHA256_PREFIX_BLOCKS;
    } else {
#pragma unroll
        for (u32 i = 0u; i < 8u; ++i) {
            state[i] = SHA256_INITIAL_STATE[i];
        }
    }

    for (u32 block_index = first_block; block_index < block_count; ++block_index) {
        u32 block[16];
#pragma unroll
        for (u32 word_index = 0u; word_index < 16u; ++word_index) {
            const u32 absolute_word = block_index * 16u + word_index;
            u32 word = 0u;
            if (absolute_word < message_words) {
                if (absolute_word >= NONCE_WORD_START
                    && absolute_word < NONCE_WORD_START + 4u) {
                    word = nonce[absolute_word - NONCE_WORD_START];
                } else {
                    word = input[INPUT_HEADER_WORDS + absolute_word];
                }
            } else if (absolute_word == message_words) {
                word = 0x80000000u;
            } else if (absolute_word == block_count * 16u - 1u) {
                word = message_bytes * 8u;
            }
            block[word_index] = word;
        }
        compress_sha256(state, block);
    }

    u32 second_block[16];
#pragma unroll
    for (u32 i = 0u; i < 16u; ++i) {
        second_block[i] = 0u;
    }
#pragma unroll
    for (u32 i = 0u; i < 8u; ++i) {
        second_block[i] = state[i];
    }
    second_block[8] = 0x80000000u;
    second_block[15] = 256u;
    for (u32 i = 0u; i < 8u; ++i) {
        digest[i] = SHA256_INITIAL_STATE[i];
    }
    compress_sha256(digest, second_block);
}

__device__ __forceinline__ bool meets_target(const u32 hash[8], const u32 target[8]) {
#pragma unroll
    for (u32 i = 0u; i < 8u; ++i) {
        if (hash[i] < target[i]) {
            return true;
        }
        if (hash[i] > target[i]) {
            return false;
        }
    }
    return true;
}

__device__ __forceinline__ bool beats_incumbent(const u32 hash[8], const u32* input) {
    if (input[14] == 0u) {
        return true;
    }
#pragma unroll
    for (u32 i = 0u; i < 8u; ++i) {
        const u32 incumbent = input[15u + i];
        if (hash[i] < incumbent) {
            return true;
        }
        if (hash[i] > incumbent) {
            return false;
        }
    }
    return false;
}

__device__ __forceinline__ bool candidate_is_better(
    u32 left,
    u32 right,
    const u32 hashes[MAX_WORKGROUP_SIZE][8],
    const u32 nonces[MAX_WORKGROUP_SIZE][4]
) {
#pragma unroll
    for (u32 word = 0u; word < 8u; ++word) {
        if (hashes[left][word] < hashes[right][word]) {
            return true;
        }
        if (hashes[left][word] > hashes[right][word]) {
            return false;
        }
    }
#pragma unroll
    for (u32 limb = 0u; limb < 4u; ++limb) {
        if (nonces[left][limb] < nonces[right][limb]) {
            return true;
        }
        if (nonces[left][limb] > nonces[right][limb]) {
            return false;
        }
    }
    return false;
}

extern "C" __global__ void astatine_cuda_sha256d_batch(
    const u32* input,
    u32* output
) {
    __shared__ u32 valid[MAX_WORKGROUP_SIZE];
    __shared__ u32 hashes[MAX_WORKGROUP_SIZE][8];
    __shared__ u32 nonces[MAX_WORKGROUP_SIZE][4];

    const u32 local = threadIdx.x;
    const u32 invocation = blockIdx.x * blockDim.x + local;
    valid[local] = 0u;
    if (invocation < input[1]) {
        u32 nonce[4];
        u32 hash[8];
        add_nonce_offset(&input[2], invocation, nonce);
        hash_work(input, nonce, hash);
        if (meets_target(hash, &input[6]) && beats_incumbent(hash, input)) {
            valid[local] = 1u;
#pragma unroll
            for (u32 word = 0u; word < 8u; ++word) {
                hashes[local][word] = hash[word];
            }
#pragma unroll
            for (u32 limb = 0u; limb < 4u; ++limb) {
                nonces[local][limb] = nonce[limb];
            }
        }
    }

    __syncthreads();
    for (u32 stride = blockDim.x / 2u; stride > 0u; stride >>= 1u) {
        if (local < stride && valid[local + stride] != 0u
            && (valid[local] == 0u
                || candidate_is_better(local + stride, local, hashes, nonces))) {
            valid[local] = 1u;
#pragma unroll
            for (u32 word = 0u; word < 8u; ++word) {
                hashes[local][word] = hashes[local + stride][word];
            }
#pragma unroll
            for (u32 limb = 0u; limb < 4u; ++limb) {
                nonces[local][limb] = nonces[local + stride][limb];
            }
        }
        __syncthreads();
    }

    if (local == 0u) {
        const u32 base = blockIdx.x * RESULT_WORDS;
        output[base] = valid[0];
        if (valid[0] != 0u) {
#pragma unroll
            for (u32 word = 0u; word < 8u; ++word) {
                output[base + 1u + word] = hashes[0][word];
            }
#pragma unroll
            for (u32 limb = 0u; limb < 4u; ++limb) {
                output[base + 9u + limb] = nonces[0][limb];
            }
        }
    }
}
