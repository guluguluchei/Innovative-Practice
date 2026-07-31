#include "gf128.h"
#include <cstring>

static void shr_block(uint8_t* out, const uint8_t* in) {
    uint8_t carry = 0;
    for (int i = 0; i < 16; i++) {
        uint8_t next_carry = in[i] & 1;
        out[i] = (in[i] >> 1) | (carry << 7);
        carry = next_carry;
    }
}

static void shl_block_le(uint8_t* out, const uint8_t* in) {
    uint8_t carry = 0;
    for (int i = 15; i >= 0; i--) {
        uint8_t next_carry = (in[i] >> 7) & 1;
        out[i] = (in[i] << 1) | carry;
        carry = next_carry;
    }
}

void gf128_mul_basic(uint8_t* result, const uint8_t* a, const uint8_t* b) {
    uint8_t V[16], Z[16];
    memcpy(V, b, 16);
    memset(Z, 0, 16);

    for (int i = 0; i < 128; i++) {
        int byte_idx = i / 8;
        int bit_idx = 7 - (i % 8);

        if (a[byte_idx] & (1 << bit_idx)) {
            for (int j = 0; j < 16; j++) Z[j] ^= V[j];
        }

        uint8_t lsb = V[15] & 1;
        shr_block(V, V);
        if (lsb) {
            V[0] ^= 0xE1;
        }
    }

    memcpy(result, Z, 16);
}

void gf128_mul_xts(uint8_t* result, const uint8_t* a) {
    uint8_t carry = (a[15] >> 7) & 1;
    shl_block_le(result, a);
    if (carry) {
        result[0] ^= 0x87;
    }
}

void ghash_compute(uint8_t* tag, const uint8_t* H,
                   const uint8_t* aad, size_t aad_len,
                   const uint8_t* ciphertext, size_t ct_len) {
    uint8_t X[16];
    memset(X, 0, 16);

    size_t i;
    for (i = 0; i + 16 <= aad_len; i += 16) {
        for (int j = 0; j < 16; j++) X[j] ^= aad[i + j];
        gf128_mul_basic(X, X, H);
    }
    if (i < aad_len) {
        uint8_t block[16];
        memset(block, 0, 16);
        memcpy(block, aad + i, aad_len - i);
        for (int j = 0; j < 16; j++) X[j] ^= block[j];
        gf128_mul_basic(X, X, H);
    }

    for (i = 0; i + 16 <= ct_len; i += 16) {
        for (int j = 0; j < 16; j++) X[j] ^= ciphertext[i + j];
        gf128_mul_basic(X, X, H);
    }
    if (i < ct_len) {
        uint8_t block[16];
        memset(block, 0, 16);
        memcpy(block, ciphertext + i, ct_len - i);
        for (int j = 0; j < 16; j++) X[j] ^= block[j];
        gf128_mul_basic(X, X, H);
    }

    uint8_t len_block[16];
    memset(len_block, 0, 16);
    uint64_t aad_bits = (uint64_t)aad_len * 8;
    uint64_t ct_bits = (uint64_t)ct_len * 8;
    len_block[8]  = (aad_bits >> 56) & 0xFF;
    len_block[9]  = (aad_bits >> 48) & 0xFF;
    len_block[10] = (aad_bits >> 40) & 0xFF;
    len_block[11] = (aad_bits >> 32) & 0xFF;
    len_block[12] = (ct_bits >> 56) & 0xFF;
    len_block[13] = (ct_bits >> 48) & 0xFF;
    len_block[14] = (ct_bits >> 40) & 0xFF;
    len_block[15] = (ct_bits >> 32) & 0xFF;

    for (int j = 0; j < 16; j++) X[j] ^= len_block[j];
    gf128_mul_basic(X, X, H);

    memcpy(tag, X, 16);
}

#if GF128_HAS_PCLMUL

void gf128_mul_pclmul(__m128i* result, __m128i a, __m128i b) {
    __m128i a_hi = _mm_srli_si128(a, 8);
    __m128i a_lo = _mm_slli_si128(a, 8);
    a_lo = _mm_srli_si128(a_lo, 8);
    __m128i b_hi = _mm_srli_si128(b, 8);
    __m128i b_lo = _mm_slli_si128(b, 8);
    b_lo = _mm_srli_si128(b_lo, 8);

    __m128i c0 = _mm_clmulepi64_si128(a_lo, b_lo, 0x00);
    __m128i c1 = _mm_clmulepi64_si128(a_lo, b_hi, 0x00);
    __m128i c2 = _mm_clmulepi64_si128(a_hi, b_lo, 0x00);
    __m128i c3 = _mm_clmulepi64_si128(a_hi, b_hi, 0x00);

    __m128i mid = _mm_xor_si128(c1, c2);
    __m128i lo = _mm_xor_si128(c0, _mm_slli_si128(mid, 8));
    __m128i hi = _mm_xor_si128(c3, _mm_srli_si128(mid, 8));

    __m128i tmp;

    tmp = _mm_srli_si128(hi, 8);
    __m128i r1 = _mm_clmulepi64_si128(tmp, _mm_set_epi64x(0, 0xE100000000000000ULL), 0x00);
    __m128i r2 = _mm_clmulepi64_si128(hi, _mm_set_epi64x(0, 0xE100000000000000ULL), 0x01);

    *result = _mm_xor_si128(_mm_xor_si128(lo, r1), r2);
}

void ghash_compute_pclmul(uint8_t* tag, const __m128i H,
                          const uint8_t* aad, size_t aad_len,
                          const uint8_t* ciphertext, size_t ct_len) {
    __m128i X = _mm_setzero_si128();

    size_t i;
    for (i = 0; i + 16 <= aad_len; i += 16) {
        __m128i block = _mm_loadu_si128((const __m128i*)(aad + i));
        X = _mm_xor_si128(X, block);
        gf128_mul_pclmul(&X, X, H);
    }
    if (i < aad_len) {
        uint8_t block[16];
        memset(block, 0, 16);
        memcpy(block, aad + i, aad_len - i);
        __m128i blk = _mm_loadu_si128((const __m128i*)block);
        X = _mm_xor_si128(X, blk);
        gf128_mul_pclmul(&X, X, H);
    }

    for (i = 0; i + 16 <= ct_len; i += 16) {
        __m128i block = _mm_loadu_si128((const __m128i*)(ciphertext + i));
        X = _mm_xor_si128(X, block);
        gf128_mul_pclmul(&X, X, H);
    }
    if (i < ct_len) {
        uint8_t block[16];
        memset(block, 0, 16);
        memcpy(block, ciphertext + i, ct_len - i);
        __m128i blk = _mm_loadu_si128((const __m128i*)block);
        X = _mm_xor_si128(X, blk);
        gf128_mul_pclmul(&X, X, H);
    }

    uint8_t len_block[16];
    memset(len_block, 0, 16);
    uint64_t aad_bits = (uint64_t)aad_len * 8;
    uint64_t ct_bits = (uint64_t)ct_len * 8;
    len_block[8]  = (aad_bits >> 56) & 0xFF;
    len_block[9]  = (aad_bits >> 48) & 0xFF;
    len_block[10] = (aad_bits >> 40) & 0xFF;
    len_block[11] = (aad_bits >> 32) & 0xFF;
    len_block[12] = (ct_bits >> 56) & 0xFF;
    len_block[13] = (ct_bits >> 48) & 0xFF;
    len_block[14] = (ct_bits >> 40) & 0xFF;
    len_block[15] = (ct_bits >> 32) & 0xFF;

    __m128i lb = _mm_loadu_si128((const __m128i*)len_block);
    X = _mm_xor_si128(X, lb);
    gf128_mul_pclmul(&X, X, H);

    _mm_storeu_si128((__m128i*)tag, X);
}
#endif // GF128_HAS_PCLMUL
