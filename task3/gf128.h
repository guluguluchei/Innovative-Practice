#ifndef GF128_H
#define GF128_H

#include <cstdint>
#include <cstddef>

#ifdef _MSC_VER
#include <intrin.h>
#else
#include <x86intrin.h>
#endif

#ifdef __PCLMUL__
#define GF128_HAS_PCLMUL 1
#else
#define GF128_HAS_PCLMUL 0
#endif

void gf128_mul_basic(uint8_t* result, const uint8_t* a, const uint8_t* b);

#if GF128_HAS_PCLMUL
void gf128_mul_pclmul(__m128i* result, __m128i a, __m128i b);
#endif

void gf128_mul_xts(uint8_t* result, const uint8_t* a);

void ghash_compute(uint8_t* tag, const uint8_t* H,
                   const uint8_t* aad, size_t aad_len,
                   const uint8_t* ciphertext, size_t ct_len);

#if GF128_HAS_PCLMUL
void ghash_compute_pclmul(uint8_t* tag, const __m128i H,
                          const uint8_t* aad, size_t aad_len,
                          const uint8_t* ciphertext, size_t ct_len);
#endif

inline void xor_block(uint8_t* out, const uint8_t* a, const uint8_t* b) {
    for (int i = 0; i < 16; i++) out[i] = a[i] ^ b[i];
}

inline void inc_counter(uint8_t* counter) {
    for (int i = 15; i >= 0; i--) {
        if (++counter[i] != 0) break;
    }
}

inline void inc_counter_n(uint8_t* counter, uint64_t n) {
    uint64_t val = 0;
    for (int i = 8; i < 16; i++) {
        val = (val << 8) | counter[i];
    }
    val += n;
    for (int i = 15; i >= 8; i--) {
        counter[i] = (uint8_t)(val & 0xFF);
        val >>= 8;
    }
    if (val) {
        for (int i = 7; i >= 0; i--) {
            if (val == 0) break;
            uint32_t tmp = counter[i] + (uint8_t)(val & 0xFF);
            counter[i] = (uint8_t)(tmp & 0xFF);
            val = (val >> 8) + (tmp >> 8);
        }
    }
}

#endif // GF128_H
