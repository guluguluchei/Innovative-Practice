#include "aes.h"
#include <cstring>
#include <wmmintrin.h>

AES_NI::AES_NI() : nr_(0) {
    memset(round_keys_enc_, 0, sizeof(round_keys_enc_));
    memset(round_keys_dec_, 0, sizeof(round_keys_dec_));
}

AES_NI::~AES_NI() {}

static inline __m128i aes128_key_expand(__m128i key, __m128i rcon) {
    key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
    key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
    key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
    return _mm_xor_si128(key, rcon);
}

#define AESKEYGENASSIST(x, rcon) _mm_aeskeygenassist_si128(x, rcon)

static void aesni_key_expansion(const uint8_t* key, __m128i* ek, __m128i* dk,
                                 size_t key_len, size_t& nr) {
    nr = 10;
    if (key_len == 24) nr = 12;
    if (key_len == 32) nr = 14;

    __m128i temp;

    if (key_len == 16) {
        ek[0] = _mm_loadu_si128((const __m128i*)key);

        temp = AESKEYGENASSIST(ek[0], 0);
        ek[1] = aes128_key_expand(ek[0], _mm_shuffle_epi32(temp, 0xFF));
        temp = AESKEYGENASSIST(ek[1], 1);
        ek[2] = aes128_key_expand(ek[1], _mm_shuffle_epi32(temp, 0xFF));
        temp = AESKEYGENASSIST(ek[2], 2);
        ek[3] = aes128_key_expand(ek[2], _mm_shuffle_epi32(temp, 0xFF));
        temp = AESKEYGENASSIST(ek[3], 3);
        ek[4] = aes128_key_expand(ek[3], _mm_shuffle_epi32(temp, 0xFF));
        temp = AESKEYGENASSIST(ek[4], 4);
        ek[5] = aes128_key_expand(ek[4], _mm_shuffle_epi32(temp, 0xFF));
        temp = AESKEYGENASSIST(ek[5], 5);
        ek[6] = aes128_key_expand(ek[5], _mm_shuffle_epi32(temp, 0xFF));
        temp = AESKEYGENASSIST(ek[6], 6);
        ek[7] = aes128_key_expand(ek[6], _mm_shuffle_epi32(temp, 0xFF));
        temp = AESKEYGENASSIST(ek[7], 7);
        ek[8] = aes128_key_expand(ek[7], _mm_shuffle_epi32(temp, 0xFF));
        temp = AESKEYGENASSIST(ek[8], 8);
        ek[9] = aes128_key_expand(ek[8], _mm_shuffle_epi32(temp, 0xFF));
        temp = AESKEYGENASSIST(ek[9], 9);
        ek[10] = aes128_key_expand(ek[9], _mm_shuffle_epi32(temp, 0xFF));
    } else if (key_len == 24) {
        ek[0] = _mm_loadu_si128((const __m128i*)key);
        ek[1] = _mm_loadu_si128((const __m128i*)(key + 16));

        temp = AESKEYGENASSIST(ek[1], 0);
        temp = _mm_shuffle_epi32(temp, 0x55);
        ek[2] = _mm_xor_si128(ek[0], _mm_slli_si128(ek[0], 4));
        ek[2] = _mm_xor_si128(ek[2], _mm_slli_si128(ek[2], 4));
        ek[2] = _mm_xor_si128(ek[2], _mm_slli_si128(ek[2], 4));
        ek[2] = _mm_xor_si128(ek[2], temp);
        temp = AESKEYGENASSIST(ek[2], 1);
        temp = _mm_shuffle_epi32(temp, 0xFF);
        {
            __m128i base = ek[0];
            ek[3] = _mm_xor_si128(base, _mm_slli_si128(base, 4));
            ek[3] = _mm_xor_si128(ek[3], _mm_slli_si128(ek[3], 4));
            ek[3] = _mm_xor_si128(ek[3], _mm_slli_si128(ek[3], 4));
            ek[3] = _mm_xor_si128(ek[3], temp);
        }
        temp = AESKEYGENASSIST(ek[3], 0);
        temp = _mm_shuffle_epi32(temp, 0x55);
        { __m128i base = ek[1]; ek[4] = _mm_xor_si128(base, _mm_slli_si128(base, 4));
          ek[4] = _mm_xor_si128(ek[4], _mm_slli_si128(ek[4], 4));
          ek[4] = _mm_xor_si128(ek[4], _mm_slli_si128(ek[4], 4));
          ek[4] = _mm_xor_si128(ek[4], temp); }
        temp = AESKEYGENASSIST(ek[4], 2);
        temp = _mm_shuffle_epi32(temp, 0xFF);
        { __m128i base = ek[2]; ek[5] = _mm_xor_si128(base, _mm_slli_si128(base, 4));
          ek[5] = _mm_xor_si128(ek[5], _mm_slli_si128(ek[5], 4));
          ek[5] = _mm_xor_si128(ek[5], _mm_slli_si128(ek[5], 4));
          ek[5] = _mm_xor_si128(ek[5], temp); }
        temp = AESKEYGENASSIST(ek[5], 0);
        temp = _mm_shuffle_epi32(temp, 0x55);
        { __m128i base = ek[3]; ek[6] = _mm_xor_si128(base, _mm_slli_si128(base, 4));
          ek[6] = _mm_xor_si128(ek[6], _mm_slli_si128(ek[6], 4));
          ek[6] = _mm_xor_si128(ek[6], _mm_slli_si128(ek[6], 4));
          ek[6] = _mm_xor_si128(ek[6], temp); }
        temp = AESKEYGENASSIST(ek[6], 3);
        temp = _mm_shuffle_epi32(temp, 0xFF);
        { __m128i base = ek[4]; ek[7] = _mm_xor_si128(base, _mm_slli_si128(base, 4));
          ek[7] = _mm_xor_si128(ek[7], _mm_slli_si128(ek[7], 4));
          ek[7] = _mm_xor_si128(ek[7], _mm_slli_si128(ek[7], 4));
          ek[7] = _mm_xor_si128(ek[7], temp); }
        temp = AESKEYGENASSIST(ek[7], 0);
        temp = _mm_shuffle_epi32(temp, 0x55);
        { __m128i base = ek[5]; ek[8] = _mm_xor_si128(base, _mm_slli_si128(base, 4));
          ek[8] = _mm_xor_si128(ek[8], _mm_slli_si128(ek[8], 4));
          ek[8] = _mm_xor_si128(ek[8], _mm_slli_si128(ek[8], 4));
          ek[8] = _mm_xor_si128(ek[8], temp); }
        temp = AESKEYGENASSIST(ek[8], 4);
        temp = _mm_shuffle_epi32(temp, 0xFF);
        { __m128i base = ek[6]; ek[9] = _mm_xor_si128(base, _mm_slli_si128(base, 4));
          ek[9] = _mm_xor_si128(ek[9], _mm_slli_si128(ek[9], 4));
          ek[9] = _mm_xor_si128(ek[9], _mm_slli_si128(ek[9], 4));
          ek[9] = _mm_xor_si128(ek[9], temp); }
        temp = AESKEYGENASSIST(ek[9], 0);
        temp = _mm_shuffle_epi32(temp, 0x55);
        { __m128i base = ek[7]; ek[10] = _mm_xor_si128(base, _mm_slli_si128(base, 4));
          ek[10] = _mm_xor_si128(ek[10], _mm_slli_si128(ek[10], 4));
          ek[10] = _mm_xor_si128(ek[10], _mm_slli_si128(ek[10], 4));
          ek[10] = _mm_xor_si128(ek[10], temp); }
        temp = AESKEYGENASSIST(ek[10], 5);
        temp = _mm_shuffle_epi32(temp, 0xFF);
        { __m128i base = ek[8]; ek[11] = _mm_xor_si128(base, _mm_slli_si128(base, 4));
          ek[11] = _mm_xor_si128(ek[11], _mm_slli_si128(ek[11], 4));
          ek[11] = _mm_xor_si128(ek[11], _mm_slli_si128(ek[11], 4));
          ek[11] = _mm_xor_si128(ek[11], temp); }
        temp = AESKEYGENASSIST(ek[11], 0);
        temp = _mm_shuffle_epi32(temp, 0x55);
        { __m128i base = ek[9]; ek[12] = _mm_xor_si128(base, _mm_slli_si128(base, 4));
          ek[12] = _mm_xor_si128(ek[12], _mm_slli_si128(ek[12], 4));
          ek[12] = _mm_xor_si128(ek[12], _mm_slli_si128(ek[12], 4));
          ek[12] = _mm_xor_si128(ek[12], temp); }
    } else {
        ek[0] = _mm_loadu_si128((const __m128i*)key);
        ek[1] = _mm_loadu_si128((const __m128i*)(key + 16));

        temp = AESKEYGENASSIST(ek[1], 0);
        temp = _mm_shuffle_epi32(temp, 0xFF);
        { __m128i base = ek[0]; ek[2] = _mm_xor_si128(base, _mm_slli_si128(base, 4));
          ek[2] = _mm_xor_si128(ek[2], _mm_slli_si128(ek[2], 4));
          ek[2] = _mm_xor_si128(ek[2], _mm_slli_si128(ek[2], 4));
          ek[2] = _mm_xor_si128(ek[2], temp); }
        temp = AESKEYGENASSIST(ek[2], 0);
        temp = _mm_shuffle_epi32(temp, 0xAA);
        { __m128i base = ek[1]; ek[3] = _mm_xor_si128(base, _mm_slli_si128(base, 4));
          ek[3] = _mm_xor_si128(ek[3], _mm_slli_si128(ek[3], 4));
          ek[3] = _mm_xor_si128(ek[3], _mm_slli_si128(ek[3], 4));
          ek[3] = _mm_xor_si128(ek[3], temp); }
        temp = AESKEYGENASSIST(ek[3], 1);
        temp = _mm_shuffle_epi32(temp, 0xFF);
        { __m128i base = ek[2]; ek[4] = _mm_xor_si128(base, _mm_slli_si128(base, 4));
          ek[4] = _mm_xor_si128(ek[4], _mm_slli_si128(ek[4], 4));
          ek[4] = _mm_xor_si128(ek[4], _mm_slli_si128(ek[4], 4));
          ek[4] = _mm_xor_si128(ek[4], temp); }
        temp = AESKEYGENASSIST(ek[4], 0);
        temp = _mm_shuffle_epi32(temp, 0xAA);
        { __m128i base = ek[3]; ek[5] = _mm_xor_si128(base, _mm_slli_si128(base, 4));
          ek[5] = _mm_xor_si128(ek[5], _mm_slli_si128(ek[5], 4));
          ek[5] = _mm_xor_si128(ek[5], _mm_slli_si128(ek[5], 4));
          ek[5] = _mm_xor_si128(ek[5], temp); }
        temp = AESKEYGENASSIST(ek[5], 2);
        temp = _mm_shuffle_epi32(temp, 0xFF);
        { __m128i base = ek[4]; ek[6] = _mm_xor_si128(base, _mm_slli_si128(base, 4));
          ek[6] = _mm_xor_si128(ek[6], _mm_slli_si128(ek[6], 4));
          ek[6] = _mm_xor_si128(ek[6], _mm_slli_si128(ek[6], 4));
          ek[6] = _mm_xor_si128(ek[6], temp); }
        temp = AESKEYGENASSIST(ek[6], 0);
        temp = _mm_shuffle_epi32(temp, 0xAA);
        { __m128i base = ek[5]; ek[7] = _mm_xor_si128(base, _mm_slli_si128(base, 4));
          ek[7] = _mm_xor_si128(ek[7], _mm_slli_si128(ek[7], 4));
          ek[7] = _mm_xor_si128(ek[7], _mm_slli_si128(ek[7], 4));
          ek[7] = _mm_xor_si128(ek[7], temp); }
        temp = AESKEYGENASSIST(ek[7], 3);
        temp = _mm_shuffle_epi32(temp, 0xFF);
        { __m128i base = ek[6]; ek[8] = _mm_xor_si128(base, _mm_slli_si128(base, 4));
          ek[8] = _mm_xor_si128(ek[8], _mm_slli_si128(ek[8], 4));
          ek[8] = _mm_xor_si128(ek[8], _mm_slli_si128(ek[8], 4));
          ek[8] = _mm_xor_si128(ek[8], temp); }
        temp = AESKEYGENASSIST(ek[8], 0);
        temp = _mm_shuffle_epi32(temp, 0xAA);
        { __m128i base = ek[7]; ek[9] = _mm_xor_si128(base, _mm_slli_si128(base, 4));
          ek[9] = _mm_xor_si128(ek[9], _mm_slli_si128(ek[9], 4));
          ek[9] = _mm_xor_si128(ek[9], _mm_slli_si128(ek[9], 4));
          ek[9] = _mm_xor_si128(ek[9], temp); }
        temp = AESKEYGENASSIST(ek[9], 4);
        temp = _mm_shuffle_epi32(temp, 0xFF);
        { __m128i base = ek[8]; ek[10] = _mm_xor_si128(base, _mm_slli_si128(base, 4));
          ek[10] = _mm_xor_si128(ek[10], _mm_slli_si128(ek[10], 4));
          ek[10] = _mm_xor_si128(ek[10], _mm_slli_si128(ek[10], 4));
          ek[10] = _mm_xor_si128(ek[10], temp); }
        temp = AESKEYGENASSIST(ek[10], 0);
        temp = _mm_shuffle_epi32(temp, 0xAA);
        { __m128i base = ek[9]; ek[11] = _mm_xor_si128(base, _mm_slli_si128(base, 4));
          ek[11] = _mm_xor_si128(ek[11], _mm_slli_si128(ek[11], 4));
          ek[11] = _mm_xor_si128(ek[11], _mm_slli_si128(ek[11], 4));
          ek[11] = _mm_xor_si128(ek[11], temp); }
        temp = AESKEYGENASSIST(ek[11], 5);
        temp = _mm_shuffle_epi32(temp, 0xFF);
        { __m128i base = ek[10]; ek[12] = _mm_xor_si128(base, _mm_slli_si128(base, 4));
          ek[12] = _mm_xor_si128(ek[12], _mm_slli_si128(ek[12], 4));
          ek[12] = _mm_xor_si128(ek[12], _mm_slli_si128(ek[12], 4));
          ek[12] = _mm_xor_si128(ek[12], temp); }
        temp = AESKEYGENASSIST(ek[12], 0);
        temp = _mm_shuffle_epi32(temp, 0xAA);
        { __m128i base = ek[11]; ek[13] = _mm_xor_si128(base, _mm_slli_si128(base, 4));
          ek[13] = _mm_xor_si128(ek[13], _mm_slli_si128(ek[13], 4));
          ek[13] = _mm_xor_si128(ek[13], _mm_slli_si128(ek[13], 4));
          ek[13] = _mm_xor_si128(ek[13], temp); }
        temp = AESKEYGENASSIST(ek[13], 6);
        temp = _mm_shuffle_epi32(temp, 0xFF);
        { __m128i base = ek[12]; ek[14] = _mm_xor_si128(base, _mm_slli_si128(base, 4));
          ek[14] = _mm_xor_si128(ek[14], _mm_slli_si128(ek[14], 4));
          ek[14] = _mm_xor_si128(ek[14], _mm_slli_si128(ek[14], 4));
          ek[14] = _mm_xor_si128(ek[14], temp); }
    }

    if (dk) {
        dk[0] = ek[nr];
        for (size_t j = 1; j < nr; j++) {
            dk[j] = _mm_aesimc_si128(ek[nr - j]);
        }
        dk[nr] = ek[0];
    }
}

void AES_NI::set_key(const uint8_t* key, size_t key_len) {
    aesni_key_expansion(key, round_keys_enc_, round_keys_dec_, key_len, nr_);
}

void AES_NI::encrypt_block(const uint8_t* plaintext, uint8_t* ciphertext) const {
    __m128i state = _mm_loadu_si128((const __m128i*)plaintext);
    state = _mm_xor_si128(state, round_keys_enc_[0]);
    for (size_t r = 1; r < nr_; r++) {
        state = _mm_aesenc_si128(state, round_keys_enc_[r]);
    }
    state = _mm_aesenclast_si128(state, round_keys_enc_[nr_]);
    _mm_storeu_si128((__m128i*)ciphertext, state);
}

void AES_NI::decrypt_block(const uint8_t* ciphertext, uint8_t* plaintext) const {
    __m128i state = _mm_loadu_si128((const __m128i*)ciphertext);
    state = _mm_xor_si128(state, round_keys_dec_[0]);
    for (size_t r = 1; r < nr_; r++) {
        state = _mm_aesdec_si128(state, round_keys_dec_[r]);
    }
    state = _mm_aesdeclast_si128(state, round_keys_dec_[nr_]);
    _mm_storeu_si128((__m128i*)plaintext, state);
}

void AES_NI::encrypt_blocks_ni(const uint8_t* in, uint8_t* out, size_t num_blocks) const {
    size_t i = 0;
    for (; i + 3 < num_blocks; i += 4) {
        __m128i b0 = _mm_loadu_si128((const __m128i*)(in + 16*i));
        __m128i b1 = _mm_loadu_si128((const __m128i*)(in + 16*(i+1)));
        __m128i b2 = _mm_loadu_si128((const __m128i*)(in + 16*(i+2)));
        __m128i b3 = _mm_loadu_si128((const __m128i*)(in + 16*(i+3)));

        b0 = _mm_xor_si128(b0, round_keys_enc_[0]);
        b1 = _mm_xor_si128(b1, round_keys_enc_[0]);
        b2 = _mm_xor_si128(b2, round_keys_enc_[0]);
        b3 = _mm_xor_si128(b3, round_keys_enc_[0]);

        for (size_t r = 1; r < nr_; r++) {
            b0 = _mm_aesenc_si128(b0, round_keys_enc_[r]);
            b1 = _mm_aesenc_si128(b1, round_keys_enc_[r]);
            b2 = _mm_aesenc_si128(b2, round_keys_enc_[r]);
            b3 = _mm_aesenc_si128(b3, round_keys_enc_[r]);
        }

        b0 = _mm_aesenclast_si128(b0, round_keys_enc_[nr_]);
        b1 = _mm_aesenclast_si128(b1, round_keys_enc_[nr_]);
        b2 = _mm_aesenclast_si128(b2, round_keys_enc_[nr_]);
        b3 = _mm_aesenclast_si128(b3, round_keys_enc_[nr_]);

        _mm_storeu_si128((__m128i*)(out + 16*i), b0);
        _mm_storeu_si128((__m128i*)(out + 16*(i+1)), b1);
        _mm_storeu_si128((__m128i*)(out + 16*(i+2)), b2);
        _mm_storeu_si128((__m128i*)(out + 16*(i+3)), b3);
    }
    for (; i < num_blocks; i++) {
        encrypt_block(in + 16*i, out + 16*i);
    }
}

void AES_NI::decrypt_blocks_ni(const uint8_t* in, uint8_t* out, size_t num_blocks) const {
    size_t i = 0;
    for (; i + 3 < num_blocks; i += 4) {
        __m128i b0 = _mm_loadu_si128((const __m128i*)(in + 16*i));
        __m128i b1 = _mm_loadu_si128((const __m128i*)(in + 16*(i+1)));
        __m128i b2 = _mm_loadu_si128((const __m128i*)(in + 16*(i+2)));
        __m128i b3 = _mm_loadu_si128((const __m128i*)(in + 16*(i+3)));

        b0 = _mm_xor_si128(b0, round_keys_dec_[0]);
        b1 = _mm_xor_si128(b1, round_keys_dec_[0]);
        b2 = _mm_xor_si128(b2, round_keys_dec_[0]);
        b3 = _mm_xor_si128(b3, round_keys_dec_[0]);

        for (size_t r = 1; r < nr_; r++) {
            b0 = _mm_aesdec_si128(b0, round_keys_dec_[r]);
            b1 = _mm_aesdec_si128(b1, round_keys_dec_[r]);
            b2 = _mm_aesdec_si128(b2, round_keys_dec_[r]);
            b3 = _mm_aesdec_si128(b3, round_keys_dec_[r]);
        }

        b0 = _mm_aesdeclast_si128(b0, round_keys_dec_[nr_]);
        b1 = _mm_aesdeclast_si128(b1, round_keys_dec_[nr_]);
        b2 = _mm_aesdeclast_si128(b2, round_keys_dec_[nr_]);
        b3 = _mm_aesdeclast_si128(b3, round_keys_dec_[nr_]);

        _mm_storeu_si128((__m128i*)(out + 16*i), b0);
        _mm_storeu_si128((__m128i*)(out + 16*(i+1)), b1);
        _mm_storeu_si128((__m128i*)(out + 16*(i+2)), b2);
        _mm_storeu_si128((__m128i*)(out + 16*(i+3)), b3);
    }
    for (; i < num_blocks; i++) {
        decrypt_block(in + 16*i, out + 16*i);
    }
}

AES* AES::create(AESImpl impl) {
    switch (impl) {
        case AESImpl::TTABLE: return new AES_TTable();
        case AESImpl::AESNI: return new AES_NI();
        default: return nullptr;
    }
}
