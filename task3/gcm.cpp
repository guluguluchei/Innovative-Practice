#include "aes.h"
#include "sm4.h"
#include "gift.h"
#include "twine.h"
#include "gf128.h"
#include <cstring>
#include <cstdio>
#include <cstdlib>

void aes_gcm_encrypt(AES* cipher,
                     const uint8_t* plaintext, uint8_t* ciphertext,
                     size_t data_len,
                     const uint8_t* iv, size_t iv_len,
                     const uint8_t* aad, size_t aad_len,
                     uint8_t* tag, size_t tag_len) {
    uint8_t H[16], zero[16];
    memset(zero, 0, 16);
    cipher->encrypt_block(zero, H);

    uint8_t J0[16];
    memset(J0, 0, 16);
    if (iv_len == 12) {
        memcpy(J0, iv, 12);
        J0[15] = 1;
    } else {
        ghash_compute(J0, H, iv, iv_len, nullptr, 0);
    }

    uint8_t counter[16];
    memcpy(counter, J0, 16);
    inc_counter(counter);

    for (size_t i = 0; i < data_len; i += 16) {
        uint8_t keystream[16];
        cipher->encrypt_block(counter, keystream);

        size_t block_len = (data_len - i < 16) ? (data_len - i) : 16;
        for (size_t j = 0; j < block_len; j++) {
            ciphertext[i + j] = plaintext[i + j] ^ keystream[j];
        }
        inc_counter(counter);
    }

    uint8_t S[16];
    ghash_compute(S, H, aad, aad_len, ciphertext, data_len);

    uint8_t enc_J0[16];
    cipher->encrypt_block(J0, enc_J0);
    for (int i = 0; i < 16; i++) S[i] ^= enc_J0[i];
    memcpy(tag, S, tag_len);
}

int aes_gcm_decrypt(AES* cipher,
                    const uint8_t* ciphertext, uint8_t* plaintext,
                    size_t data_len,
                    const uint8_t* iv, size_t iv_len,
                    const uint8_t* aad, size_t aad_len,
                    const uint8_t* tag, size_t tag_len) {
    uint8_t H[16], zero[16];
    memset(zero, 0, 16);
    cipher->encrypt_block(zero, H);

    uint8_t J0[16];
    memset(J0, 0, 16);
    if (iv_len == 12) {
        memcpy(J0, iv, 12);
        J0[15] = 1;
    } else {
        ghash_compute(J0, H, iv, iv_len, nullptr, 0);
    }

    uint8_t computed_tag[16];
    ghash_compute(computed_tag, H, aad, aad_len, ciphertext, data_len);

    uint8_t enc_J0[16];
    cipher->encrypt_block(J0, enc_J0);
    for (int i = 0; i < 16; i++) computed_tag[i] ^= enc_J0[i];

    uint8_t diff = 0;
    for (size_t i = 0; i < tag_len; i++) diff |= computed_tag[i] ^ tag[i];

    if (diff != 0) {
        memset(plaintext, 0, data_len);
        return 0;
    }

    uint8_t counter[16];
    memcpy(counter, J0, 16);
    inc_counter(counter);

    for (size_t i = 0; i < data_len; i += 16) {
        uint8_t keystream[16];
        cipher->encrypt_block(counter, keystream);

        size_t block_len = (data_len - i < 16) ? (data_len - i) : 16;
        for (size_t j = 0; j < block_len; j++) {
            plaintext[i + j] = ciphertext[i + j] ^ keystream[j];
        }
        inc_counter(counter);
    }
    return 1;
}

void sm4_gcm_encrypt(SM4* cipher,
                     const uint8_t* plaintext, uint8_t* ciphertext,
                     size_t data_len,
                     const uint8_t* iv, size_t iv_len,
                     const uint8_t* aad, size_t aad_len,
                     uint8_t* tag, size_t tag_len) {
    uint8_t H[16], zero[16];
    memset(zero, 0, 16);
    cipher->encrypt_block(zero, H);

    uint8_t J0[16];
    memset(J0, 0, 16);
    if (iv_len == 12) {
        memcpy(J0, iv, 12);
        J0[15] = 1;
    } else {
        ghash_compute(J0, H, iv, iv_len, nullptr, 0);
    }

    uint8_t counter[16];
    memcpy(counter, J0, 16);
    inc_counter(counter);

    for (size_t i = 0; i < data_len; i += 16) {
        uint8_t keystream[16];
        cipher->encrypt_block(counter, keystream);

        size_t block_len = (data_len - i < 16) ? (data_len - i) : 16;
        for (size_t j = 0; j < block_len; j++) {
            ciphertext[i + j] = plaintext[i + j] ^ keystream[j];
        }
        inc_counter(counter);
    }

    uint8_t S[16];
    ghash_compute(S, H, aad, aad_len, ciphertext, data_len);

    uint8_t enc_J0[16];
    cipher->encrypt_block(J0, enc_J0);
    for (int i = 0; i < 16; i++) S[i] ^= enc_J0[i];
    memcpy(tag, S, tag_len);
}

int sm4_gcm_decrypt(SM4* cipher,
                    const uint8_t* ciphertext, uint8_t* plaintext,
                    size_t data_len,
                    const uint8_t* iv, size_t iv_len,
                    const uint8_t* aad, size_t aad_len,
                    const uint8_t* tag, size_t tag_len) {
    uint8_t H[16], zero[16];
    memset(zero, 0, 16);
    cipher->encrypt_block(zero, H);

    uint8_t J0[16];
    memset(J0, 0, 16);
    if (iv_len == 12) {
        memcpy(J0, iv, 12);
        J0[15] = 1;
    } else {
        ghash_compute(J0, H, iv, iv_len, nullptr, 0);
    }

    uint8_t computed_tag[16];
    ghash_compute(computed_tag, H, aad, aad_len, ciphertext, data_len);

    uint8_t enc_J0[16];
    cipher->encrypt_block(J0, enc_J0);
    for (int i = 0; i < 16; i++) computed_tag[i] ^= enc_J0[i];

    uint8_t diff = 0;
    for (size_t i = 0; i < tag_len; i++) diff |= computed_tag[i] ^ tag[i];

    if (diff != 0) {
        memset(plaintext, 0, data_len);
        return 0;
    }

    uint8_t counter[16];
    memcpy(counter, J0, 16);
    inc_counter(counter);

    for (size_t i = 0; i < data_len; i += 16) {
        uint8_t keystream[16];
        cipher->encrypt_block(counter, keystream);

        size_t block_len = (data_len - i < 16) ? (data_len - i) : 16;
        for (size_t j = 0; j < block_len; j++) {
            plaintext[i + j] = ciphertext[i + j] ^ keystream[j];
        }
        inc_counter(counter);
    }
    return 1;
}

void gift_gcm_encrypt(GIFT* cipher,
                      const uint8_t* plaintext, uint8_t* ciphertext,
                      size_t data_len,
                      const uint8_t* iv, size_t iv_len,
                      const uint8_t* aad, size_t aad_len,
                      uint8_t* tag, size_t tag_len) {
    uint8_t H[16], zero[16];
    memset(zero, 0, 16);
    cipher->encrypt_block(zero, H);

    uint8_t J0[16];
    memset(J0, 0, 16);
    if (iv_len == 12) {
        memcpy(J0, iv, 12);
        J0[15] = 1;
    } else {
        ghash_compute(J0, H, iv, iv_len, nullptr, 0);
    }

    uint8_t counter[16];
    memcpy(counter, J0, 16);
    inc_counter(counter);

    for (size_t i = 0; i < data_len; i += 16) {
        uint8_t keystream[16];
        cipher->encrypt_block(counter, keystream);

        size_t block_len = (data_len - i < 16) ? (data_len - i) : 16;
        for (size_t j = 0; j < block_len; j++) {
            ciphertext[i + j] = plaintext[i + j] ^ keystream[j];
        }
        inc_counter(counter);
    }

    uint8_t S[16];
    ghash_compute(S, H, aad, aad_len, ciphertext, data_len);

    uint8_t enc_J0[16];
    cipher->encrypt_block(J0, enc_J0);
    for (int i = 0; i < 16; i++) S[i] ^= enc_J0[i];
    memcpy(tag, S, tag_len);
}

int gift_gcm_decrypt(GIFT* cipher,
                     const uint8_t* ciphertext, uint8_t* plaintext,
                     size_t data_len,
                     const uint8_t* iv, size_t iv_len,
                     const uint8_t* aad, size_t aad_len,
                     const uint8_t* tag, size_t tag_len) {
    uint8_t H[16], zero[16];
    memset(zero, 0, 16);
    cipher->encrypt_block(zero, H);

    uint8_t J0[16];
    memset(J0, 0, 16);
    if (iv_len == 12) {
        memcpy(J0, iv, 12);
        J0[15] = 1;
    } else {
        ghash_compute(J0, H, iv, iv_len, nullptr, 0);
    }

    uint8_t computed_tag[16];
    ghash_compute(computed_tag, H, aad, aad_len, ciphertext, data_len);

    uint8_t enc_J0[16];
    cipher->encrypt_block(J0, enc_J0);
    for (int i = 0; i < 16; i++) computed_tag[i] ^= enc_J0[i];

    uint8_t diff = 0;
    for (size_t i = 0; i < tag_len; i++) diff |= computed_tag[i] ^ tag[i];

    if (diff != 0) {
        memset(plaintext, 0, data_len);
        return 0;
    }

    uint8_t counter[16];
    memcpy(counter, J0, 16);
    inc_counter(counter);

    for (size_t i = 0; i < data_len; i += 16) {
        uint8_t keystream[16];
        cipher->encrypt_block(counter, keystream);

        size_t block_len = (data_len - i < 16) ? (data_len - i) : 16;
        for (size_t j = 0; j < block_len; j++) {
            plaintext[i + j] = ciphertext[i + j] ^ keystream[j];
        }
        inc_counter(counter);
    }
    return 1;
}

void twine_gcm_encrypt(TWINE* cipher,
                       const uint8_t* plaintext, uint8_t* ciphertext,
                       size_t data_len,
                       const uint8_t* iv, size_t iv_len,
                       const uint8_t* aad, size_t aad_len,
                       uint8_t* tag, size_t tag_len) {
    uint8_t zero8[8];
    memset(zero8, 0, 8);
    uint8_t H[16];
    cipher->encrypt_block(zero8, H);
    cipher->encrypt_block(zero8, H + 8);

    uint8_t J0[16];
    memset(J0, 0, 16);
    if (iv_len == 12) {
        memcpy(J0, iv, 12);
        J0[15] = 1;
    } else {
        ghash_compute(J0, H, iv, iv_len, nullptr, 0);
    }

    uint8_t counter[8];
    memcpy(counter, J0, 8);

    for (size_t i = 0; i < data_len; i += 8) {
        uint8_t keystream[8];
        cipher->encrypt_block(counter, keystream);

        size_t block_len = (data_len - i < 8) ? (data_len - i) : 8;
        for (size_t j = 0; j < block_len; j++) {
            ciphertext[i + j] = plaintext[i + j] ^ keystream[j];
        }
        for (int k = 7; k >= 0; k--) {
            if (++counter[k] != 0) break;
        }
    }

    uint8_t S[16];
    ghash_compute(S, H, aad, aad_len, ciphertext, data_len);

    uint8_t enc_J0[16];
    cipher->encrypt_block(J0, enc_J0);
    cipher->encrypt_block(J0 + 8, enc_J0 + 8);
    for (int i = 0; i < 16; i++) S[i] ^= enc_J0[i];
    memcpy(tag, S, tag_len);
}

int twine_gcm_decrypt(TWINE* cipher,
                      const uint8_t* ciphertext, uint8_t* plaintext,
                      size_t data_len,
                      const uint8_t* iv, size_t iv_len,
                      const uint8_t* aad, size_t aad_len,
                      const uint8_t* tag, size_t tag_len) {
    uint8_t zero8[8];
    memset(zero8, 0, 8);
    uint8_t H[16];
    cipher->encrypt_block(zero8, H);
    cipher->encrypt_block(zero8, H + 8);

    uint8_t J0[16];
    memset(J0, 0, 16);
    if (iv_len == 12) {
        memcpy(J0, iv, 12);
        J0[15] = 1;
    } else {
        ghash_compute(J0, H, iv, iv_len, nullptr, 0);
    }

    uint8_t computed_tag[16];
    ghash_compute(computed_tag, H, aad, aad_len, ciphertext, data_len);

    uint8_t enc_J0[16];
    cipher->encrypt_block(J0, enc_J0);
    cipher->encrypt_block(J0 + 8, enc_J0 + 8);
    for (int i = 0; i < 16; i++) computed_tag[i] ^= enc_J0[i];

    uint8_t diff = 0;
    for (size_t i = 0; i < tag_len; i++) diff |= computed_tag[i] ^ tag[i];

    if (diff != 0) {
        memset(plaintext, 0, data_len);
        return 0;
    }

    uint8_t counter[8];
    memcpy(counter, J0, 8);

    for (size_t i = 0; i < data_len; i += 8) {
        uint8_t keystream[8];
        cipher->encrypt_block(counter, keystream);

        size_t block_len = (data_len - i < 8) ? (data_len - i) : 8;
        for (size_t j = 0; j < block_len; j++) {
            plaintext[i + j] = ciphertext[i + j] ^ keystream[j];
        }
        for (int k = 7; k >= 0; k--) {
            if (++counter[k] != 0) break;
        }
    }
    return 1;
}
