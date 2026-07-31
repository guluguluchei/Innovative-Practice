#include "aes.h"
#include "sm4.h"
#include "gift.h"
#include "twine.h"
#include "gf128.h"
#include <cstring>
#include <cstdio>

void aes_ctr_encrypt(AES* cipher,
                     const uint8_t* plaintext, uint8_t* ciphertext,
                     const uint8_t* iv, size_t iv_len, size_t data_len) {
    uint8_t counter[16];
    memset(counter, 0, 16);

    if (iv_len == 12) {
        memcpy(counter, iv, 12);
        counter[15] = 1;
    } else if (iv_len == 16) {
        memcpy(counter, iv, 16);
    } else {
        size_t copy = iv_len < 16 ? iv_len : 16;
        memcpy(counter, iv, copy);
    }

    for (size_t i = 0; i < data_len; i += 16) {
        uint8_t keystream[16];
        cipher->encrypt_block(counter, keystream);

        size_t block_len = (data_len - i < 16) ? (data_len - i) : 16;
        for (size_t j = 0; j < block_len; j++) {
            ciphertext[i + j] = plaintext[i + j] ^ keystream[j];
        }
        inc_counter(counter);
    }
}

void aes_ctr_decrypt(AES* cipher,
                     const uint8_t* ciphertext, uint8_t* plaintext,
                     const uint8_t* iv, size_t iv_len, size_t data_len) {
    aes_ctr_encrypt(cipher, ciphertext, plaintext, iv, iv_len, data_len);
}

void sm4_ctr_encrypt(SM4* cipher,
                     const uint8_t* plaintext, uint8_t* ciphertext,
                     const uint8_t* iv, size_t iv_len, size_t data_len) {
    uint8_t counter[16];
    memset(counter, 0, 16);

    if (iv_len == 12) {
        memcpy(counter, iv, 12);
        counter[15] = 1;
    } else if (iv_len == 16) {
        memcpy(counter, iv, 16);
    } else {
        size_t copy = iv_len < 16 ? iv_len : 16;
        memcpy(counter, iv, copy);
    }

    for (size_t i = 0; i < data_len; i += 16) {
        uint8_t keystream[16];
        cipher->encrypt_block(counter, keystream);

        size_t block_len = (data_len - i < 16) ? (data_len - i) : 16;
        for (size_t j = 0; j < block_len; j++) {
            ciphertext[i + j] = plaintext[i + j] ^ keystream[j];
        }
        inc_counter(counter);
    }
}

void sm4_ctr_decrypt(SM4* cipher,
                     const uint8_t* ciphertext, uint8_t* plaintext,
                     const uint8_t* iv, size_t iv_len, size_t data_len) {
    sm4_ctr_encrypt(cipher, ciphertext, plaintext, iv, iv_len, data_len);
}

void gift_ctr_encrypt(GIFT* cipher,
                      const uint8_t* plaintext, uint8_t* ciphertext,
                      const uint8_t* iv, size_t iv_len, size_t data_len) {
    uint8_t counter[16];
    memset(counter, 0, 16);

    if (iv_len == 12) {
        memcpy(counter, iv, 12);
        counter[15] = 1;
    } else if (iv_len == 16) {
        memcpy(counter, iv, 16);
    } else {
        size_t copy = iv_len < 16 ? iv_len : 16;
        memcpy(counter, iv, copy);
    }

    for (size_t i = 0; i < data_len; i += 16) {
        uint8_t keystream[16];
        cipher->encrypt_block(counter, keystream);

        size_t block_len = (data_len - i < 16) ? (data_len - i) : 16;
        for (size_t j = 0; j < block_len; j++) {
            ciphertext[i + j] = plaintext[i + j] ^ keystream[j];
        }
        inc_counter(counter);
    }
}

void gift_ctr_decrypt(GIFT* cipher,
                      const uint8_t* ciphertext, uint8_t* plaintext,
                      const uint8_t* iv, size_t iv_len, size_t data_len) {
    gift_ctr_encrypt(cipher, ciphertext, plaintext, iv, iv_len, data_len);
}

void twine_ctr_encrypt(TWINE* cipher,
                       const uint8_t* plaintext, uint8_t* ciphertext,
                       const uint8_t* iv, size_t iv_len, size_t data_len) {
    uint8_t counter[8];
    memset(counter, 0, 8);

    if (iv_len == 8) {
        memcpy(counter, iv, 8);
    } else {
        size_t copy = iv_len < 8 ? iv_len : 8;
        memcpy(counter, iv, copy);
    }

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
}

void twine_ctr_decrypt(TWINE* cipher,
                       const uint8_t* ciphertext, uint8_t* plaintext,
                       const uint8_t* iv, size_t iv_len, size_t data_len) {
    twine_ctr_encrypt(cipher, ciphertext, plaintext, iv, iv_len, data_len);
}
