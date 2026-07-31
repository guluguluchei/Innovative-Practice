#include "aes.h"
#include "sm4.h"
#include "gift.h"
#include "twine.h"
#include "gf128.h"
#include <cstring>

void aes_xts_encrypt(AES* cipher1, AES* cipher2,
                     const uint8_t* plaintext, uint8_t* ciphertext,
                     size_t data_len, uint64_t sector) {
    size_t num_blocks = (data_len + 15) / 16;
    bool has_stealing = (data_len % 16) != 0;

    uint8_t tweak_in[16], T[16];
    memset(tweak_in, 0, 16);
    tweak_in[8]  = (sector >> 56) & 0xFF;
    tweak_in[9]  = (sector >> 48) & 0xFF;
    tweak_in[10] = (sector >> 40) & 0xFF;
    tweak_in[11] = (sector >> 32) & 0xFF;
    tweak_in[12] = (sector >> 24) & 0xFF;
    tweak_in[13] = (sector >> 16) & 0xFF;
    tweak_in[14] = (sector >> 8) & 0xFF;
    tweak_in[15] = sector & 0xFF;
    cipher2->encrypt_block(tweak_in, T);

    for (size_t j = 0; j < num_blocks; j++) {
        uint8_t block[16], encrypted[16];

        if (j == num_blocks - 1 && has_stealing) {
            size_t remaining = data_len - j * 16;
            for (size_t k = 0; k < remaining; k++) {
                ciphertext[j*16 + k] = ciphertext[(j-1)*16 + k];
                block[k] = ciphertext[(j-1)*16 + k];
            }
            for (size_t k = remaining; k < 16; k++) block[k] = 0;

            for (int b = 0; b < 16; b++) block[b] ^= T[b];
            cipher1->encrypt_block(block, encrypted);
            for (int b = 0; b < 16; b++) encrypted[b] ^= T[b];
            memcpy(ciphertext + (j-1)*16, encrypted, 16);
            break;
        }

        for (int b = 0; b < 16; b++) block[b] = plaintext[j*16+b] ^ T[b];
        cipher1->encrypt_block(block, encrypted);
        for (int b = 0; b < 16; b++) ciphertext[j*16+b] = encrypted[b] ^ T[b];
        gf128_mul_xts(T, T);
    }
}

void aes_xts_decrypt(AES* cipher1, AES* cipher2,
                     const uint8_t* ciphertext, uint8_t* plaintext,
                     size_t data_len, uint64_t sector) {
    size_t num_blocks = (data_len + 15) / 16;
    bool has_stealing = (data_len % 16) != 0;

    uint8_t tweak_in[16], T[16];
    memset(tweak_in, 0, 16);
    tweak_in[8]  = (sector >> 56) & 0xFF;
    tweak_in[9]  = (sector >> 48) & 0xFF;
    tweak_in[10] = (sector >> 40) & 0xFF;
    tweak_in[11] = (sector >> 32) & 0xFF;
    tweak_in[12] = (sector >> 24) & 0xFF;
    tweak_in[13] = (sector >> 16) & 0xFF;
    tweak_in[14] = (sector >> 8) & 0xFF;
    tweak_in[15] = sector & 0xFF;
    cipher2->encrypt_block(tweak_in, T);

    for (size_t j = 0; j < num_blocks; j++) {
        uint8_t block[16], decrypted[16];

        if (j == num_blocks - 1 && has_stealing) {
            size_t remaining = data_len - j * 16;
            for (int b = 0; b < 16; b++) block[b] = ciphertext[(j-1)*16+b] ^ T[b];
            cipher1->decrypt_block(block, decrypted);
            for (int b = 0; b < 16; b++) decrypted[b] ^= T[b];
            for (size_t k = 0; k < remaining; k++)
                plaintext[(j-1)*16+k] = ciphertext[j*16+k];
            for (size_t k = remaining; k < 16; k++)
                plaintext[(j-1)*16+k] = decrypted[k];
            for (size_t k = 0; k < remaining; k++)
                plaintext[j*16+k] = decrypted[k];
            break;
        }

        for (int b = 0; b < 16; b++) block[b] = ciphertext[j*16+b] ^ T[b];
        cipher1->decrypt_block(block, decrypted);
        for (int b = 0; b < 16; b++) plaintext[j*16+b] = decrypted[b] ^ T[b];
        gf128_mul_xts(T, T);
    }
}

void sm4_xts_encrypt(SM4* cipher1, SM4* cipher2,
                     const uint8_t* plaintext, uint8_t* ciphertext,
                     size_t data_len, uint64_t sector) {
    size_t num_blocks = (data_len + 15) / 16;
    bool has_stealing = (data_len % 16) != 0;

    uint8_t tweak_in[16], T[16];
    memset(tweak_in, 0, 16);
    tweak_in[8]  = (sector >> 56) & 0xFF;
    tweak_in[9]  = (sector >> 48) & 0xFF;
    tweak_in[10] = (sector >> 40) & 0xFF;
    tweak_in[11] = (sector >> 32) & 0xFF;
    tweak_in[12] = (sector >> 24) & 0xFF;
    tweak_in[13] = (sector >> 16) & 0xFF;
    tweak_in[14] = (sector >> 8) & 0xFF;
    tweak_in[15] = sector & 0xFF;
    cipher2->encrypt_block(tweak_in, T);

    for (size_t j = 0; j < num_blocks; j++) {
        uint8_t block[16], encrypted[16];

        if (j == num_blocks - 1 && has_stealing) {
            size_t remaining = data_len - j * 16;
            for (size_t k = 0; k < remaining; k++) {
                ciphertext[j*16 + k] = ciphertext[(j-1)*16 + k];
                block[k] = ciphertext[(j-1)*16 + k];
            }
            for (size_t k = remaining; k < 16; k++) block[k] = 0;

            for (int b = 0; b < 16; b++) block[b] ^= T[b];
            cipher1->encrypt_block(block, encrypted);
            for (int b = 0; b < 16; b++) encrypted[b] ^= T[b];
            memcpy(ciphertext + (j-1)*16, encrypted, 16);
            break;
        }

        for (int b = 0; b < 16; b++) block[b] = plaintext[j*16+b] ^ T[b];
        cipher1->encrypt_block(block, encrypted);
        for (int b = 0; b < 16; b++) ciphertext[j*16+b] = encrypted[b] ^ T[b];
        gf128_mul_xts(T, T);
    }
}

void sm4_xts_decrypt(SM4* cipher1, SM4* cipher2,
                     const uint8_t* ciphertext, uint8_t* plaintext,
                     size_t data_len, uint64_t sector) {
    size_t num_blocks = (data_len + 15) / 16;
    bool has_stealing = (data_len % 16) != 0;

    uint8_t tweak_in[16], T[16];
    memset(tweak_in, 0, 16);
    tweak_in[8]  = (sector >> 56) & 0xFF;
    tweak_in[9]  = (sector >> 48) & 0xFF;
    tweak_in[10] = (sector >> 40) & 0xFF;
    tweak_in[11] = (sector >> 32) & 0xFF;
    tweak_in[12] = (sector >> 24) & 0xFF;
    tweak_in[13] = (sector >> 16) & 0xFF;
    tweak_in[14] = (sector >> 8) & 0xFF;
    tweak_in[15] = sector & 0xFF;
    cipher2->encrypt_block(tweak_in, T);

    for (size_t j = 0; j < num_blocks; j++) {
        uint8_t block[16], decrypted[16];

        if (j == num_blocks - 1 && has_stealing) {
            size_t remaining = data_len - j * 16;
            for (int b = 0; b < 16; b++) block[b] = ciphertext[(j-1)*16+b] ^ T[b];
            cipher1->decrypt_block(block, decrypted);
            for (int b = 0; b < 16; b++) decrypted[b] ^= T[b];
            for (size_t k = 0; k < remaining; k++)
                plaintext[(j-1)*16+k] = ciphertext[j*16+k];
            for (size_t k = remaining; k < 16; k++)
                plaintext[(j-1)*16+k] = decrypted[k];
            for (size_t k = 0; k < remaining; k++)
                plaintext[j*16+k] = decrypted[k];
            break;
        }

        for (int b = 0; b < 16; b++) block[b] = ciphertext[j*16+b] ^ T[b];
        cipher1->decrypt_block(block, decrypted);
        for (int b = 0; b < 16; b++) plaintext[j*16+b] = decrypted[b] ^ T[b];
        gf128_mul_xts(T, T);
    }
}

void gift_xts_encrypt(GIFT* cipher1, GIFT* cipher2,
                      const uint8_t* plaintext, uint8_t* ciphertext,
                      size_t data_len, uint64_t sector) {
    size_t num_blocks = (data_len + 15) / 16;
    bool has_stealing = (data_len % 16) != 0;

    uint8_t tweak_in[16], T[16];
    memset(tweak_in, 0, 16);
    tweak_in[8]  = (sector >> 56) & 0xFF;
    tweak_in[9]  = (sector >> 48) & 0xFF;
    tweak_in[10] = (sector >> 40) & 0xFF;
    tweak_in[11] = (sector >> 32) & 0xFF;
    tweak_in[12] = (sector >> 24) & 0xFF;
    tweak_in[13] = (sector >> 16) & 0xFF;
    tweak_in[14] = (sector >> 8) & 0xFF;
    tweak_in[15] = sector & 0xFF;
    cipher2->encrypt_block(tweak_in, T);

    for (size_t j = 0; j < num_blocks; j++) {
        uint8_t block[16], encrypted[16];

        if (j == num_blocks - 1 && has_stealing) {
            size_t remaining = data_len - j * 16;
            for (size_t k = 0; k < remaining; k++) {
                ciphertext[j*16 + k] = ciphertext[(j-1)*16 + k];
                block[k] = ciphertext[(j-1)*16 + k];
            }
            for (size_t k = remaining; k < 16; k++) block[k] = 0;

            for (int b = 0; b < 16; b++) block[b] ^= T[b];
            cipher1->encrypt_block(block, encrypted);
            for (int b = 0; b < 16; b++) encrypted[b] ^= T[b];
            memcpy(ciphertext + (j-1)*16, encrypted, 16);
            break;
        }

        for (int b = 0; b < 16; b++) block[b] = plaintext[j*16+b] ^ T[b];
        cipher1->encrypt_block(block, encrypted);
        for (int b = 0; b < 16; b++) ciphertext[j*16+b] = encrypted[b] ^ T[b];
        gf128_mul_xts(T, T);
    }
}

void gift_xts_decrypt(GIFT* cipher1, GIFT* cipher2,
                      const uint8_t* ciphertext, uint8_t* plaintext,
                      size_t data_len, uint64_t sector) {
    size_t num_blocks = (data_len + 15) / 16;
    bool has_stealing = (data_len % 16) != 0;

    uint8_t tweak_in[16], T[16];
    memset(tweak_in, 0, 16);
    tweak_in[8]  = (sector >> 56) & 0xFF;
    tweak_in[9]  = (sector >> 48) & 0xFF;
    tweak_in[10] = (sector >> 40) & 0xFF;
    tweak_in[11] = (sector >> 32) & 0xFF;
    tweak_in[12] = (sector >> 24) & 0xFF;
    tweak_in[13] = (sector >> 16) & 0xFF;
    tweak_in[14] = (sector >> 8) & 0xFF;
    tweak_in[15] = sector & 0xFF;
    cipher2->encrypt_block(tweak_in, T);

    for (size_t j = 0; j < num_blocks; j++) {
        uint8_t block[16], decrypted[16];

        if (j == num_blocks - 1 && has_stealing) {
            size_t remaining = data_len - j * 16;
            for (int b = 0; b < 16; b++) block[b] = ciphertext[(j-1)*16+b] ^ T[b];
            cipher1->decrypt_block(block, decrypted);
            for (int b = 0; b < 16; b++) decrypted[b] ^= T[b];
            for (size_t k = 0; k < remaining; k++)
                plaintext[(j-1)*16+k] = ciphertext[j*16+k];
            for (size_t k = remaining; k < 16; k++)
                plaintext[(j-1)*16+k] = decrypted[k];
            for (size_t k = 0; k < remaining; k++)
                plaintext[j*16+k] = decrypted[k];
            break;
        }

        for (int b = 0; b < 16; b++) block[b] = ciphertext[j*16+b] ^ T[b];
        cipher1->decrypt_block(block, decrypted);
        for (int b = 0; b < 16; b++) plaintext[j*16+b] = decrypted[b] ^ T[b];
        gf128_mul_xts(T, T);
    }
}

void twine_xts_encrypt(TWINE* cipher1, TWINE* cipher2,
                       const uint8_t* plaintext, uint8_t* ciphertext,
                       size_t data_len, uint64_t sector) {
    size_t num_blocks = (data_len + 7) / 8;
    bool has_stealing = (data_len % 8) != 0;

    uint8_t T[8];
    T[0] = (sector >> 56) & 0xFF;
    T[1] = (sector >> 48) & 0xFF;
    T[2] = (sector >> 40) & 0xFF;
    T[3] = (sector >> 32) & 0xFF;
    T[4] = (sector >> 24) & 0xFF;
    T[5] = (sector >> 16) & 0xFF;
    T[6] = (sector >> 8) & 0xFF;
    T[7] = sector & 0xFF;

    for (size_t j = 0; j < num_blocks; j++) {
        uint8_t block[8], encrypted[8];

        if (j == num_blocks - 1 && has_stealing) {
            size_t remaining = data_len - j * 8;
            for (size_t k = 0; k < remaining; k++) {
                ciphertext[j*8 + k] = ciphertext[(j-1)*8 + k];
                block[k] = ciphertext[(j-1)*8 + k];
            }
            for (size_t k = remaining; k < 8; k++) block[k] = 0;

            for (int b = 0; b < 8; b++) block[b] ^= T[b];
            cipher1->encrypt_block(block, encrypted);
            for (int b = 0; b < 8; b++) encrypted[b] ^= T[b];
            memcpy(ciphertext + (j-1)*8, encrypted, 8);
            break;
        }

        for (int b = 0; b < 8; b++) block[b] = plaintext[j*8+b] ^ T[b];
        cipher1->encrypt_block(block, encrypted);
        for (int b = 0; b < 8; b++) ciphertext[j*8+b] = encrypted[b] ^ T[b];
    }
}

void twine_xts_decrypt(TWINE* cipher1, TWINE* cipher2,
                       const uint8_t* ciphertext, uint8_t* plaintext,
                       size_t data_len, uint64_t sector) {
    size_t num_blocks = (data_len + 7) / 8;
    bool has_stealing = (data_len % 8) != 0;

    uint8_t T[8];
    T[0] = (sector >> 56) & 0xFF;
    T[1] = (sector >> 48) & 0xFF;
    T[2] = (sector >> 40) & 0xFF;
    T[3] = (sector >> 32) & 0xFF;
    T[4] = (sector >> 24) & 0xFF;
    T[5] = (sector >> 16) & 0xFF;
    T[6] = (sector >> 8) & 0xFF;
    T[7] = sector & 0xFF;

    for (size_t j = 0; j < num_blocks; j++) {
        uint8_t block[8], decrypted[8];

        if (j == num_blocks - 1 && has_stealing) {
            size_t remaining = data_len - j * 8;
            for (int b = 0; b < 8; b++) block[b] = ciphertext[(j-1)*8+b] ^ T[b];
            cipher1->decrypt_block(block, decrypted);
            for (int b = 0; b < 8; b++) decrypted[b] ^= T[b];
            for (size_t k = 0; k < remaining; k++)
                plaintext[(j-1)*8+k] = ciphertext[j*8+k];
            for (size_t k = remaining; k < 8; k++)
                plaintext[(j-1)*8+k] = decrypted[k];
            for (size_t k = 0; k < remaining; k++)
                plaintext[j*8+k] = decrypted[k];
            break;
        }

        for (int b = 0; b < 8; b++) block[b] = ciphertext[j*8+b] ^ T[b];
        cipher1->decrypt_block(block, decrypted);
        for (int b = 0; b < 8; b++) plaintext[j*8+b] = decrypted[b] ^ T[b];
    }
}
