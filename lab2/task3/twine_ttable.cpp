#include "twine.h"
#include <cstring>

static const uint8_t TWINE_SBOX[16] = {
    0xC, 0x0, 0xF, 0xA, 0x2, 0xB, 0x9, 0x5,
    0x8, 0x3, 0xD, 0x7, 0x1, 0xE, 0x6, 0x4
};

static const uint8_t TWINE_SBOX_INV[16] = {
    0x1, 0xC, 0x4, 0x9, 0xF, 0x7, 0xE, 0xB,
    0x8, 0x6, 0x3, 0x5, 0x0, 0xA, 0xD, 0x2
};

static const uint8_t SHUFFLE[16] = {
    5, 0, 1, 4, 7, 12, 3, 8, 13, 6, 9, 2, 15, 10, 11, 14
};

static const uint8_t SHUFFLE_INV[16] = {
    1, 2, 11, 6, 3, 0, 9, 4, 7, 10, 13, 14, 5, 8, 15, 12
};

static uint8_t T_TABLE[256], T_TABLE_INV[256];
static bool tables_init = false;

static void init_tables() {
    if (tables_init) return;
    for (int i = 0; i < 256; i++) {
        uint8_t hi = TWINE_SBOX[(i >> 4) & 0xF];
        uint8_t lo = TWINE_SBOX[i & 0xF];
        T_TABLE[i] = (hi << 4) | lo;

        uint8_t hi_inv = TWINE_SBOX_INV[(i >> 4) & 0xF];
        uint8_t lo_inv = TWINE_SBOX_INV[i & 0xF];
        T_TABLE_INV[i] = (hi_inv << 4) | lo_inv;
    }
    tables_init = true;
}

TWINE_TTable::TWINE_TTable() {
    init_tables();
    memset(rk_, 0, sizeof(rk_));
}
TWINE_TTable::~TWINE_TTable() {}

void TWINE_TTable::set_key(const uint8_t* key, size_t key_len) {
    size_t nk = (key_len == 10) ? 10 : 16;
    uint8_t W[32];
    memset(W, 0, sizeof(W));
    for (size_t i = 0; i < nk; i++) W[i] = key[i];

    if (nk == 10) {
        uint8_t con = 0x01;
        for (size_t i = 0; i < 36; i++) {
            for (int j = 0; j < 4; j++) {
                uint8_t val = W[1] ^ W[3] ^ W[4] ^ W[6] ^ W[13] ^ W[14] ^ con;
                W[0] ^= T_TABLE[val];
                for (int k = 0; k < 15; k++) W[k] = W[k+1];
                W[15] = W[0];
            }
            rk_[i] = ((uint32_t)W[1] << 24) | ((uint32_t)W[3] << 16) |
                     ((uint32_t)W[4] << 8) | (uint32_t)W[5];
            con = (con << 1) ^ ((con & 0x80) ? 0x1B : 0);
        }
    } else {
        for (size_t i = 0; i < 36; i++) {
            rk_[i] = ((uint32_t)W[2] << 24) | ((uint32_t)W[3] << 16) |
                     ((uint32_t)W[12] << 8) | (uint32_t)W[15];
        }
    }
}

void TWINE_TTable::encrypt_block(const uint8_t* plaintext, uint8_t* ciphertext) const {
    uint8_t bytes[8];
    memcpy(bytes, plaintext, 8);

    for (int r = 0; r < 35; r++) {
        uint32_t rk = rk_[r];
        uint8_t rk_nibbles[8];
        for (int j = 0; j < 8; j++) rk_nibbles[j] = (rk >> (28 - 4*j)) & 0xF;

        uint8_t nibbles[16];
        for (int i = 0; i < 8; i++) {
            nibbles[2*i]   = (bytes[i] >> 4) & 0xF;
            nibbles[2*i+1] = bytes[i] & 0xF;
        }

        for (int j = 0; j < 8; j++) {
            uint8_t idx = (nibbles[2*j] ^ rk_nibbles[j]);
            uint8_t sb = TWINE_SBOX[idx];
            nibbles[2*j+1] ^= sb;
        }

        uint8_t Y[16];
        for (int h = 0; h < 16; h++) Y[SHUFFLE[h]] = nibbles[h];

        for (int i = 0; i < 8; i++) {
            bytes[i] = (Y[2*i] << 4) | Y[2*i+1];
        }
    }

    uint32_t rk = rk_[35];
    uint8_t nibbles[16];
    for (int i = 0; i < 8; i++) {
        nibbles[2*i]   = (bytes[i] >> 4) & 0xF;
        nibbles[2*i+1] = bytes[i] & 0xF;
    }
    for (int j = 0; j < 8; j++) {
        uint8_t rkn = (rk >> (28 - 4*j)) & 0xF;
        nibbles[2*j+1] ^= TWINE_SBOX[nibbles[2*j] ^ rkn];
    }
    for (int i = 0; i < 8; i++) {
        ciphertext[i] = (nibbles[2*i] << 4) | nibbles[2*i+1];
    }
}

void TWINE_TTable::decrypt_block(const uint8_t* ciphertext, uint8_t* plaintext) const {
    uint8_t bytes[8];
    memcpy(bytes, ciphertext, 8);

    uint8_t nibbles[16];
    for (int i = 0; i < 8; i++) {
        nibbles[2*i]   = (bytes[i] >> 4) & 0xF;
        nibbles[2*i+1] = bytes[i] & 0xF;
    }

    uint32_t rk = rk_[35];
    for (int j = 0; j < 8; j++) {
        uint8_t rkn = (rk >> (28 - 4*j)) & 0xF;
        nibbles[2*j+1] ^= TWINE_SBOX[nibbles[2*j] ^ rkn];
    }

    for (int r = 34; r >= 0; r--) {
        uint8_t Y[16];
        for (int h = 0; h < 16; h++) Y[SHUFFLE_INV[h]] = nibbles[h];

        rk = rk_[r];
        for (int j = 0; j < 8; j++) {
            uint8_t rkn = (rk >> (28 - 4*j)) & 0xF;
            Y[2*j+1] ^= TWINE_SBOX[Y[2*j] ^ rkn];
        }

        for (int h = 0; h < 16; h++) nibbles[h] = Y[h];
    }

    for (int i = 0; i < 8; i++) {
        plaintext[i] = (nibbles[2*i] << 4) | nibbles[2*i+1];
    }
}
