#include "gift.h"
#include <cstring>

static const uint8_t GIFT_SBOX[16] = {
    0x1, 0xA, 0x4, 0xC, 0x6, 0xF, 0x3, 0x9,
    0x2, 0xD, 0xB, 0x7, 0x5, 0x0, 0x8, 0xE
};

static const uint8_t GIFT_SBOX_INV[16] = {
    0xD, 0x0, 0x8, 0x6, 0x2, 0xC, 0x4, 0xB,
    0xE, 0x7, 0x1, 0xA, 0x3, 0x9, 0xF, 0x5
};

static const uint8_t PERM[128] = {
      0,  33,  66,  99,  96,   1,  34,  67,
     64,  97,   2,  35,  32,  65,  98,   3,
      4,  37,  70, 103, 100,   5,  38,  71,
     68, 101,   6,  39,  36,  69, 102,   7,
      8,  41,  74, 107, 104,   9,  42,  75,
     72, 105,  10,  43,  40,  73, 106,  11,
     12,  45,  78, 111, 108,  13,  46,  79,
     76, 109,  14,  47,  44,  77, 110,  15,
     16,  49,  82, 115, 112,  17,  50,  83,
     80, 113,  18,  51,  48,  81, 114,  19,
     20,  53,  86, 119, 116,  21,  54,  87,
     84, 117,  22,  55,  52,  85, 118,  23,
     24,  57,  90, 123, 120,  25,  58,  91,
     88, 121,  26,  59,  56,  89, 122,  27,
     28,  61,  94, 127, 124,  29,  62,  95,
     92, 125,  30,  63,  60,  93, 126,  31
};

static const uint8_t PERM_INV[128] = {
      0,   5,  10,  15,  16,  21,  26,  31,
     32,  37,  42,  47,  48,  53,  58,  63,
     64,  69,  74,  79,  80,  85,  90,  95,
     96, 101, 106, 111, 112, 117, 122, 127,
     12,   1,   6,  11,  28,  17,  22,  27,
     44,  33,  38,  43,  60,  49,  54,  59,
     76,  65,  70,  75,  92,  81,  86,  91,
    108,  97, 102, 107, 124, 113, 118, 123,
      8,  13,   2,   7,  24,  29,  18,  23,
     40,  45,  34,  39,  56,  61,  50,  55,
     72,  77,  66,  71,  88,  93,  82,  87,
    104, 109,  98, 103, 120, 125, 114, 119,
      4,   9,  14,   3,  20,  25,  30,  19,
     36,  41,  46,  35,  52,  57,  62,  51,
     68,  73,  78,  67,  84,  89,  94,  83,
    100, 105, 110,  99, 116, 121, 126, 115
};

GIFT_Basic::GIFT_Basic() { memset(rk_, 0, sizeof(rk_)); }
GIFT_Basic::~GIFT_Basic() {}

void GIFT_Basic::set_key(const uint8_t* key) {
    uint16_t k[8];
    for (int i = 0; i < 8; i++) {
        k[i] = ((uint16_t)key[2*i] << 8) | key[2*i+1];
    }

    for (int r = 0; r < 40; r++) {
        rk_[r] = ((uint32_t)(k[5] & 0xFFFF) << 16) | (k[4] & 0xFFFF);
        rk_[r] = ((rk_[r] << 16) & 0xFFFF0000) | ((uint32_t)(k[1] & 0xFFFF));
        rk_[r] = (rk_[r] << 16) | (k[0] & 0xFFFF);

        uint16_t t0 = (k[1] >> 2) | (k[1] << 14);
        uint16_t t1 = (k[0] >> 12) | (k[0] << 4);
        k[7] = k[6];
        k[6] = k[5];
        k[5] = k[4];
        k[4] = k[3];
        k[3] = k[2];
        k[2] = k[1];
        k[1] = k[0];
        k[0] = t1;
    }
}

static void gift_encrypt_round(uint8_t* state, uint32_t rk, int round) {
    uint8_t rc = 0;
    int c = round;
    for (int i = 0; i < 6; i++) {
        rc = (rc << 1) | (c & 1);
        c >>= 1;
    }
    rc = ((rc << 1) | 1) & 0x3F;

    for (int i = 0; i < 16; i++) {
        uint8_t nibble = state[i];
        uint8_t hi = (nibble >> 4) & 0xF;
        uint8_t lo = nibble & 0xF;
        state[i] = (GIFT_SBOX[hi] << 4) | GIFT_SBOX[lo];
    }

    uint8_t bits[128];
    for (int i = 0; i < 16; i++) {
        for (int b = 0; b < 8; b++) {
            bits[8*i + b] = (state[i] >> (7 - b)) & 1;
        }
    }

    uint32_t rk_word = rk;
    for (int i = 0; i < 32; i++) {
        bits[4*i + 1] ^= (rk_word >> (31 - i)) & 1;
    }
    rk_word = rk >> 32;
    for (int i = 0; i < 32; i++) {
        bits[4*i + 2] ^= (rk_word >> (31 - i)) & 1;
    }

    bits[127] ^= 1;
    for (int i = 0; i < 6; i++) {
        bits[127 - 4*i] ^= (rc >> (5 - i)) & 1;
    }

    uint8_t perm[128];
    for (int i = 0; i < 128; i++) {
        perm[i] = bits[PERM[i]];
    }

    for (int i = 0; i < 16; i++) {
        state[i] = 0;
        for (int b = 0; b < 8; b++) {
            state[i] = (state[i] << 1) | perm[8*i + b];
        }
    }
}

static void gift_decrypt_round(uint8_t* state, uint32_t rk, int round) {
    uint8_t bits[128];
    for (int i = 0; i < 16; i++) {
        for (int b = 0; b < 8; b++) {
            bits[8*i + b] = (state[i] >> (7 - b)) & 1;
        }
    }

    uint8_t perm[128];
    for (int i = 0; i < 128; i++) {
        perm[i] = bits[PERM_INV[i]];
    }

    uint8_t rc = 0;
    int c = round;
    for (int i = 0; i < 6; i++) {
        rc = (rc << 1) | (c & 1);
        c >>= 1;
    }
    rc = ((rc << 1) | 1) & 0x3F;

    perm[127] ^= 1;
    for (int i = 0; i < 6; i++) {
        perm[127 - 4*i] ^= (rc >> (5 - i)) & 1;
    }

    uint32_t rk_word = rk;
    for (int i = 0; i < 32; i++) {
        perm[4*i + 1] ^= (rk_word >> (31 - i)) & 1;
    }
    rk_word = rk >> 32;
    for (int i = 0; i < 32; i++) {
        perm[4*i + 2] ^= (rk_word >> (31 - i)) & 1;
    }

    for (int i = 0; i < 16; i++) {
        state[i] = 0;
        for (int b = 0; b < 8; b++) {
            state[i] = (state[i] << 1) | perm[8*i + b];
        }
    }

    for (int i = 0; i < 16; i++) {
        uint8_t nibble = state[i];
        uint8_t hi = (nibble >> 4) & 0xF;
        uint8_t lo = nibble & 0xF;
        state[i] = (GIFT_SBOX_INV[hi] << 4) | GIFT_SBOX_INV[lo];
    }
}

void GIFT_Basic::encrypt_block(const uint8_t* plaintext, uint8_t* ciphertext) const {
    uint8_t state[16];
    memcpy(state, plaintext, 16);

    for (int r = 0; r < 40; r++) {
        gift_encrypt_round(state, rk_[r] & 0xFFFFFFFF, r);
    }

    memcpy(ciphertext, state, 16);
}

void GIFT_Basic::decrypt_block(const uint8_t* ciphertext, uint8_t* plaintext) const {
    uint8_t state[16];
    memcpy(state, ciphertext, 16);

    for (int r = 39; r >= 0; r--) {
        gift_decrypt_round(state, rk_[r] & 0xFFFFFFFF, r);
    }

    memcpy(plaintext, state, 16);
}
