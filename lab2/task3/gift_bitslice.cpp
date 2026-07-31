#include "gift.h"
#include <cstring>

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

GIFT_Bitslice::GIFT_Bitslice() { memset(rk_, 0, sizeof(rk_)); }
GIFT_Bitslice::~GIFT_Bitslice() {}

void GIFT_Bitslice::set_key(const uint8_t* key) {
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
        k[7] = k[6]; k[6] = k[5]; k[5] = k[4]; k[4] = k[3];
        k[3] = k[2]; k[2] = k[1]; k[1] = k[0];
        k[0] = t1;
    }
}

static void bitslice_sbox(uint32_t& s0, uint32_t& s1, uint32_t& s2, uint32_t& s3) {
    s1 ^= (s0 & s2);
    s0 ^= (s1 & s3);
    s2 ^= (s0 | s1);
    s3 ^= s2;
    s1 ^= s3;
    s2 ^= (s0 & s1);
    uint32_t t = s0;
    s0 = s3; s3 = t;
}

static void bitslice_sbox_inv(uint32_t& s0, uint32_t& s1, uint32_t& s2, uint32_t& s3) {
    uint32_t t = s0;
    s0 = s3; s3 = t;
    s2 ^= (s0 & s1);
    s1 ^= s3;
    s3 ^= s2;
    s2 ^= (s0 | s1);
    s0 ^= (s1 & s3);
    s1 ^= (s0 & s2);
}

// PERM maps old bit position to new bit position.
// Bit position p = 4*j + k where j = nibble index (0..31), k = bit within nibble (0..3).
// In bitslice: s[k] bit (31-j) stores nibble j, bit k.
// To read/output bit-plane k, we iterate j=0..31 and use PERM[4*j + k].
static void bitslice_permbits(uint32_t& s0, uint32_t& s1, uint32_t& s2, uint32_t& s3) {
    uint32_t r0 = 0, r1 = 0, r2 = 0, r3 = 0;
    uint32_t ss[4] = {s0, s1, s2, s3};

    for (int j = 0; j < 32; j++) {
        // Bit-plane 0: output nibble j, bit 0 → source from PERM[4*j + 0]
        int src = PERM[4*j + 0];
        int old_j = src / 4, old_k = src % 4;
        if (ss[old_k] & (1u << (31 - old_j))) r0 |= (1u << (31 - j));

        // Bit-plane 1: output nibble j, bit 1 → source from PERM[4*j + 1]
        src = PERM[4*j + 1];
        old_j = src / 4; old_k = src % 4;
        if (ss[old_k] & (1u << (31 - old_j))) r1 |= (1u << (31 - j));

        // Bit-plane 2: output nibble j, bit 2 → source from PERM[4*j + 2]
        src = PERM[4*j + 2];
        old_j = src / 4; old_k = src % 4;
        if (ss[old_k] & (1u << (31 - old_j))) r2 |= (1u << (31 - j));

        // Bit-plane 3: output nibble j, bit 3 → source from PERM[4*j + 3]
        src = PERM[4*j + 3];
        old_j = src / 4; old_k = src % 4;
        if (ss[old_k] & (1u << (31 - old_j))) r3 |= (1u << (31 - j));
    }

    s0 = r0; s1 = r1; s2 = r2; s3 = r3;
}

static void bitslice_permbits_inv(uint32_t& s0, uint32_t& s1, uint32_t& s2, uint32_t& s3) {
    uint32_t r0 = 0, r1 = 0, r2 = 0, r3 = 0;
    uint32_t ss[4] = {s0, s1, s2, s3};

    for (int j = 0; j < 32; j++) {
        // Bit-plane 0: output nibble j, bit 0 → source from PERM_INV[4*j + 0]
        int src = PERM_INV[4*j + 0];
        int old_j = src / 4, old_k = src % 4;
        if (ss[old_k] & (1u << (31 - old_j))) r0 |= (1u << (31 - j));

        // Bit-plane 1: output nibble j, bit 1 → source from PERM_INV[4*j + 1]
        src = PERM_INV[4*j + 1];
        old_j = src / 4; old_k = src % 4;
        if (ss[old_k] & (1u << (31 - old_j))) r1 |= (1u << (31 - j));

        // Bit-plane 2: output nibble j, bit 2 → source from PERM_INV[4*j + 2]
        src = PERM_INV[4*j + 2];
        old_j = src / 4; old_k = src % 4;
        if (ss[old_k] & (1u << (31 - old_j))) r2 |= (1u << (31 - j));

        // Bit-plane 3: output nibble j, bit 3 → source from PERM_INV[4*j + 3]
        src = PERM_INV[4*j + 3];
        old_j = src / 4; old_k = src % 4;
        if (ss[old_k] & (1u << (31 - old_j))) r3 |= (1u << (31 - j));
    }

    s0 = r0; s1 = r1; s2 = r2; s3 = r3;
}

void GIFT_Bitslice::encrypt_block(const uint8_t* plaintext, uint8_t* ciphertext) const {
    uint32_t s[4];
    for (int i = 0; i < 4; i++) {
        s[i] = ((uint32_t)plaintext[4*i] << 24) | ((uint32_t)plaintext[4*i+1] << 16) |
               ((uint32_t)plaintext[4*i+2] << 8) | (uint32_t)plaintext[4*i+3];
    }

    for (int r = 0; r < 40; r++) {
        bitslice_sbox(s[0], s[1], s[2], s[3]);

        uint32_t rk = rk_[r];
        // Apply lower 32 bits of round key to positions 4*j+1 (spread across all 4 words)
        for (int j = 0; j < 32; j++) {
            if ((rk >> (31 - j)) & 1) {
                int w = j / 8;
                int bp = 31 - (4 * (j % 8) + 1);
                s[w] ^= (1u << bp);
            }
        }
        // Upper 32 bits of round key (positions 4*j+2) are 0 for uint32_t rk_

        uint8_t rc = 0;
        int c = r;
        for (int i = 0; i < 6; i++) {
            rc = (rc << 1) | (c & 1);
            c >>= 1;
        }
        rc = ((rc << 1) | 1) & 0x3F;

        // Constant 1 at bit 127 -> nibble 31 bit 3 -> s[3] bit 0
        s[3] ^= (1u << 0);
        // Round constant at bits {127,123,119,115,111,107} -> nibble {31,30,29,28,27,26} bit 3 -> s[3] bits 0..5
        for (int i = 0; i < 6; i++) {
            if (rc & (1 << (5 - i))) s[3] ^= (1u << i);
        }

        bitslice_permbits(s[0], s[1], s[2], s[3]);
    }

    for (int i = 0; i < 4; i++) {
        ciphertext[4*i]   = (s[i] >> 24) & 0xFF;
        ciphertext[4*i+1] = (s[i] >> 16) & 0xFF;
        ciphertext[4*i+2] = (s[i] >> 8) & 0xFF;
        ciphertext[4*i+3] = s[i] & 0xFF;
    }
}

void GIFT_Bitslice::decrypt_block(const uint8_t* ciphertext, uint8_t* plaintext) const {
    uint32_t s[4];
    for (int i = 0; i < 4; i++) {
        s[i] = ((uint32_t)ciphertext[4*i] << 24) | ((uint32_t)ciphertext[4*i+1] << 16) |
               ((uint32_t)ciphertext[4*i+2] << 8) | (uint32_t)ciphertext[4*i+3];
    }

    for (int r = 39; r >= 0; r--) {
        bitslice_permbits_inv(s[0], s[1], s[2], s[3]);

        uint8_t rc = 0;
        int c = r;
        for (int i = 0; i < 6; i++) {
            rc = (rc << 1) | (c & 1);
            c >>= 1;
        }
        rc = ((rc << 1) | 1) & 0x3F;

        // Constant 1 at bit 127 -> nibble 31 bit 3 -> s[3] bit 0
        s[3] ^= (1u << 0);
        // Round constant at bits {127,123,119,115,111,107} -> nibble {31,30,29,28,27,26} bit 3 -> s[3] bits 0..5
        for (int i = 0; i < 6; i++) {
            if (rc & (1 << (5 - i))) s[3] ^= (1u << i);
        }

        uint32_t rk = rk_[r];
        // Apply lower 32 bits of round key to positions 4*j+1 (spread across all 4 words)
        for (int j = 0; j < 32; j++) {
            if ((rk >> (31 - j)) & 1) {
                int w = j / 8;
                int bp = 31 - (4 * (j % 8) + 1);
                s[w] ^= (1u << bp);
            }
        }
        // Upper 32 bits of round key (positions 4*j+2) are 0 for uint32_t rk_

        bitslice_sbox_inv(s[0], s[1], s[2], s[3]);
    }

    for (int i = 0; i < 4; i++) {
        plaintext[4*i]   = (s[i] >> 24) & 0xFF;
        plaintext[4*i+1] = (s[i] >> 16) & 0xFF;
        plaintext[4*i+2] = (s[i] >> 8) & 0xFF;
        plaintext[4*i+3] = s[i] & 0xFF;
    }
}
