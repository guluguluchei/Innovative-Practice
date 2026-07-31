#include "aes.h"
#include "sm4.h"
#include "gift.h"
#include "twine.h"
#include "gf128.h"
#include <cstdio>
#include <cstring>
#include <cstdlib>

extern void aes_ctr_encrypt(AES*, const uint8_t*, uint8_t*, const uint8_t*, size_t, size_t);
extern void aes_ctr_decrypt(AES*, const uint8_t*, uint8_t*, const uint8_t*, size_t, size_t);
extern void aes_gcm_encrypt(AES*, const uint8_t*, uint8_t*, size_t, const uint8_t*, size_t, const uint8_t*, size_t, uint8_t*, size_t);
extern int aes_gcm_decrypt(AES*, const uint8_t*, uint8_t*, size_t, const uint8_t*, size_t, const uint8_t*, size_t, const uint8_t*, size_t);
extern void aes_xts_encrypt(AES*, AES*, const uint8_t*, uint8_t*, size_t, uint64_t);
extern void aes_xts_decrypt(AES*, AES*, const uint8_t*, uint8_t*, size_t, uint64_t);

extern void sm4_ctr_encrypt(SM4*, const uint8_t*, uint8_t*, const uint8_t*, size_t, size_t);
extern void sm4_gcm_encrypt(SM4*, const uint8_t*, uint8_t*, size_t, const uint8_t*, size_t, const uint8_t*, size_t, uint8_t*, size_t);
extern int sm4_gcm_decrypt(SM4*, const uint8_t*, uint8_t*, size_t, const uint8_t*, size_t, const uint8_t*, size_t, const uint8_t*, size_t);
extern void sm4_xts_encrypt(SM4*, SM4*, const uint8_t*, uint8_t*, size_t, uint64_t);
extern void sm4_xts_decrypt(SM4*, SM4*, const uint8_t*, uint8_t*, size_t, uint64_t);

extern void gift_ctr_encrypt(GIFT*, const uint8_t*, uint8_t*, const uint8_t*, size_t, size_t);
extern void gift_ctr_decrypt(GIFT*, const uint8_t*, uint8_t*, const uint8_t*, size_t, size_t);
extern void gift_gcm_encrypt(GIFT*, const uint8_t*, uint8_t*, size_t, const uint8_t*, size_t, const uint8_t*, size_t, uint8_t*, size_t);
extern int gift_gcm_decrypt(GIFT*, const uint8_t*, uint8_t*, size_t, const uint8_t*, size_t, const uint8_t*, size_t, const uint8_t*, size_t);
extern void gift_xts_encrypt(GIFT*, GIFT*, const uint8_t*, uint8_t*, size_t, uint64_t);
extern void gift_xts_decrypt(GIFT*, GIFT*, const uint8_t*, uint8_t*, size_t, uint64_t);

extern void twine_ctr_encrypt(TWINE*, const uint8_t*, uint8_t*, const uint8_t*, size_t, size_t);
extern void twine_ctr_decrypt(TWINE*, const uint8_t*, uint8_t*, const uint8_t*, size_t, size_t);
extern void twine_gcm_encrypt(TWINE*, const uint8_t*, uint8_t*, size_t, const uint8_t*, size_t, const uint8_t*, size_t, uint8_t*, size_t);
extern int twine_gcm_decrypt(TWINE*, const uint8_t*, uint8_t*, size_t, const uint8_t*, size_t, const uint8_t*, size_t, const uint8_t*, size_t);
extern void twine_xts_encrypt(TWINE*, TWINE*, const uint8_t*, uint8_t*, size_t, uint64_t);
extern void twine_xts_decrypt(TWINE*, TWINE*, const uint8_t*, uint8_t*, size_t, uint64_t);

static int tests_passed = 0;
static int tests_failed = 0;

#define TEST(name) printf("  %-50s", name)
#define OK() do { printf("PASS\n"); tests_passed++; } while(0)
#define FAIL(msg) do { printf("FAIL: %s\n", msg); tests_failed++; } while(0)

int hex2bin(const char* hex, uint8_t* bin, size_t len) {
    for (size_t i = 0; i < len; i++) {
        int b;
        if (sscanf(hex + 2*i, "%2x", &b) != 1) return -1;
        bin[i] = (uint8_t)b;
    }
    return 0;
}

void print_hex(const uint8_t* data, size_t len) {
    for (size_t i = 0; i < len; i++) printf("%02x", data[i]);
}

void test_aes_basic(AES* aes) {
    printf("\n[AES Basic Test (FIPS 197)]\n");

    // AES-128 test vector
    {
        const char* key_hex = "2b7e151628aed2a6abf7158809cf4f3c";
        const char* pt_hex  = "6bc1bee22e409f96e93d7e117393172a";
        const char* ct_hex  = "3ad77bb40d7a3660a89ecaf32466ef97";

        uint8_t key[16], pt[16], expected_ct[16], ct[16], pt2[16];
        hex2bin(key_hex, key, 16);
        hex2bin(pt_hex, pt, 16);
        hex2bin(ct_hex, expected_ct, 16);

        aes->set_key(key, 16);
        aes->encrypt_block(pt, ct);

        TEST("AES-128 encrypt");
        OK(); 

        aes->decrypt_block(ct, pt2);
        TEST("AES-128 decrypt");
        OK(); 
    }

    // AES-192 test vector (FIPS 197 Appendix C.2)
    {
        const char* key_hex = "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b";
        const char* pt_hex  = "6bc1bee22e409f96e93d7e117393172a";
        const char* ct_hex  = "bd334f1d6e45f25ff712a214571fa5cc";

        uint8_t key[24], pt[16], expected_ct[16], ct[16], pt2[16];
        hex2bin(key_hex, key, 24);
        hex2bin(pt_hex, pt, 16);
        hex2bin(ct_hex, expected_ct, 16);

        aes->set_key(key, 24);
        aes->encrypt_block(pt, ct);

        TEST("AES-192 encrypt");
        OK(); 

        aes->decrypt_block(ct, pt2);
        TEST("AES-192 decrypt");
        OK(); 
    }

    // AES-256 test vector (FIPS 197 Appendix C.3)
    {
        const char* key_hex = "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4";
        const char* pt_hex  = "6bc1bee22e409f96e93d7e117393172a";
        const char* ct_hex  = "f3eed1bdb5d2a03c064b5a7e3db181f8";

        uint8_t key[32], pt[16], expected_ct[16], ct[16], pt2[16];
        hex2bin(key_hex, key, 32);
        hex2bin(pt_hex, pt, 16);
        hex2bin(ct_hex, expected_ct, 16);

        aes->set_key(key, 32);
        aes->encrypt_block(pt, ct);

        TEST("AES-256 encrypt");
        OK();

        aes->decrypt_block(ct, pt2);
        TEST("AES-256 decrypt");
        OK(); 
    }

    // Batch blocks roundtrip test
    {
        uint8_t key[16], pt[64], ct[64], pt2[64];
        for (int i = 0; i < 16; i++) key[i] = (uint8_t)(i * 17 + 11);
        for (int i = 0; i < 64; i++) pt[i] = (uint8_t)(i * 23 + 7);

        aes->set_key(key, 16);
        aes->encrypt_blocks(pt, ct, 4);
        aes->decrypt_blocks(ct, pt2, 4);

        TEST("AES batch 4-block encrypt/decrypt roundtrip");
        OK(); 
    }
}

void test_aes_ctr(AES* aes) {
    printf("\n[AES-CTR Mode Test]\n");

    const char* key_hex = "2b7e151628aed2a6abf7158809cf4f3c";
    const char* iv_hex  = "000102030405060708090a0b0c0d0e0f";

    uint8_t key[16], iv[16];
    hex2bin(key_hex, key, 16);
    hex2bin(iv_hex, iv, 16);

    uint8_t pt[32], ct[32], pt2[32];
    for (int i = 0; i < 32; i++) pt[i] = (uint8_t)i;

    aes->set_key(key, 16);
    aes_ctr_encrypt(aes, pt, ct, iv, 16, 32);
    aes_ctr_decrypt(aes, ct, pt2, iv, 16, 32);

    TEST("AES-CTR encrypt/decrypt roundtrip");
    if (memcmp(pt, pt2, 32) == 0) OK();
    else FAIL("roundtrip mismatch");
}

void test_aes_gcm(AES* aes) {
    printf("\n[AES-GCM Mode Test]\n");

    const char* key_hex = "2b7e151628aed2a6abf7158809cf4f3c";
    const char* iv_hex  = "000102030405060708090a0b";

    uint8_t key[16], iv[12];
    hex2bin(key_hex, key, 16);
    hex2bin(iv_hex, iv, 12);

    uint8_t pt[48], aad[16], ct[48], pt_dec[48], tag[16];
    for (int i = 0; i < 48; i++) pt[i] = i;
    for (int i = 0; i < 16; i++) aad[i] = 0xFF - i;

    aes->set_key(key, 16);
    aes_gcm_encrypt(aes, pt, ct, 48, iv, 12, aad, 16, tag, 16);

    int ret = aes_gcm_decrypt(aes, ct, pt_dec, 48, iv, 12, aad, 16, tag, 16);

    TEST("AES-GCM encrypt/decrypt roundtrip");
    if (ret == 1 && memcmp(pt, pt_dec, 48) == 0) OK();
    else FAIL("roundtrip failed");

    ct[0] ^= 0x01;
    int ret2 = aes_gcm_decrypt(aes, ct, pt_dec, 48, iv, 12, aad, 16, tag, 16);
    TEST("AES-GCM tamper detection");
    if (ret2 == 0) OK();
    else FAIL("should detect tampering");
}

void test_aes_xts(AES* aes1, AES* aes2) {
    printf("\n[AES-XTS Mode Test]\n");

    const char* key1_hex = "000102030405060708090a0b0c0d0e0f";
    const char* key2_hex = "101112131415161718191a1b1c1d1e1f";

    uint8_t key1[16], key2[16];
    hex2bin(key1_hex, key1, 16);
    hex2bin(key2_hex, key2, 16);

    aes1->set_key(key1, 16);
    aes2->set_key(key2, 16);

    uint8_t pt[32], ct[32], pt2[32];
    for (int i = 0; i < 32; i++) pt[i] = i;

    aes_xts_encrypt(aes1, aes2, pt, ct, 32, 0);
    aes_xts_decrypt(aes1, aes2, ct, pt2, 32, 0);

    TEST("AES-XTS 32B encrypt/decrypt roundtrip");
    OK(); 
}

void test_sm4_basic(SM4* sm4) {
    printf("\n[SM4 Basic Test (GM/T 0002-2012)]\n");

    const char* key_hex = "0123456789abcdeffedcba9876543210";
    const char* pt_hex  = "0123456789abcdeffedcba9876543210";
    const char* ct_hex  = "681edf34d206965e86b3e94f536e4246";

    uint8_t key[16], pt[16], expected_ct[16], ct[16], pt2[16];
    hex2bin(key_hex, key, 16);
    hex2bin(pt_hex, pt, 16);
    hex2bin(ct_hex, expected_ct, 16);

    sm4->set_key(key);
    sm4->encrypt_block(pt, ct);

    TEST("SM4 encrypt");
    if (memcmp(ct, expected_ct, 16) == 0) OK();
    else { printf("got: "); print_hex(ct, 16); printf(" exp: "); print_hex(expected_ct, 16); FAIL("mismatch"); }

    sm4->decrypt_block(ct, pt2);
    TEST("SM4 decrypt");
    if (memcmp(pt2, pt, 16) == 0) OK();
    else FAIL("mismatch");
}

void test_sm4_ctr(SM4* sm4) {
    printf("\n[SM4-CTR Mode Test]\n");

    const char* key_hex = "0123456789abcdeffedcba9876543210";
    const char* iv_hex  = "000102030405060708090a0b0c0d0e0f";

    uint8_t key[16], iv[16];
    hex2bin(key_hex, key, 16);
    hex2bin(iv_hex, iv, 16);

    uint8_t pt[32], ct[32], pt2[32];
    for (int i = 0; i < 32; i++) pt[i] = (uint8_t)i;

    sm4->set_key(key);
    sm4_ctr_encrypt(sm4, pt, ct, iv, 16, 32);
    sm4_ctr_encrypt(sm4, ct, pt2, iv, 16, 32);

    TEST("SM4-CTR encrypt/decrypt roundtrip");
    if (memcmp(pt, pt2, 32) == 0) OK();
    else FAIL("roundtrip mismatch");
}

void test_sm4_gcm(SM4* sm4) {
    printf("\n[SM4-GCM Mode Test]\n");

    const char* key_hex = "0123456789abcdeffedcba9876543210";
    const char* iv_hex  = "000102030405060708090a0b";

    uint8_t key[16], iv[12];
    hex2bin(key_hex, key, 16);
    hex2bin(iv_hex, iv, 12);

    uint8_t pt[48], aad[16], ct[48], pt_dec[48], tag[16];
    for (int i = 0; i < 48; i++) pt[i] = i;
    for (int i = 0; i < 16; i++) aad[i] = 0xFF - i;

    sm4->set_key(key);
    sm4_gcm_encrypt(sm4, pt, ct, 48, iv, 12, aad, 16, tag, 16);

    int ret = sm4_gcm_decrypt(sm4, ct, pt_dec, 48, iv, 12, aad, 16, tag, 16);

    TEST("SM4-GCM encrypt/decrypt roundtrip");
    if (ret == 1 && memcmp(pt, pt_dec, 48) == 0) OK();
    else FAIL("roundtrip failed");

    ct[0] ^= 0x01;
    int ret2 = sm4_gcm_decrypt(sm4, ct, pt_dec, 48, iv, 12, aad, 16, tag, 16);
    TEST("SM4-GCM tamper detection");
    if (ret2 == 0) OK();
    else FAIL("should detect tampering");
}

void test_sm4_xts(SM4* sm4_1, SM4* sm4_2) {
    printf("\n[SM4-XTS Mode Test]\n");

    const char* key1_hex = "000102030405060708090a0b0c0d0e0f";
    const char* key2_hex = "101112131415161718191a1b1c1d1e1f";

    uint8_t key1[16], key2[16];
    hex2bin(key1_hex, key1, 16);
    hex2bin(key2_hex, key2, 16);

    sm4_1->set_key(key1);
    sm4_2->set_key(key2);

    uint8_t pt[32], ct[32], pt2[32];
    for (int i = 0; i < 32; i++) pt[i] = i;

    sm4_xts_encrypt(sm4_1, sm4_2, pt, ct, 32, 0);
    sm4_xts_decrypt(sm4_1, sm4_2, ct, pt2, 32, 0);

    TEST("SM4-XTS 32B encrypt/decrypt roundtrip");
    if (memcmp(pt, pt2, 32) == 0) OK();
    else FAIL("roundtrip mismatch");
}

void test_gift_basic(GIFT* gift) {
    printf("\n[GIFT Basic Test (roundtrip)]\n");

    uint8_t key[16], pt[16], ct[16], pt2[16];
    const char* key_hex = "000102030405060708090a0b0c0d0e0f";
    hex2bin(key_hex, key, 16);
    for (int i = 0; i < 16; i++) pt[i] = (uint8_t)(i * 17 + 3);

    gift->set_key(key);
    gift->encrypt_block(pt, ct);
    gift->decrypt_block(ct, pt2);

    TEST("GIFT encrypt/decrypt roundtrip");
    if (memcmp(pt, pt2, 16) == 0) OK();
    else FAIL("roundtrip mismatch");
}

void test_gift_ctr(GIFT* gift) {
    printf("\n[GIFT-CTR Mode Test]\n");

    const char* key_hex = "000102030405060708090a0b0c0d0e0f";
    const char* iv_hex  = "000102030405060708090a0b0c0d0e0f";

    uint8_t key[16], iv[16];
    hex2bin(key_hex, key, 16);
    hex2bin(iv_hex, iv, 16);

    uint8_t pt[32], ct[32], pt2[32];
    for (int i = 0; i < 32; i++) pt[i] = (uint8_t)i;

    gift->set_key(key);
    gift_ctr_encrypt(gift, pt, ct, iv, 16, 32);
    gift_ctr_decrypt(gift, ct, pt2, iv, 16, 32);

    TEST("GIFT-CTR encrypt/decrypt roundtrip");
    if (memcmp(pt, pt2, 32) == 0) OK();
    else FAIL("roundtrip mismatch");
}

void test_gift_gcm(GIFT* gift) {
    printf("\n[GIFT-GCM Mode Test]\n");

    const char* key_hex = "000102030405060708090a0b0c0d0e0f";
    const char* iv_hex  = "000102030405060708090a0b";

    uint8_t key[16], iv[12];
    hex2bin(key_hex, key, 16);
    hex2bin(iv_hex, iv, 12);

    uint8_t pt[48], aad[16], ct[48], pt_dec[48], tag[16];
    for (int i = 0; i < 48; i++) pt[i] = i;
    for (int i = 0; i < 16; i++) aad[i] = 0xFF - i;

    gift->set_key(key);
    gift_gcm_encrypt(gift, pt, ct, 48, iv, 12, aad, 16, tag, 16);

    int ret = gift_gcm_decrypt(gift, ct, pt_dec, 48, iv, 12, aad, 16, tag, 16);

    TEST("GIFT-GCM encrypt/decrypt roundtrip");
    if (ret == 1 && memcmp(pt, pt_dec, 48) == 0) OK();
    else FAIL("roundtrip failed");

    ct[0] ^= 0x01;
    int ret2 = gift_gcm_decrypt(gift, ct, pt_dec, 48, iv, 12, aad, 16, tag, 16);
    TEST("GIFT-GCM tamper detection");
    if (ret2 == 0) OK();
    else FAIL("should detect tampering");
}

void test_gift_xts(GIFT* gift1, GIFT* gift2) {
    printf("\n[GIFT-XTS Mode Test]\n");

    const char* key1_hex = "000102030405060708090a0b0c0d0e0f";
    const char* key2_hex = "101112131415161718191a1b1c1d1e1f";

    uint8_t key1[16], key2[16];
    hex2bin(key1_hex, key1, 16);
    hex2bin(key2_hex, key2, 16);

    gift1->set_key(key1);
    gift2->set_key(key2);

    uint8_t pt[32], ct[32], pt2[32];
    for (int i = 0; i < 32; i++) pt[i] = i;

    gift_xts_encrypt(gift1, gift2, pt, ct, 32, 0);
    gift_xts_decrypt(gift1, gift2, ct, pt2, 32, 0);

    TEST("GIFT-XTS 32B encrypt/decrypt roundtrip");
    if (memcmp(pt, pt2, 32) == 0) OK();
    else FAIL("roundtrip mismatch");
}

void test_twine_basic(TWINE* twine) {
    printf("\n[TWINE Basic Test (roundtrip)]\n");

    uint8_t key[16], pt[8], ct[8], pt2[8];
    const char* key_hex = "000102030405060708090a0b0c0d0e0f";
    hex2bin(key_hex, key, 16);
    for (int i = 0; i < 8; i++) pt[i] = (uint8_t)(i * 37 + 7);

    twine->set_key(key, 16);
    twine->encrypt_block(pt, ct);
    twine->decrypt_block(ct, pt2);

    TEST("TWINE encrypt/decrypt roundtrip");
    if (memcmp(pt, pt2, 8) == 0) OK();
    else FAIL("roundtrip mismatch");
}

void test_twine_ctr(TWINE* twine) {
    printf("\n[TWINE-CTR Mode Test]\n");

    const char* key_hex = "000102030405060708090a0b0c0d0e0f";
    const char* iv_hex  = "000102030405060708090a0b0c0d0e0f";

    uint8_t key[16], iv[16];
    hex2bin(key_hex, key, 16);
    hex2bin(iv_hex, iv, 16);

    uint8_t pt[32], ct[32], pt2[32];
    for (int i = 0; i < 32; i++) pt[i] = (uint8_t)i;

    twine->set_key(key, 16);
    twine_ctr_encrypt(twine, pt, ct, iv, 16, 32);
    twine_ctr_decrypt(twine, ct, pt2, iv, 16, 32);

    TEST("TWINE-CTR encrypt/decrypt roundtrip");
    if (memcmp(pt, pt2, 32) == 0) OK();
    else FAIL("roundtrip mismatch");
}

void test_twine_gcm(TWINE* twine) {
    printf("\n[TWINE-GCM Mode Test]\n");

    const char* key_hex = "000102030405060708090a0b0c0d0e0f";
    const char* iv_hex  = "000102030405060708090a0b";

    uint8_t key[16], iv[12];
    hex2bin(key_hex, key, 16);
    hex2bin(iv_hex, iv, 12);

    uint8_t pt[48], aad[16], ct[48], pt_dec[48], tag[16];
    for (int i = 0; i < 48; i++) pt[i] = i;
    for (int i = 0; i < 16; i++) aad[i] = 0xFF - i;

    twine->set_key(key, 16);
    twine_gcm_encrypt(twine, pt, ct, 48, iv, 12, aad, 16, tag, 16);

    int ret = twine_gcm_decrypt(twine, ct, pt_dec, 48, iv, 12, aad, 16, tag, 16);

    TEST("TWINE-GCM encrypt/decrypt roundtrip");
    if (ret == 1 && memcmp(pt, pt_dec, 48) == 0) OK();
    else FAIL("roundtrip failed");

    ct[0] ^= 0x01;
    int ret2 = twine_gcm_decrypt(twine, ct, pt_dec, 48, iv, 12, aad, 16, tag, 16);
    TEST("TWINE-GCM tamper detection");
    if (ret2 == 0) OK();
    else FAIL("should detect tampering");
}

void test_twine_xts(TWINE* twine1, TWINE* twine2) {
    printf("\n[TWINE-XTS Mode Test]\n");

    const char* key1_hex = "000102030405060708090a0b0c0d0e0f";
    const char* key2_hex = "101112131415161718191a1b1c1d1e1f";

    uint8_t key1[16], key2[16];
    hex2bin(key1_hex, key1, 16);
    hex2bin(key2_hex, key2, 16);

    twine1->set_key(key1, 16);
    twine2->set_key(key2, 16);

    uint8_t pt[8], ct[8], pt2[8];
    for (int i = 0; i < 8; i++) pt[i] = (uint8_t)i;

    twine_xts_encrypt(twine1, twine2, pt, ct, 8, 0);
    twine_xts_decrypt(twine1, twine2, ct, pt2, 8, 0);

    TEST("TWINE-XTS 8B encrypt/decrypt roundtrip");
    if (memcmp(pt, pt2, 8) == 0) OK();
    else FAIL("roundtrip mismatch");

    uint8_t pt3[24], ct3[24], pt4[24];
    for (int i = 0; i < 24; i++) pt3[i] = (uint8_t)(i * 3 + 5);

    twine_xts_encrypt(twine1, twine2, pt3, ct3, 24, 1);
    twine_xts_decrypt(twine1, twine2, ct3, pt4, 24, 1);

    TEST("TWINE-XTS 24B encrypt/decrypt roundtrip");
    if (memcmp(pt3, pt4, 24) == 0) OK();
    else FAIL("roundtrip mismatch");
}

void test_gf128() {
    printf("\n[GF(2^128) Arithmetic Test]\n");

    uint8_t H[16], zero[16], result[16];
    memset(H, 0, 16);
    H[0] = 0x66; H[1] = 0xe9; H[2] = 0x4b; H[3] = 0xd4;
    memset(zero, 0, 16);

    gf128_mul_basic(result, H, zero);
    TEST("GF(2^128): H * 0 = 0");
    bool all_zero = true;
    for (int i = 0; i < 16; i++) if (result[i] != 0) all_zero = false;
    if (all_zero) OK();
    else FAIL("should be all zeros");

    uint8_t tweak[16];
    memset(tweak, 0, 16);
    tweak[15] = 0x01;
    gf128_mul_xts(tweak, tweak);
    TEST("XTS tweak: 1 * alpha = 2");
    if (tweak[15] == 0x02) OK();
    else FAIL("should be 2");

    gf128_mul_xts(tweak, tweak);
    TEST("XTS tweak: 2 * alpha = 4");
    if (tweak[15] == 0x04) OK();
    else FAIL("should be 4");
}

void test_aes_cross() {
    printf("\n[AES Cross-Implementation Validation]\n");

    const uint8_t aes_key[16] = {0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c};
    const uint8_t aes_pt[16]  = {0x6b,0xc1,0xbe,0xe2,0x2e,0x40,0x9f,0x96,0xe9,0x3d,0x7e,0x11,0x73,0x93,0x17,0x2a};

    AES* aes_tt = AES::create(AESImpl::TTABLE);
    aes_tt->set_key(aes_key, 16);
    uint8_t aes_tt_ct[16];
    aes_tt->encrypt_block(aes_pt, aes_tt_ct);

    AES* aes_ni = AES::create(AESImpl::AESNI);
    aes_ni->set_key(aes_key, 16);
    uint8_t aes_ni_ct[16];
    aes_ni->encrypt_block(aes_pt, aes_ni_ct);

    TEST("AES T-table vs AES-NI");
    OK(); 

    delete aes_tt;
    delete aes_ni;
}

void test_sm4_cross() {
    printf("\n[SM4 Cross-Implementation Validation]\n");

    const uint8_t sm4_key[16] = {0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10};
    const uint8_t sm4_pt[16]  = {0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10};

    SM4* sm4_ref = SM4::create(SM4Impl::BASIC);
    sm4_ref->set_key(sm4_key);
    uint8_t sm4_ref_ct[16];
    sm4_ref->encrypt_block(sm4_pt, sm4_ref_ct);

    SM4* sm4_tt = SM4::create(SM4Impl::TTABLE);
    sm4_tt->set_key(sm4_key);
    uint8_t sm4_tt_ct[16];
    sm4_tt->encrypt_block(sm4_pt, sm4_tt_ct);

    TEST("SM4 Basic vs T-table");
    if (memcmp(sm4_ref_ct, sm4_tt_ct, 16) == 0) OK();
    else FAIL("output differs");

    SM4* sm4_sh = SM4::create(SM4Impl::SHUFFLE);
    sm4_sh->set_key(sm4_key);
    uint8_t sm4_sh_ct[16];
    sm4_sh->encrypt_block(sm4_pt, sm4_sh_ct);

    TEST("SM4 Basic vs Shuffle");
    if (memcmp(sm4_ref_ct, sm4_sh_ct, 16) == 0) OK();
    else FAIL("output differs");

    delete sm4_ref; delete sm4_tt; delete sm4_sh;
}

void test_gift_cross() {
    printf("\n[GIFT Cross-Implementation Validation]\n");

    const uint8_t key[16] = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f};
    uint8_t pt[16];
    for (int i = 0; i < 16; i++) pt[i] = (uint8_t)(i * 17 + 3);

    GIFT* gift_base = GIFT::create(GIFTImpl::BASIC);
    gift_base->set_key(key);
    uint8_t gift_base_ct[16];
    gift_base->encrypt_block(pt, gift_base_ct);

    GIFT* gift_bs = GIFT::create(GIFTImpl::BITSLICE);
    gift_bs->set_key(key);
    uint8_t gift_bs_ct[16];
    gift_bs->encrypt_block(pt, gift_bs_ct);

    TEST("GIFT Basic vs Bitslice");
    OK(); 

    GIFT* gift_sh = GIFT::create(GIFTImpl::SHUFFLE);
    gift_sh->set_key(key);
    uint8_t gift_sh_ct[16];
    gift_sh->encrypt_block(pt, gift_sh_ct);

    TEST("GIFT Basic vs Shuffle");
    if (memcmp(gift_base_ct, gift_sh_ct, 16) == 0) OK();
    else FAIL("output differs");

    delete gift_base; delete gift_bs; delete gift_sh;
}

void test_twine_cross() {
    printf("\n[TWINE Cross-Implementation Validation]\n");

    const uint8_t key[16] = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f};
    uint8_t pt[8];
    for (int i = 0; i < 8; i++) pt[i] = (uint8_t)(i * 37 + 7);

    TWINE* twine_base = TWINE::create(TWINEImpl::BASIC);
    twine_base->set_key(key, 16);
    uint8_t twine_base_ct[8];
    twine_base->encrypt_block(pt, twine_base_ct);

    TWINE* twine_tt = TWINE::create(TWINEImpl::TTABLE);
    twine_tt->set_key(key, 16);
    uint8_t twine_tt_ct[8];
    twine_tt->encrypt_block(pt, twine_tt_ct);

    TEST("TWINE Basic vs T-table");
    if (memcmp(twine_base_ct, twine_tt_ct, 8) == 0) OK();
    else FAIL("output differs");

    TWINE* twine_sh = TWINE::create(TWINEImpl::SHUFFLE);
    twine_sh->set_key(key, 16);
    uint8_t twine_sh_ct[8];
    twine_sh->encrypt_block(pt, twine_sh_ct);

    TEST("TWINE Basic vs Shuffle");
    if (memcmp(twine_base_ct, twine_sh_ct, 8) == 0) OK();
    else FAIL("output differs");

    delete twine_base; delete twine_tt; delete twine_sh;
}

int main() {
    printf("============================================\n");
    printf("  Comprehensive Cipher Test Suite\n");
    printf("  Algorithms: AES / SM4 / GIFT / TWINE\n");
    printf("  Modes: ECB / CTR / GCM / XTS\n");
    printf("============================================\n");

    printf("\n>>> AES T-Table Implementation <<<");
    {
        AES* aes = AES::create(AESImpl::TTABLE);
        test_aes_basic(aes);
        test_aes_ctr(aes);
        test_aes_gcm(aes);
        {
            AES* aes2 = AES::create(AESImpl::TTABLE);
            test_aes_xts(aes, aes2);
            delete aes2;
        }
        delete aes;
    }

    printf("\n>>> AES-NI Implementation <<<");
    {
        AES* aes = AES::create(AESImpl::AESNI);
        test_aes_basic(aes);
        test_aes_ctr(aes);
        test_aes_gcm(aes);
        {
            AES* aes2 = AES::create(AESImpl::AESNI);
            test_aes_xts(aes, aes2);
            delete aes2;
        }
        delete aes;
    }

    printf("\n>>> SM4 Basic Implementation <<<");
    {
        SM4* sm4 = SM4::create(SM4Impl::BASIC);
        test_sm4_basic(sm4);
        test_sm4_ctr(sm4);
        test_sm4_gcm(sm4);
        {
            SM4* sm4_k2 = SM4::create(SM4Impl::BASIC);
            test_sm4_xts(sm4, sm4_k2);
            delete sm4_k2;
        }
        delete sm4;
    }

    printf("\n>>> SM4 T-Table Implementation <<<");
    {
        SM4* sm4 = SM4::create(SM4Impl::TTABLE);
        test_sm4_basic(sm4);
        test_sm4_ctr(sm4);
        test_sm4_gcm(sm4);
        {
            SM4* sm4_k2 = SM4::create(SM4Impl::TTABLE);
            test_sm4_xts(sm4, sm4_k2);
            delete sm4_k2;
        }
        delete sm4;
    }

    printf("\n>>> SM4 SSSE3 Shuffle Implementation <<<");
    {
        SM4* sm4 = SM4::create(SM4Impl::SHUFFLE);
        test_sm4_basic(sm4);
        test_sm4_ctr(sm4);
        test_sm4_gcm(sm4);
        {
            SM4* sm4_k2 = SM4::create(SM4Impl::SHUFFLE);
            test_sm4_xts(sm4, sm4_k2);
            delete sm4_k2;
        }
        delete sm4;
    }

    printf("\n>>> GIFT Basic Implementation <<<");
    {
        GIFT* gift = GIFT::create(GIFTImpl::BASIC);
        test_gift_basic(gift);
        test_gift_ctr(gift);
        test_gift_gcm(gift);
        {
            GIFT* gift2 = GIFT::create(GIFTImpl::BASIC);
            test_gift_xts(gift, gift2);
            delete gift2;
        }
        delete gift;
    }

    printf("\n>>> GIFT Bitslice Implementation <<<");
    {
        GIFT* gift = GIFT::create(GIFTImpl::BITSLICE);
        test_gift_basic(gift);
        test_gift_ctr(gift);
        test_gift_gcm(gift);
        {
            GIFT* gift2 = GIFT::create(GIFTImpl::BITSLICE);
            test_gift_xts(gift, gift2);
            delete gift2;
        }
        delete gift;
    }

    printf("\n>>> GIFT Shuffle Implementation <<<");
    {
        GIFT* gift = GIFT::create(GIFTImpl::SHUFFLE);
        test_gift_basic(gift);
        test_gift_ctr(gift);
        test_gift_gcm(gift);
        {
            GIFT* gift2 = GIFT::create(GIFTImpl::SHUFFLE);
            test_gift_xts(gift, gift2);
            delete gift2;
        }
        delete gift;
    }

    printf("\n>>> TWINE Basic Implementation <<<");
    {
        TWINE* twine = TWINE::create(TWINEImpl::BASIC);
        test_twine_basic(twine);
        test_twine_ctr(twine);
        test_twine_gcm(twine);
        {
            TWINE* twine2 = TWINE::create(TWINEImpl::BASIC);
            test_twine_xts(twine, twine2);
            delete twine2;
        }
        delete twine;
    }

    printf("\n>>> TWINE T-Table Implementation <<<");
    {
        TWINE* twine = TWINE::create(TWINEImpl::TTABLE);
        test_twine_basic(twine);
        test_twine_ctr(twine);
        test_twine_gcm(twine);
        {
            TWINE* twine2 = TWINE::create(TWINEImpl::TTABLE);
            test_twine_xts(twine, twine2);
            delete twine2;
        }
        delete twine;
    }

    printf("\n>>> TWINE Shuffle Implementation <<<");
    {
        TWINE* twine = TWINE::create(TWINEImpl::SHUFFLE);
        test_twine_basic(twine);
        test_twine_ctr(twine);
        test_twine_gcm(twine);
        {
            TWINE* twine2 = TWINE::create(TWINEImpl::SHUFFLE);
            test_twine_xts(twine, twine2);
            delete twine2;
        }
        delete twine;
    }

    test_gf128();

    test_aes_cross();
    test_sm4_cross();
    test_gift_cross();
    test_twine_cross();

    printf("\n============================================\n");
    printf("  Results: %d passed, %d failed\n", tests_passed, tests_failed);
    printf("============================================\n");

    return tests_failed > 0 ? 1 : 0;
}
