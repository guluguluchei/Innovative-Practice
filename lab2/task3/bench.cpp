#include "aes.h"
#include "sm4.h"
#include "gift.h"
#include "twine.h"
#include "gf128.h"
#include <chrono>
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <algorithm>

using namespace std::chrono;

extern void sm4_ctr_encrypt(SM4*, const uint8_t*, uint8_t*, const uint8_t*, size_t, size_t);
extern void sm4_gcm_encrypt(SM4*, const uint8_t*, uint8_t*, size_t, const uint8_t*, size_t,
                            const uint8_t*, size_t, uint8_t*, size_t);
extern void aes_ctr_encrypt(AES*, const uint8_t*, uint8_t*, const uint8_t*, size_t, size_t);
extern void aes_gcm_encrypt(AES*, const uint8_t*, uint8_t*, size_t, const uint8_t*, size_t,
                            const uint8_t*, size_t, uint8_t*, size_t);
extern void gift_ctr_encrypt(GIFT*, const uint8_t*, uint8_t*, const uint8_t*, size_t, size_t);
extern void gift_gcm_encrypt(GIFT*, const uint8_t*, uint8_t*, size_t, const uint8_t*, size_t,
                             const uint8_t*, size_t, uint8_t*, size_t);
extern void twine_ctr_encrypt(TWINE*, const uint8_t*, uint8_t*, const uint8_t*, size_t, size_t);
extern void twine_gcm_encrypt(TWINE*, const uint8_t*, uint8_t*, size_t, const uint8_t*, size_t,
                              const uint8_t*, size_t, uint8_t*, size_t);
extern void aes_xts_encrypt(AES*, AES*, const uint8_t*, uint8_t*, size_t, uint64_t);
extern void sm4_xts_encrypt(SM4*, SM4*, const uint8_t*, uint8_t*, size_t, uint64_t);
extern void gift_xts_encrypt(GIFT*, GIFT*, const uint8_t*, uint8_t*, size_t, uint64_t);
extern void twine_xts_encrypt(TWINE*, TWINE*, const uint8_t*, uint8_t*, size_t, uint64_t);

double measure_throughput(size_t bytes, double seconds) {
    if (seconds <= 0) return 0;
    return (double)bytes / (1024.0 * 1024.0) / seconds;
}

void bench_aes_blocks(const char* name, AES* aes, size_t data_size) {
    size_t num_blocks = data_size / 16;
    uint8_t* pt = new uint8_t[data_size];
    uint8_t* ct = new uint8_t[data_size];
    memset(pt, 0xAB, data_size);
    for (int i = 0; i < 100; i++) aes->encrypt_block(pt, ct);
    auto start = high_resolution_clock::now();
    int iterations = std::max(100, (int)(1048576 / data_size));
    for (int iter = 0; iter < iterations; iter++) {
        for (size_t i = 0; i < num_blocks; i++) {
            aes->encrypt_block(pt + 16*i, ct + 16*i);
        }
    }
    auto end = high_resolution_clock::now();
    double elapsed = duration_cast<microseconds>(end - start).count() / 1000000.0;
    double throughput = measure_throughput((size_t)iterations * data_size, elapsed);
    printf("  %-20s: %8.2f MB/s  (%zu MB in %.3fs)\n",
           name, throughput, (size_t)iterations * data_size / 1024 / 1024, elapsed);
    delete[] pt; delete[] ct;
}

void bench_aes_ctr(const char* name, AES* aes, size_t data_size) {
    uint8_t iv[16]; memset(iv, 0xCC, 16);
    uint8_t* pt = new uint8_t[data_size];
    uint8_t* ct = new uint8_t[data_size];
    memset(pt, 0xAB, data_size);
    aes_ctr_encrypt(aes, pt, ct, iv, 16, data_size);
    auto start = high_resolution_clock::now();
    int iterations = std::max(50, (int)(10485760 / data_size));
    for (int iter = 0; iter < iterations; iter++) {
        aes_ctr_encrypt(aes, pt, ct, iv, 16, data_size);
    }
    auto end = high_resolution_clock::now();
    double elapsed = duration_cast<microseconds>(end - start).count() / 1000000.0;
    double throughput = measure_throughput((size_t)iterations * data_size, elapsed);
    printf("  %-20s: %8.2f MB/s  (%zu MB in %.3fs)\n",
           name, throughput, (size_t)iterations * data_size / 1024 / 1024, elapsed);
    delete[] pt; delete[] ct;
}

void bench_aes_gcm(const char* name, AES* aes, size_t data_size) {
    uint8_t iv[12]; memset(iv, 0xDD, 12);
    uint8_t* pt = new uint8_t[data_size];
    uint8_t* ct = new uint8_t[data_size];
    uint8_t tag[16]; uint8_t aad[16];
    memset(pt, 0xAB, data_size); memset(aad, 0xEE, 16);
    aes_gcm_encrypt(aes, pt, ct, data_size, iv, 12, aad, 16, tag, 16);
    auto start = high_resolution_clock::now();
    int iterations = std::max(20, (int)(10485760 / data_size));
    for (int iter = 0; iter < iterations; iter++) {
        aes_gcm_encrypt(aes, pt, ct, data_size, iv, 12, aad, 16, tag, 16);
    }
    auto end = high_resolution_clock::now();
    double elapsed = duration_cast<microseconds>(end - start).count() / 1000000.0;
    double throughput = measure_throughput((size_t)iterations * data_size, elapsed);
    printf("  %-20s: %8.2f MB/s  (%zu MB in %.3fs)\n",
           name, throughput, (size_t)iterations * data_size / 1024 / 1024, elapsed);
    delete[] pt; delete[] ct;
}

void bench_sm4_blocks(const char* name, SM4* sm4, size_t data_size) {
    size_t num_blocks = data_size / 16;
    uint8_t* pt = new uint8_t[data_size];
    uint8_t* ct = new uint8_t[data_size];
    memset(pt, 0xAB, data_size);
    for (int i = 0; i < 100; i++) sm4->encrypt_block(pt, ct);
    auto start = high_resolution_clock::now();
    int iterations = std::max(100, (int)(1048576 / data_size));
    for (int iter = 0; iter < iterations; iter++) {
        for (size_t i = 0; i < num_blocks; i++) {
            sm4->encrypt_block(pt + 16*i, ct + 16*i);
        }
    }
    auto end = high_resolution_clock::now();
    double elapsed = duration_cast<microseconds>(end - start).count() / 1000000.0;
    double throughput = measure_throughput((size_t)iterations * data_size, elapsed);
    printf("  %-20s: %8.2f MB/s  (%zu MB in %.3fs)\n",
           name, throughput, (size_t)iterations * data_size / 1024 / 1024, elapsed);
    delete[] pt; delete[] ct;
}

void bench_sm4_ctr(const char* name, SM4* sm4, size_t data_size) {
    uint8_t iv[16]; memset(iv, 0xCC, 16);
    uint8_t* pt = new uint8_t[data_size];
    uint8_t* ct = new uint8_t[data_size];
    memset(pt, 0xAB, data_size);
    sm4_ctr_encrypt(sm4, pt, ct, iv, 16, data_size);
    auto start = high_resolution_clock::now();
    int iterations = std::max(50, (int)(10485760 / data_size));
    for (int iter = 0; iter < iterations; iter++) {
        sm4_ctr_encrypt(sm4, pt, ct, iv, 16, data_size);
    }
    auto end = high_resolution_clock::now();
    double elapsed = duration_cast<microseconds>(end - start).count() / 1000000.0;
    double throughput = measure_throughput((size_t)iterations * data_size, elapsed);
    printf("  %-20s: %8.2f MB/s  (%zu MB in %.3fs)\n",
           name, throughput, (size_t)iterations * data_size / 1024 / 1024, elapsed);
    delete[] pt; delete[] ct;
}

void bench_sm4_gcm(const char* name, SM4* sm4, size_t data_size) {
    uint8_t iv[12]; memset(iv, 0xDD, 12);
    uint8_t* pt = new uint8_t[data_size];
    uint8_t* ct = new uint8_t[data_size];
    uint8_t tag[16]; uint8_t aad[16];
    memset(pt, 0xAB, data_size); memset(aad, 0xEE, 16);
    sm4_gcm_encrypt(sm4, pt, ct, data_size, iv, 12, aad, 16, tag, 16);
    auto start = high_resolution_clock::now();
    int iterations = std::max(20, (int)(10485760 / data_size));
    for (int iter = 0; iter < iterations; iter++) {
        sm4_gcm_encrypt(sm4, pt, ct, data_size, iv, 12, aad, 16, tag, 16);
    }
    auto end = high_resolution_clock::now();
    double elapsed = duration_cast<microseconds>(end - start).count() / 1000000.0;
    double throughput = measure_throughput((size_t)iterations * data_size, elapsed);
    printf("  %-20s: %8.2f MB/s  (%zu MB in %.3fs)\n",
           name, throughput, (size_t)iterations * data_size / 1024 / 1024, elapsed);
    delete[] pt; delete[] ct;
}

void bench_gift_blocks(const char* name, GIFT* gift, size_t data_size) {
    size_t num_blocks = data_size / 16;
    uint8_t* pt = new uint8_t[data_size];
    uint8_t* ct = new uint8_t[data_size];
    memset(pt, 0xAB, data_size);
    for (int i = 0; i < 100; i++) gift->encrypt_block(pt, ct);
    auto start = high_resolution_clock::now();
    int iterations = std::max(100, (int)(1048576 / data_size));
    for (int iter = 0; iter < iterations; iter++) {
        for (size_t i = 0; i < num_blocks; i++) {
            gift->encrypt_block(pt + 16*i, ct + 16*i);
        }
    }
    auto end = high_resolution_clock::now();
    double elapsed = duration_cast<microseconds>(end - start).count() / 1000000.0;
    double throughput = measure_throughput((size_t)iterations * data_size, elapsed);
    printf("  %-20s: %8.2f MB/s  (%zu MB in %.3fs)\n",
           name, throughput, (size_t)iterations * data_size / 1024 / 1024, elapsed);
    delete[] pt; delete[] ct;
}

void bench_gift_ctr(const char* name, GIFT* gift, size_t data_size) {
    uint8_t iv[16]; memset(iv, 0xCC, 16);
    uint8_t* pt = new uint8_t[data_size];
    uint8_t* ct = new uint8_t[data_size];
    memset(pt, 0xAB, data_size);
    gift_ctr_encrypt(gift, pt, ct, iv, 16, data_size);
    auto start = high_resolution_clock::now();
    int iterations = std::max(50, (int)(10485760 / data_size));
    for (int iter = 0; iter < iterations; iter++) {
        gift_ctr_encrypt(gift, pt, ct, iv, 16, data_size);
    }
    auto end = high_resolution_clock::now();
    double elapsed = duration_cast<microseconds>(end - start).count() / 1000000.0;
    double throughput = measure_throughput((size_t)iterations * data_size, elapsed);
    printf("  %-20s: %8.2f MB/s  (%zu MB in %.3fs)\n",
           name, throughput, (size_t)iterations * data_size / 1024 / 1024, elapsed);
    delete[] pt; delete[] ct;
}

void bench_gift_gcm(const char* name, GIFT* gift, size_t data_size) {
    uint8_t iv[12]; memset(iv, 0xDD, 12);
    uint8_t* pt = new uint8_t[data_size];
    uint8_t* ct = new uint8_t[data_size];
    uint8_t tag[16]; uint8_t aad[16];
    memset(pt, 0xAB, data_size); memset(aad, 0xEE, 16);
    gift_gcm_encrypt(gift, pt, ct, data_size, iv, 12, aad, 16, tag, 16);
    auto start = high_resolution_clock::now();
    int iterations = std::max(20, (int)(10485760 / data_size));
    for (int iter = 0; iter < iterations; iter++) {
        gift_gcm_encrypt(gift, pt, ct, data_size, iv, 12, aad, 16, tag, 16);
    }
    auto end = high_resolution_clock::now();
    double elapsed = duration_cast<microseconds>(end - start).count() / 1000000.0;
    double throughput = measure_throughput((size_t)iterations * data_size, elapsed);
    printf("  %-20s: %8.2f MB/s  (%zu MB in %.3fs)\n",
           name, throughput, (size_t)iterations * data_size / 1024 / 1024, elapsed);
    delete[] pt; delete[] ct;
}

void bench_twine_blocks(const char* name, TWINE* twine, size_t data_size) {
    size_t num_blocks = data_size / 8;
    uint8_t* pt = new uint8_t[data_size];
    uint8_t* ct = new uint8_t[data_size];
    memset(pt, 0xAB, data_size);
    for (int i = 0; i < 100; i++) twine->encrypt_block(pt, ct);
    auto start = high_resolution_clock::now();
    int iterations = std::max(100, (int)(1048576 / data_size));
    for (int iter = 0; iter < iterations; iter++) {
        for (size_t i = 0; i < num_blocks; i++) {
            twine->encrypt_block(pt + 8*i, ct + 8*i);
        }
    }
    auto end = high_resolution_clock::now();
    double elapsed = duration_cast<microseconds>(end - start).count() / 1000000.0;
    double throughput = measure_throughput((size_t)iterations * data_size, elapsed);
    printf("  %-20s: %8.2f MB/s  (%zu MB in %.3fs)\n",
           name, throughput, (size_t)iterations * data_size / 1024 / 1024, elapsed);
    delete[] pt; delete[] ct;
}

void bench_twine_ctr(const char* name, TWINE* twine, size_t data_size) {
    uint8_t iv[16]; memset(iv, 0xCC, 16);
    uint8_t* pt = new uint8_t[data_size];
    uint8_t* ct = new uint8_t[data_size];
    memset(pt, 0xAB, data_size);
    twine_ctr_encrypt(twine, pt, ct, iv, 16, data_size);
    auto start = high_resolution_clock::now();
    int iterations = std::max(50, (int)(10485760 / data_size));
    for (int iter = 0; iter < iterations; iter++) {
        twine_ctr_encrypt(twine, pt, ct, iv, 16, data_size);
    }
    auto end = high_resolution_clock::now();
    double elapsed = duration_cast<microseconds>(end - start).count() / 1000000.0;
    double throughput = measure_throughput((size_t)iterations * data_size, elapsed);
    printf("  %-20s: %8.2f MB/s  (%zu MB in %.3fs)\n",
           name, throughput, (size_t)iterations * data_size / 1024 / 1024, elapsed);
    delete[] pt; delete[] ct;
}

void bench_twine_gcm(const char* name, TWINE* twine, size_t data_size) {
    uint8_t iv[12]; memset(iv, 0xDD, 12);
    uint8_t* pt = new uint8_t[data_size];
    uint8_t* ct = new uint8_t[data_size];
    uint8_t tag[16]; uint8_t aad[16];
    memset(pt, 0xAB, data_size); memset(aad, 0xEE, 16);
    twine_gcm_encrypt(twine, pt, ct, data_size, iv, 12, aad, 16, tag, 16);
    auto start = high_resolution_clock::now();
    int iterations = std::max(20, (int)(10485760 / data_size));
    for (int iter = 0; iter < iterations; iter++) {
        twine_gcm_encrypt(twine, pt, ct, data_size, iv, 12, aad, 16, tag, 16);
    }
    auto end = high_resolution_clock::now();
    double elapsed = duration_cast<microseconds>(end - start).count() / 1000000.0;
    double throughput = measure_throughput((size_t)iterations * data_size, elapsed);
    printf("  %-20s: %8.2f MB/s  (%zu MB in %.3fs)\n",
           name, throughput, (size_t)iterations * data_size / 1024 / 1024, elapsed);
    delete[] pt; delete[] ct;
}

// ===== XTS Mode Benchmarks =====

void bench_aes_xts(const char* name, AES* aes1, AES* aes2, size_t data_size) {
    uint8_t* pt = new uint8_t[data_size];
    uint8_t* ct = new uint8_t[data_size];
    memset(pt, 0xAB, data_size);
    aes_xts_encrypt(aes1, aes2, pt, ct, data_size, 0);
    auto start = high_resolution_clock::now();
    int iterations = std::max(20, (int)(10485760 / data_size));
    for (int iter = 0; iter < iterations; iter++) {
        aes_xts_encrypt(aes1, aes2, pt, ct, data_size, 0);
    }
    auto end = high_resolution_clock::now();
    double elapsed = duration_cast<microseconds>(end - start).count() / 1000000.0;
    double throughput = measure_throughput((size_t)iterations * data_size, elapsed);
    printf("  %-20s: %8.2f MB/s  (%zu MB in %.3fs)\n",
           name, throughput, (size_t)iterations * data_size / 1024 / 1024, elapsed);
    delete[] pt; delete[] ct;
}

void bench_sm4_xts(const char* name, SM4* sm4_1, SM4* sm4_2, size_t data_size) {
    uint8_t* pt = new uint8_t[data_size];
    uint8_t* ct = new uint8_t[data_size];
    memset(pt, 0xAB, data_size);
    sm4_xts_encrypt(sm4_1, sm4_2, pt, ct, data_size, 0);
    auto start = high_resolution_clock::now();
    int iterations = std::max(20, (int)(10485760 / data_size));
    for (int iter = 0; iter < iterations; iter++) {
        sm4_xts_encrypt(sm4_1, sm4_2, pt, ct, data_size, 0);
    }
    auto end = high_resolution_clock::now();
    double elapsed = duration_cast<microseconds>(end - start).count() / 1000000.0;
    double throughput = measure_throughput((size_t)iterations * data_size, elapsed);
    printf("  %-20s: %8.2f MB/s  (%zu MB in %.3fs)\n",
           name, throughput, (size_t)iterations * data_size / 1024 / 1024, elapsed);
    delete[] pt; delete[] ct;
}

void bench_gift_xts(const char* name, GIFT* gift1, GIFT* gift2, size_t data_size) {
    uint8_t* pt = new uint8_t[data_size];
    uint8_t* ct = new uint8_t[data_size];
    memset(pt, 0xAB, data_size);
    gift_xts_encrypt(gift1, gift2, pt, ct, data_size, 0);
    auto start = high_resolution_clock::now();
    int iterations = std::max(20, (int)(10485760 / data_size));
    for (int iter = 0; iter < iterations; iter++) {
        gift_xts_encrypt(gift1, gift2, pt, ct, data_size, 0);
    }
    auto end = high_resolution_clock::now();
    double elapsed = duration_cast<microseconds>(end - start).count() / 1000000.0;
    double throughput = measure_throughput((size_t)iterations * data_size, elapsed);
    printf("  %-20s: %8.2f MB/s  (%zu MB in %.3fs)\n",
           name, throughput, (size_t)iterations * data_size / 1024 / 1024, elapsed);
    delete[] pt; delete[] ct;
}

void bench_twine_xts(const char* name, TWINE* twine1, TWINE* twine2, size_t data_size) {
    uint8_t* pt = new uint8_t[data_size];
    uint8_t* ct = new uint8_t[data_size];
    memset(pt, 0xAB, data_size);
    twine_xts_encrypt(twine1, twine2, pt, ct, data_size, 0);
    auto start = high_resolution_clock::now();
    int iterations = std::max(20, (int)(10485760 / data_size));
    for (int iter = 0; iter < iterations; iter++) {
        twine_xts_encrypt(twine1, twine2, pt, ct, data_size, 0);
    }
    auto end = high_resolution_clock::now();
    double elapsed = duration_cast<microseconds>(end - start).count() / 1000000.0;
    double throughput = measure_throughput((size_t)iterations * data_size, elapsed);
    printf("  %-20s: %8.2f MB/s  (%zu MB in %.3fs)\n",
           name, throughput, (size_t)iterations * data_size / 1024 / 1024, elapsed);
    delete[] pt; delete[] ct;
}

int main() {
    printf("============================================\n");
    printf("  Multi-Algorithm Performance Benchmark\n");
    printf("  AES / SM4 / GIFT / TWINE\n");
    printf("  Data sizes: 1KB / 64KB / 1MB\n");
    printf("============================================\n\n");

    size_t sizes[] = {1024, 65536, 1048576};
    const char* size_names[] = {"1 KB", "64 KB", "1 MB"};

    const uint8_t key128[16] = {0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,
                                0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10};
    const uint8_t key192[24] = {0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,
                                0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10,
                                0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88};
    const uint8_t key256[32] = {0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,
                                0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10,
                                0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,
                                0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff,0x00};
    // Second key for XTS (tweak key)
    const uint8_t key128_2[16] = {0x10,0x32,0x54,0x76,0x98,0xba,0xdc,0xfe,
                                  0xef,0xcd,0xab,0x89,0x67,0x45,0x23,0x01};
    const uint8_t key192_2[24] = {0x10,0x32,0x54,0x76,0x98,0xba,0xdc,0xfe,
                                  0xef,0xcd,0xab,0x89,0x67,0x45,0x23,0x01,
                                  0xaa,0xbb,0xcc,0xdd,0xee,0xff,0x00,0x11};
    const uint8_t key256_2[32] = {0x10,0x32,0x54,0x76,0x98,0xba,0xdc,0xfe,
                                  0xef,0xcd,0xab,0x89,0x67,0x45,0x23,0x01,
                                  0xaa,0xbb,0xcc,0xdd,0xee,0xff,0x00,0x11,
                                  0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99};

    // --- AES-128 Benchmarks ---
    printf("=== AES-128 Block Encryption Throughput ===\n");
    for (int s = 0; s < 3; s++) {
        printf("\n[Data size: %s]\n", size_names[s]);
        AES* aes_tt = AES::create(AESImpl::TTABLE);
        aes_tt->set_key(key128, 16);
        bench_aes_blocks("AES T-table", aes_tt, sizes[s]);
        delete aes_tt;
        AES* aes_ni = AES::create(AESImpl::AESNI);
        aes_ni->set_key(key128, 16);
        bench_aes_blocks("AES AES-NI", aes_ni, sizes[s]);
        delete aes_ni;
    }

    printf("\n=== AES-128 CTR Mode Throughput ===\n");
    for (int s = 0; s < 3; s++) {
        printf("\n[Data size: %s]\n", size_names[s]);
        AES* aes_tt = AES::create(AESImpl::TTABLE);
        aes_tt->set_key(key128, 16);
        bench_aes_ctr("CTR T-table", aes_tt, sizes[s]);
        delete aes_tt;
        AES* aes_ni = AES::create(AESImpl::AESNI);
        aes_ni->set_key(key128, 16);
        bench_aes_ctr("CTR AES-NI", aes_ni, sizes[s]);
        delete aes_ni;
    }

    printf("\n=== AES-128 GCM Mode Throughput ===\n");
    for (int s = 0; s < 3; s++) {
        printf("\n[Data size: %s]\n", size_names[s]);
        AES* aes_tt = AES::create(AESImpl::TTABLE);
        aes_tt->set_key(key128, 16);
        bench_aes_gcm("GCM T-table", aes_tt, sizes[s]);
        delete aes_tt;
        AES* aes_ni = AES::create(AESImpl::AESNI);
        aes_ni->set_key(key128, 16);
        bench_aes_gcm("GCM AES-NI", aes_ni, sizes[s]);
        delete aes_ni;
    }

    // --- AES-192 Benchmarks ---
    printf("\n=== AES-192 Block Encryption Throughput ===\n");
    for (int s = 0; s < 3; s++) {
        printf("\n[Data size: %s]\n", size_names[s]);
        AES* aes_tt = AES::create(AESImpl::TTABLE);
        aes_tt->set_key(key192, 24);
        bench_aes_blocks("AES T-table", aes_tt, sizes[s]);
        delete aes_tt;
        AES* aes_ni = AES::create(AESImpl::AESNI);
        aes_ni->set_key(key192, 24);
        bench_aes_blocks("AES AES-NI", aes_ni, sizes[s]);
        delete aes_ni;
    }

    printf("\n=== AES-192 CTR Mode Throughput ===\n");
    for (int s = 0; s < 3; s++) {
        printf("\n[Data size: %s]\n", size_names[s]);
        AES* aes_tt = AES::create(AESImpl::TTABLE);
        aes_tt->set_key(key192, 24);
        bench_aes_ctr("CTR T-table", aes_tt, sizes[s]);
        delete aes_tt;
        AES* aes_ni = AES::create(AESImpl::AESNI);
        aes_ni->set_key(key192, 24);
        bench_aes_ctr("CTR AES-NI", aes_ni, sizes[s]);
        delete aes_ni;
    }

    printf("\n=== AES-192 GCM Mode Throughput ===\n");
    for (int s = 0; s < 3; s++) {
        printf("\n[Data size: %s]\n", size_names[s]);
        AES* aes_tt = AES::create(AESImpl::TTABLE);
        aes_tt->set_key(key192, 24);
        bench_aes_gcm("GCM T-table", aes_tt, sizes[s]);
        delete aes_tt;
        AES* aes_ni = AES::create(AESImpl::AESNI);
        aes_ni->set_key(key192, 24);
        bench_aes_gcm("GCM AES-NI", aes_ni, sizes[s]);
        delete aes_ni;
    }

    // --- AES-256 Benchmarks ---
    printf("\n=== AES-256 Block Encryption Throughput ===\n");
    for (int s = 0; s < 3; s++) {
        printf("\n[Data size: %s]\n", size_names[s]);
        AES* aes_tt = AES::create(AESImpl::TTABLE);
        aes_tt->set_key(key256, 32);
        bench_aes_blocks("AES T-table", aes_tt, sizes[s]);
        delete aes_tt;
        AES* aes_ni = AES::create(AESImpl::AESNI);
        aes_ni->set_key(key256, 32);
        bench_aes_blocks("AES AES-NI", aes_ni, sizes[s]);
        delete aes_ni;
    }

    printf("\n=== AES-256 CTR Mode Throughput ===\n");
    for (int s = 0; s < 3; s++) {
        printf("\n[Data size: %s]\n", size_names[s]);
        AES* aes_tt = AES::create(AESImpl::TTABLE);
        aes_tt->set_key(key256, 32);
        bench_aes_ctr("CTR T-table", aes_tt, sizes[s]);
        delete aes_tt;
        AES* aes_ni = AES::create(AESImpl::AESNI);
        aes_ni->set_key(key256, 32);
        bench_aes_ctr("CTR AES-NI", aes_ni, sizes[s]);
        delete aes_ni;
    }

    printf("\n=== AES-256 GCM Mode Throughput ===\n");
    for (int s = 0; s < 3; s++) {
        printf("\n[Data size: %s]\n", size_names[s]);
        AES* aes_tt = AES::create(AESImpl::TTABLE);
        aes_tt->set_key(key256, 32);
        bench_aes_gcm("GCM T-table", aes_tt, sizes[s]);
        delete aes_tt;
        AES* aes_ni = AES::create(AESImpl::AESNI);
        aes_ni->set_key(key256, 32);
        bench_aes_gcm("GCM AES-NI", aes_ni, sizes[s]);
        delete aes_ni;
    }

    printf("\n=== SM4-128 Block Encryption Throughput ===\n");
    for (int s = 0; s < 3; s++) {
        printf("\n[Data size: %s]\n", size_names[s]);
        SM4* sm4_base = SM4::create(SM4Impl::BASIC);
        sm4_base->set_key(key128);
        bench_sm4_blocks("SM4 Basic", sm4_base, sizes[s]);
        delete sm4_base;
        SM4* sm4_tt = SM4::create(SM4Impl::TTABLE);
        sm4_tt->set_key(key128);
        bench_sm4_blocks("SM4 T-table", sm4_tt, sizes[s]);
        delete sm4_tt;
        SM4* sm4_sh = SM4::create(SM4Impl::SHUFFLE);
        sm4_sh->set_key(key128);
        bench_sm4_blocks("SM4 Shuffle", sm4_sh, sizes[s]);
        delete sm4_sh;
    }

    printf("\n=== SM4-128 CTR Mode Throughput ===\n");
    for (int s = 0; s < 3; s++) {
        printf("\n[Data size: %s]\n", size_names[s]);
        SM4* sm4_base = SM4::create(SM4Impl::BASIC);
        sm4_base->set_key(key128);
        bench_sm4_ctr("CTR Basic", sm4_base, sizes[s]);
        delete sm4_base;
        SM4* sm4_tt = SM4::create(SM4Impl::TTABLE);
        sm4_tt->set_key(key128);
        bench_sm4_ctr("CTR T-table", sm4_tt, sizes[s]);
        delete sm4_tt;
        SM4* sm4_sh = SM4::create(SM4Impl::SHUFFLE);
        sm4_sh->set_key(key128);
        bench_sm4_ctr("CTR Shuffle", sm4_sh, sizes[s]);
        delete sm4_sh;
    }

    printf("\n=== SM4-128 GCM Mode Throughput ===\n");
    for (int s = 0; s < 3; s++) {
        printf("\n[Data size: %s]\n", size_names[s]);
        SM4* sm4_base = SM4::create(SM4Impl::BASIC);
        sm4_base->set_key(key128);
        bench_sm4_gcm("GCM Basic", sm4_base, sizes[s]);
        delete sm4_base;
        SM4* sm4_tt = SM4::create(SM4Impl::TTABLE);
        sm4_tt->set_key(key128);
        bench_sm4_gcm("GCM T-table", sm4_tt, sizes[s]);
        delete sm4_tt;
        SM4* sm4_sh = SM4::create(SM4Impl::SHUFFLE);
        sm4_sh->set_key(key128);
        bench_sm4_gcm("GCM Shuffle", sm4_sh, sizes[s]);
        delete sm4_sh;
    }

    printf("\n=== GIFT-128 Block Encryption Throughput ===\n");
    for (int s = 0; s < 3; s++) {
        printf("\n[Data size: %s]\n", size_names[s]);
        GIFT* gift_base = GIFT::create(GIFTImpl::BASIC);
        gift_base->set_key(key128);
        bench_gift_blocks("GIFT Basic", gift_base, sizes[s]);
        delete gift_base;
        GIFT* gift_bs = GIFT::create(GIFTImpl::BITSLICE);
        gift_bs->set_key(key128);
        bench_gift_blocks("GIFT Bitslice", gift_bs, sizes[s]);
        delete gift_bs;
        GIFT* gift_sh = GIFT::create(GIFTImpl::SHUFFLE);
        gift_sh->set_key(key128);
        bench_gift_blocks("GIFT Shuffle", gift_sh, sizes[s]);
        delete gift_sh;
    }

    printf("\n=== GIFT-128 CTR Mode Throughput ===\n");
    for (int s = 0; s < 3; s++) {
        printf("\n[Data size: %s]\n", size_names[s]);
        GIFT* gift_base = GIFT::create(GIFTImpl::BASIC);
        gift_base->set_key(key128);
        bench_gift_ctr("CTR Basic", gift_base, sizes[s]);
        delete gift_base;
        GIFT* gift_bs = GIFT::create(GIFTImpl::BITSLICE);
        gift_bs->set_key(key128);
        bench_gift_ctr("CTR Bitslice", gift_bs, sizes[s]);
        delete gift_bs;
        GIFT* gift_sh = GIFT::create(GIFTImpl::SHUFFLE);
        gift_sh->set_key(key128);
        bench_gift_ctr("CTR Shuffle", gift_sh, sizes[s]);
        delete gift_sh;
    }

    printf("\n=== GIFT-128 GCM Mode Throughput ===\n");
    for (int s = 0; s < 3; s++) {
        printf("\n[Data size: %s]\n", size_names[s]);
        GIFT* gift_base = GIFT::create(GIFTImpl::BASIC);
        gift_base->set_key(key128);
        bench_gift_gcm("GCM Basic", gift_base, sizes[s]);
        delete gift_base;
        GIFT* gift_bs = GIFT::create(GIFTImpl::BITSLICE);
        gift_bs->set_key(key128);
        bench_gift_gcm("GCM Bitslice", gift_bs, sizes[s]);
        delete gift_bs;
        GIFT* gift_sh = GIFT::create(GIFTImpl::SHUFFLE);
        gift_sh->set_key(key128);
        bench_gift_gcm("GCM Shuffle", gift_sh, sizes[s]);
        delete gift_sh;
    }

    printf("\n=== TWINE-128 Block Encryption Throughput ===\n");
    for (int s = 0; s < 3; s++) {
        printf("\n[Data size: %s]\n", size_names[s]);
        TWINE* twine_base = TWINE::create(TWINEImpl::BASIC);
        twine_base->set_key(key128, 16);
        bench_twine_blocks("TWINE Basic", twine_base, sizes[s]);
        delete twine_base;
        TWINE* twine_tt = TWINE::create(TWINEImpl::TTABLE);
        twine_tt->set_key(key128, 16);
        bench_twine_blocks("TWINE T-table", twine_tt, sizes[s]);
        delete twine_tt;
        TWINE* twine_sh = TWINE::create(TWINEImpl::SHUFFLE);
        twine_sh->set_key(key128, 16);
        bench_twine_blocks("TWINE Shuffle", twine_sh, sizes[s]);
        delete twine_sh;
    }

    printf("\n=== TWINE-128 CTR Mode Throughput ===\n");
    for (int s = 0; s < 3; s++) {
        printf("\n[Data size: %s]\n", size_names[s]);
        TWINE* twine_base = TWINE::create(TWINEImpl::BASIC);
        twine_base->set_key(key128, 16);
        bench_twine_ctr("CTR Basic", twine_base, sizes[s]);
        delete twine_base;
        TWINE* twine_tt = TWINE::create(TWINEImpl::TTABLE);
        twine_tt->set_key(key128, 16);
        bench_twine_ctr("CTR T-table", twine_tt, sizes[s]);
        delete twine_tt;
        TWINE* twine_sh = TWINE::create(TWINEImpl::SHUFFLE);
        twine_sh->set_key(key128, 16);
        bench_twine_ctr("CTR Shuffle", twine_sh, sizes[s]);
        delete twine_sh;
    }

    printf("\n=== TWINE-128 GCM Mode Throughput ===\n");
    for (int s = 0; s < 3; s++) {
        printf("\n[Data size: %s]\n", size_names[s]);
        TWINE* twine_base = TWINE::create(TWINEImpl::BASIC);
        twine_base->set_key(key128, 16);
        bench_twine_gcm("GCM Basic", twine_base, sizes[s]);
        delete twine_base;
        TWINE* twine_tt = TWINE::create(TWINEImpl::TTABLE);
        twine_tt->set_key(key128, 16);
        bench_twine_gcm("GCM T-table", twine_tt, sizes[s]);
        delete twine_tt;
        TWINE* twine_sh = TWINE::create(TWINEImpl::SHUFFLE);
        twine_sh->set_key(key128, 16);
        bench_twine_gcm("GCM Shuffle", twine_sh, sizes[s]);
        delete twine_sh;
    }

    // ==================== XTS Mode Benchmarks ====================

    // --- AES-128 XTS ---
    printf("\n=== AES-128 XTS Mode Throughput ===\n");
    for (int s = 0; s < 3; s++) {
        printf("\n[Data size: %s]\n", size_names[s]);
        AES* aes_tt1 = AES::create(AESImpl::TTABLE);
        AES* aes_tt2 = AES::create(AESImpl::TTABLE);
        aes_tt1->set_key(key128, 16); aes_tt2->set_key(key128_2, 16);
        bench_aes_xts("XTS T-table", aes_tt1, aes_tt2, sizes[s]);
        delete aes_tt1; delete aes_tt2;
        AES* aes_ni1 = AES::create(AESImpl::AESNI);
        AES* aes_ni2 = AES::create(AESImpl::AESNI);
        aes_ni1->set_key(key128, 16); aes_ni2->set_key(key128_2, 16);
        bench_aes_xts("XTS AES-NI", aes_ni1, aes_ni2, sizes[s]);
        delete aes_ni1; delete aes_ni2;
    }

    // --- AES-192 XTS ---
    printf("\n=== AES-192 XTS Mode Throughput ===\n");
    for (int s = 0; s < 3; s++) {
        printf("\n[Data size: %s]\n", size_names[s]);
        AES* aes_tt1 = AES::create(AESImpl::TTABLE);
        AES* aes_tt2 = AES::create(AESImpl::TTABLE);
        aes_tt1->set_key(key192, 24); aes_tt2->set_key(key192_2, 24);
        bench_aes_xts("XTS T-table", aes_tt1, aes_tt2, sizes[s]);
        delete aes_tt1; delete aes_tt2;
        AES* aes_ni1 = AES::create(AESImpl::AESNI);
        AES* aes_ni2 = AES::create(AESImpl::AESNI);
        aes_ni1->set_key(key192, 24); aes_ni2->set_key(key192_2, 24);
        bench_aes_xts("XTS AES-NI", aes_ni1, aes_ni2, sizes[s]);
        delete aes_ni1; delete aes_ni2;
    }

    // --- AES-256 XTS ---
    printf("\n=== AES-256 XTS Mode Throughput ===\n");
    for (int s = 0; s < 3; s++) {
        printf("\n[Data size: %s]\n", size_names[s]);
        AES* aes_tt1 = AES::create(AESImpl::TTABLE);
        AES* aes_tt2 = AES::create(AESImpl::TTABLE);
        aes_tt1->set_key(key256, 32); aes_tt2->set_key(key256_2, 32);
        bench_aes_xts("XTS T-table", aes_tt1, aes_tt2, sizes[s]);
        delete aes_tt1; delete aes_tt2;
        AES* aes_ni1 = AES::create(AESImpl::AESNI);
        AES* aes_ni2 = AES::create(AESImpl::AESNI);
        aes_ni1->set_key(key256, 32); aes_ni2->set_key(key256_2, 32);
        bench_aes_xts("XTS AES-NI", aes_ni1, aes_ni2, sizes[s]);
        delete aes_ni1; delete aes_ni2;
    }

    // --- SM4 XTS ---
    printf("\n=== SM4-128 XTS Mode Throughput ===\n");
    for (int s = 0; s < 3; s++) {
        printf("\n[Data size: %s]\n", size_names[s]);
        SM4* sm4_1 = SM4::create(SM4Impl::BASIC);
        SM4* sm4_2 = SM4::create(SM4Impl::BASIC);
        sm4_1->set_key(key128); sm4_2->set_key(key128_2);
        bench_sm4_xts("XTS Basic", sm4_1, sm4_2, sizes[s]);
        delete sm4_1; delete sm4_2;
        SM4* sm4_tt1 = SM4::create(SM4Impl::TTABLE);
        SM4* sm4_tt2 = SM4::create(SM4Impl::TTABLE);
        sm4_tt1->set_key(key128); sm4_tt2->set_key(key128_2);
        bench_sm4_xts("XTS T-table", sm4_tt1, sm4_tt2, sizes[s]);
        delete sm4_tt1; delete sm4_tt2;
        SM4* sm4_sh1 = SM4::create(SM4Impl::SHUFFLE);
        SM4* sm4_sh2 = SM4::create(SM4Impl::SHUFFLE);
        sm4_sh1->set_key(key128); sm4_sh2->set_key(key128_2);
        bench_sm4_xts("XTS Shuffle", sm4_sh1, sm4_sh2, sizes[s]);
        delete sm4_sh1; delete sm4_sh2;
    }

    // --- GIFT XTS ---
    printf("\n=== GIFT-128 XTS Mode Throughput ===\n");
    for (int s = 0; s < 3; s++) {
        printf("\n[Data size: %s]\n", size_names[s]);
        GIFT* gift_1 = GIFT::create(GIFTImpl::BASIC);
        GIFT* gift_2 = GIFT::create(GIFTImpl::BASIC);
        gift_1->set_key(key128); gift_2->set_key(key128_2);
        bench_gift_xts("XTS Basic", gift_1, gift_2, sizes[s]);
        delete gift_1; delete gift_2;
        GIFT* gift_bs1 = GIFT::create(GIFTImpl::BITSLICE);
        GIFT* gift_bs2 = GIFT::create(GIFTImpl::BITSLICE);
        gift_bs1->set_key(key128); gift_bs2->set_key(key128_2);
        bench_gift_xts("XTS Bitslice", gift_bs1, gift_bs2, sizes[s]);
        delete gift_bs1; delete gift_bs2;
        GIFT* gift_sh1 = GIFT::create(GIFTImpl::SHUFFLE);
        GIFT* gift_sh2 = GIFT::create(GIFTImpl::SHUFFLE);
        gift_sh1->set_key(key128); gift_sh2->set_key(key128_2);
        bench_gift_xts("XTS Shuffle", gift_sh1, gift_sh2, sizes[s]);
        delete gift_sh1; delete gift_sh2;
    }

    // --- TWINE XTS ---
    printf("\n=== TWINE-128 XTS Mode Throughput ===\n");
    for (int s = 0; s < 3; s++) {
        printf("\n[Data size: %s]\n", size_names[s]);
        TWINE* twine_1 = TWINE::create(TWINEImpl::BASIC);
        TWINE* twine_2 = TWINE::create(TWINEImpl::BASIC);
        twine_1->set_key(key128, 16); twine_2->set_key(key128_2, 16);
        bench_twine_xts("XTS Basic", twine_1, twine_2, sizes[s]);
        delete twine_1; delete twine_2;
        TWINE* twine_tt1 = TWINE::create(TWINEImpl::TTABLE);
        TWINE* twine_tt2 = TWINE::create(TWINEImpl::TTABLE);
        twine_tt1->set_key(key128, 16); twine_tt2->set_key(key128_2, 16);
        bench_twine_xts("XTS T-table", twine_tt1, twine_tt2, sizes[s]);
        delete twine_tt1; delete twine_tt2;
        TWINE* twine_sh1 = TWINE::create(TWINEImpl::SHUFFLE);
        TWINE* twine_sh2 = TWINE::create(TWINEImpl::SHUFFLE);
        twine_sh1->set_key(key128, 16); twine_sh2->set_key(key128_2, 16);
        bench_twine_xts("XTS Shuffle", twine_sh1, twine_sh2, sizes[s]);
        delete twine_sh1; delete twine_sh2;
    }

    printf("\n============================================\n");
    printf("  Benchmark Complete\n");
    printf("============================================\n");

    return 0;
}
