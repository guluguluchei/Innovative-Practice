/*
  SM3实现正确性测试和性能基准
 
  测试内容：
    1. 标准测试向量验证
    2. 标量 vs AVX2 SIMD 交叉验证
    3. 性能对比测试
 */

#include "sm3.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

typedef struct {
    const char *desc;
    const char *input;   
    const char *expected; 
} test_vector_t;

static const test_vector_t TEST_VECTORS[] = {
    {
        "SM3(\"abc\")",
        "616263",
        "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0"
    },
    {
        "SM3(\"abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd\")",
        NULL, 
        "debe9ff92275b8a138604889c18e5a4d6fdb70e5387e5765293dcba39c0c5732"
    },
    {
        "SM3(empty message)",
        "",
        "1ab21d8355cfa17f8e61194831e81a8f22bec8c728fefb747ed035eb5082aa2b"
    },
    { NULL, NULL, NULL }
};

/* hex字符串转字节数组 */
static int hex_to_bytes(const char *hex, uint8_t *bytes, size_t max_len)
{
    size_t hex_len = strlen(hex);
    size_t byte_len = hex_len / 2;
    size_t i;

    if (byte_len > max_len) return -1;

    for (i = 0; i < byte_len; i++) {
        unsigned int val;
        sscanf(hex + i * 2, "%2x", &val);
        bytes[i] = (uint8_t)val;
    }
    return (int)byte_len;
}

/* 字节数组转hex字符串 */
static void bytes_to_hex(const uint8_t *bytes, size_t len, char *hex)
{
    size_t i;
    for (i = 0; i < len; i++) {
        sprintf(hex + i * 2, "%02x", bytes[i]);
    }
    hex[len * 2] = '\0';
}

/* 标准测试向量 */

static int test_vectors(void)
{
    int passed = 0, failed = 0;
    int i;

    printf("=== Test 1: Standard Test Vectors ===\n\n");

    for (i = 0; TEST_VECTORS[i].desc != NULL; i++) {
        uint8_t input[256];
        int input_len;
        uint8_t digest[SM3_DIGEST_LENGTH];
        char digest_hex[SM3_DIGEST_LENGTH * 2 + 1];

        if (TEST_VECTORS[i].input != NULL) {
            input_len = hex_to_bytes(TEST_VECTORS[i].input, input, sizeof(input));
        } else {
            int k;
            for (k = 0; k < 16; k++) {
                memcpy(input + k * 4, "abcd", 4);
            }
            input_len = 64;
        }

        sm3_hash(input, (size_t)input_len, digest);
        bytes_to_hex(digest, SM3_DIGEST_LENGTH, digest_hex);

        if (strcmp(digest_hex, TEST_VECTORS[i].expected) == 0) {
            printf("  [PASS] %s\n", TEST_VECTORS[i].desc);
            printf("         digest: %s\n", digest_hex);
            passed++;
        } else {
            printf("  [FAIL] %s\n", TEST_VECTORS[i].desc);
            printf("         expected: %s\n", TEST_VECTORS[i].expected);
            printf("         got:      %s\n", digest_hex);
            failed++;
        }
        printf("\n");
    }

    printf("  Result: %d passed, %d failed\n\n", passed, failed);
    return failed;
}

/* 标量 vs AVX2 交叉验证 */

static int test_cross_validation(void)
{
    int passed = 0, failed = 0;

    printf("===  Test 2: Cross-Validation ===\n\n");

    /* 生成8条相同消息，使用标量版本逐一计算，再使用AVX2 8路并行计算，验证二者结果一致 */
    {
        const char *msg = "SM3 hash algorithm SIMD optimization test. "
                          "Using AVX2 to process 8 messages in parallel.";
        size_t msg_len = strlen(msg);
        uint8_t ref_digest[SM3_DIGEST_LENGTH];
        const uint8_t *data_ptrs[8];
        uint8_t simd_digests[8][SM3_DIGEST_LENGTH];
        char ref_hex[65], simd_hex[65];
        int i;

        /* 标量参考值 */
        sm3_hash((const uint8_t *)msg, msg_len, ref_digest);
        bytes_to_hex(ref_digest, SM3_DIGEST_LENGTH, ref_hex);

        /* AVX2 8路并行 */
        for (i = 0; i < 8; i++) {
            data_ptrs[i] = (const uint8_t *)msg;
        }
        sm3_hash_x8(data_ptrs, msg_len, simd_digests);

        /* 验证所有8路输出一致 */
        for (i = 0; i < 8; i++) {
            bytes_to_hex(simd_digests[i], SM3_DIGEST_LENGTH, simd_hex);
            if (strcmp(ref_hex, simd_hex) == 0) {
                printf("  [PASS] Lane %d matches reference\n", i);
                passed++;
            } else {
                printf("  [FAIL] Lane %d mismatch!\n", i);
                printf("         ref:  %s\n", ref_hex);
                printf("         simd: %s\n", simd_hex);
                failed++;
            }
        }
    }

    /* 测试不同消息 */
    {
        /* 使用相同长度的不同消息 */
        const char *msgs[8] = {
            "Msg00: Hello SM3! 0123456789ABCDEF",
            "Msg01: SIMD Optimi 0123456789ABCDEF",
            "Msg02: AVX2 8-way! 0123456789ABCDEF",
            "Msg03: Crypto Hash. 0123456789ABCDEF",
            "Msg04: Nat Standard 0123456789ABCDEF",
            "Msg05: 256-bit dig 0123456789ABCDEF",
            "Msg06: MerkleDamgr 0123456789ABCDEF",
            "Msg07: Compress Fun 0123456789ABCDEF"
        };
        uint8_t ref_digests[8][SM3_DIGEST_LENGTH];
        const uint8_t *data_ptrs[8];
        uint8_t simd_digests[8][SM3_DIGEST_LENGTH];
        char ref_hex[65], simd_hex[65];
        int i;

        /* 标量计算所有8条消息 */
        for (i = 0; i < 8; i++) {
            sm3_hash((const uint8_t *)msgs[i], 32, ref_digests[i]);
        }

        /* AVX2 8路并行 */
        for (i = 0; i < 8; i++) {
            data_ptrs[i] = (const uint8_t *)msgs[i];
        }
        sm3_hash_x8(data_ptrs, 32, simd_digests);

        /* 逐个验证 */
        for (i = 0; i < 8; i++) {
            bytes_to_hex(ref_digests[i], SM3_DIGEST_LENGTH, ref_hex);
            bytes_to_hex(simd_digests[i], SM3_DIGEST_LENGTH, simd_hex);
            if (strcmp(ref_hex, simd_hex) == 0) {
                printf("  [PASS] Different messages - Lane %d matches\n", i);
                passed++;
            } else {
                printf("  [FAIL] Different messages - Lane %d mismatch!\n", i);
                printf("         ref:  %s\n", ref_hex);
                printf("         simd: %s\n", simd_hex);
                failed++;
            }
        }
    }

    printf("\n  Result: %d passed, %d failed\n\n", passed, failed);
    return failed;
}

/* 性能测试 */
static double get_time_us(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec * 1e6 + (double)ts.tv_nsec / 1e3;
}

static void performance_test(void)
{
    printf("===  Test 3: Performance Benchmark ===\n\n");

    /* 使用不同大小的消息进行性能测试 */
    const size_t msg_sizes[] = {
        64,       /* 1 block */
        1024,     /* 16 blocks */
        10240,    /* 160 blocks */
        102400    /* 1600 blocks */
    };
    const int iterations[] = { 10000, 1000, 100, 10 };
    int s;

    for (s = 0; s < 4; s++) {
        size_t msg_len = msg_sizes[s];
        int iters = iterations[s];
        uint8_t *msg = (uint8_t *)malloc(msg_len);
        uint8_t digest[SM3_DIGEST_LENGTH];
        double start, end, total_us;
        double mb_per_s;
        int i;

        /* 填充测试数据 */
        memset(msg, 0xAA, msg_len);

        /* 标量实现性能 */
        start = get_time_us();
        for (i = 0; i < iters; i++) {
            sm3_hash(msg, msg_len, digest);
        }
        end = get_time_us();
        total_us = end - start;
        mb_per_s = (double)(msg_len * iters) / (total_us / 1e6) / (1024.0 * 1024.0);

        printf("  [Scalar] %5lu bytes x %5d iterations: %10.2f us, "
               "%8.2f MB/s\n",
               (unsigned long)msg_len, iters, total_us, mb_per_s);

        /* AVX2 8路并行性能 */
        {
            const uint8_t *data_ptrs[8];
            uint8_t digests[8][SM3_DIGEST_LENGTH];

            for (i = 0; i < 8; i++) {
                data_ptrs[i] = msg;
            }

            start = get_time_us();
            for (i = 0; i < iters; i++) {
                sm3_hash_x8(data_ptrs, msg_len, digests);
            }
            end = get_time_us();
            total_us = end - start;

            mb_per_s = (double)(msg_len * iters * 8) /
                       (total_us / 1e6) / (1024.0 * 1024.0);

            printf("  [AVX2 ] %5lu bytes x %5d iterations: %10.2f us, "
                   "%8.2f MB/s (8-way)\n",
                   (unsigned long)msg_len, iters, total_us, mb_per_s);
        }

        free(msg);
        printf("\n");
    }
}

/* 增量API测试 */

static int test_incremental_api(void)
{
    int failed = 0;

    printf("===  Test 4: Incremental API Test ===\n\n");

    {
        const char *parts[] = { "abc", "def", "ghi", "jkl" };
        const char *full   = "abcdefghijkl";
        uint8_t inc_digest[SM3_DIGEST_LENGTH];
        uint8_t one_digest[SM3_DIGEST_LENGTH];
        char inc_hex[65], one_hex[65];
        sm3_ctx_t ctx;
        int i;

        /* 增量计算 */
        sm3_init(&ctx);
        for (i = 0; i < 4; i++) {
            sm3_update(&ctx, (const uint8_t *)parts[i],
                       strlen(parts[i]));
        }
        sm3_final(&ctx, inc_digest);

        /* 一次性计算 */
        sm3_hash((const uint8_t *)full, strlen(full), one_digest);

        bytes_to_hex(inc_digest, SM3_DIGEST_LENGTH, inc_hex);
        bytes_to_hex(one_digest, SM3_DIGEST_LENGTH, one_hex);

        if (strcmp(inc_hex, one_hex) == 0) {
            printf("  [PASS] Incremental API matches one-shot API\n");
            printf("         digest: %s\n", inc_hex);
        } else {
            printf("  [FAIL] Incremental API mismatch!\n");
            printf("         incremental: %s\n", inc_hex);
            printf("         one-shot:    %s\n", one_hex);
            failed++;
        }
    }

    printf("\n  Result: %d failed\n\n", failed);
    return failed;
}

int main(void)
{
    int total_failed = 0;

    total_failed += test_vectors();
    total_failed += test_incremental_api();
    total_failed += test_cross_validation();
    performance_test();

    if (total_failed == 0) {
        printf("ALL TESTS PASSED!\n");
    } else {
        printf("%d TEST(S) FAILED!\n", total_failed);
    }

    return total_failed > 0 ? 1 : 0;
}
