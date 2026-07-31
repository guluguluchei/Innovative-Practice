#ifndef SM3_H
#define SM3_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* SM3 输出摘要长度 (256 bits) */
#define SM3_DIGEST_LENGTH  32

/* SM3 消息块大小 (512 bits) */
#define SM3_BLOCK_SIZE     64

/* SM3 状态和消息字数量 */
#define SM3_STATE_WORDS    8
#define SM3_MSG_WORDS      16
#define SM3_EXPANDED_WORDS 68

/*
 SM3 上下文结构体
 保存哈希计算的中间状态
 */
typedef struct {
    uint32_t state[SM3_STATE_WORDS];   /* 256位状态 */
    uint64_t total_bits;                /* 已处理的总比特数 */
    uint8_t  buffer[SM3_BLOCK_SIZE];   /* 未处理的输入缓冲区 */
    size_t   buf_len;                   /* 缓冲区中已有的字节数 */
} sm3_ctx_t;



void sm3_init(sm3_ctx_t *ctx);

void sm3_update(sm3_ctx_t *ctx, const uint8_t *data, size_t len);

void sm3_final(sm3_ctx_t *ctx, uint8_t digest[SM3_DIGEST_LENGTH]);

void sm3_hash(const uint8_t *data, size_t len,
              uint8_t digest[SM3_DIGEST_LENGTH]);

/* 8路并行哈希 */
void sm3_hash_x8(const uint8_t *data[8], size_t len,
                 uint8_t digest[8][SM3_DIGEST_LENGTH]);

/* 4路并行独立消息的SM3摘要 */
void sm3_hash_x4(const uint8_t *data[4], size_t len,
                 uint8_t digest[4][SM3_DIGEST_LENGTH]);

const char *sm3_impl_name(void);

#ifdef __cplusplus
}
#endif

#endif 
