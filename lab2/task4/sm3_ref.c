/*
  SM3密码杂凑算法参考实现

  算法概述：
    1. 消息填充：在消息末尾填充"1"、若干"0"以及64位长度值
    2. 消息扩展：将512位消息块扩展为132个32位字（W[0..67], W'[0..63]）
    3. 压缩函数：使用扩展消息字进行64轮迭代压缩
    4. 输出256位杂凑值
 */

#include "sm3.h"
#include <string.h>
#include <stdlib.h>

/* 32位循环左移 */
#define ROTL32(x, n) (((x) << (n)) | ((x) >> (32 - (n))))

static inline uint32_t FF(int j, uint32_t x, uint32_t y, uint32_t z)
{
    if (j < 16) {
        return x ^ y ^ z;
    } else {
        return (x & y) | (x & z) | (y & z);
    }
}

static inline uint32_t GG(int j, uint32_t x, uint32_t y, uint32_t z)
{
    if (j < 16) {
        return x ^ y ^ z;
    } else {
        return (x & y) | ((~x) & z);
    }
}

/* P_0(X) = X ⊕ (X <<< 9) ⊕ (X <<< 17) */
static inline uint32_t P0(uint32_t x)
{
    return x ^ ROTL32(x, 9) ^ ROTL32(x, 17);
}

/* P_1(X) = X ⊕ (X <<< 15) ⊕ (X <<< 23) */
static inline uint32_t P1(uint32_t x)
{
    return x ^ ROTL32(x, 15) ^ ROTL32(x, 23);
}

/* IV */
static const uint32_t SM3_IV[8] = {
    0x7380166F, 0x4914B2B9, 0x172442D7, 0xDA8A0600,
    0xA96F30BC, 0x163138AA, 0xE38DEE4D, 0xB0FB0E4E
};

/* 压缩函数 */
static void sm3_message_expansion(const uint32_t B[16], uint32_t W[68])
{
    int j;

    /* W[0..15] = B[0..15] */
    for (j = 0; j < 16; j++) {
        W[j] = B[j];
    }

    /* W[16..67] 扩展 */
    for (j = 16; j < 68; j++) {
        uint32_t tmp = W[j - 16] ^ W[j - 9] ^ ROTL32(W[j - 3], 15);
        W[j] = P1(tmp) ^ ROTL32(W[j - 13], 7) ^ W[j - 6];
    }
}

/* SM3压缩函数 */
static void sm3_compress(uint32_t V[8], const uint32_t B[16])
{
    uint32_t W[68];
    uint32_t A, B_j, C, D, E, F, G, H;
    uint32_t SS1, SS2, TT1, TT2;
    int j;

    /* 消息扩展 */
    sm3_message_expansion(B, W);

    A = V[0]; B_j = V[1]; C = V[2]; D = V[3];
    E = V[4]; F = V[5]; G = V[6]; H = V[7];

    for (j = 0; j < 64; j++) {
        uint32_t T_j;
        if (j < 16) {
            T_j = 0x79CC4519;
        } else {
            T_j = 0x7A879D8A;
        }

        /* SS1 = ((A <<< 12) + E + (T_j <<< (j mod 32))) <<< 7 */
        SS1 = ROTL32(A, 12) + E + ROTL32(T_j, j & 31);
        SS1 = ROTL32(SS1, 7);

        /* SS2 = SS1 ⊕ (A <<< 12) */
        SS2 = SS1 ^ ROTL32(A, 12);

        /* TT1 = FF_j(A,B,C) + D + SS2 + W'[j]  (W'[j] = W[j] ^ W[j+4]) */
        TT1 = FF(j, A, B_j, C) + D + SS2 + (W[j] ^ W[j + 4]);

        /* TT2 = GG_j(E,F,G) + H + SS1 + W[j] */
        TT2 = GG(j, E, F, G) + H + SS1 + W[j];

        /* 状态更新 */
        D = C;
        C = ROTL32(B_j, 9);
        B_j = A;
        A = TT1;
        H = G;
        G = ROTL32(F, 19);
        F = E;
        E = P0(TT2);
    }

    /* 输出: V^(i+1) = ABCDEFGH ⊕ V^(i) */
    V[0] ^= A;
    V[1] ^= B_j;
    V[2] ^= C;
    V[3] ^= D;
    V[4] ^= E;
    V[5] ^= F;
    V[6] ^= G;
    V[7] ^= H;
}

/* 内部块处理 */

/* 将缓冲区中的64字节转换为16个32位大端字 */
static void bytes_to_words(const uint8_t buf[64], uint32_t words[16])
{
    int i;
    for (i = 0; i < 16; i++) {
        words[i] = ((uint32_t)buf[i * 4 + 0] << 24) |
                   ((uint32_t)buf[i * 4 + 1] << 16) |
                   ((uint32_t)buf[i * 4 + 2] << 8)  |
                   ((uint32_t)buf[i * 4 + 3]);
    }
}

/* 将8个32位状态字转换为32字节大端输出 */
static void words_to_bytes(const uint32_t state[8], uint8_t digest[32])
{
    int i;
    for (i = 0; i < 8; i++) {
        digest[i * 4 + 0] = (uint8_t)(state[i] >> 24);
        digest[i * 4 + 1] = (uint8_t)(state[i] >> 16);
        digest[i * 4 + 2] = (uint8_t)(state[i] >> 8);
        digest[i * 4 + 3] = (uint8_t)(state[i]);
    }
}

void sm3_init(sm3_ctx_t *ctx)
{
    memcpy(ctx->state, SM3_IV, sizeof(SM3_IV));
    ctx->total_bits = 0;
    ctx->buf_len = 0;
    memset(ctx->buffer, 0, SM3_BLOCK_SIZE);
}

void sm3_update(sm3_ctx_t *ctx, const uint8_t *data, size_t len)
{
    size_t buf_len = ctx->buf_len;

    ctx->total_bits += (uint64_t)len * 8;

    if (buf_len > 0) {
        size_t fill = SM3_BLOCK_SIZE - buf_len;
        if (len < fill) {
            memcpy(ctx->buffer + buf_len, data, len);
            ctx->buf_len = buf_len + len;
            return;
        }
        memcpy(ctx->buffer + buf_len, data, fill);
        uint32_t B[16];
        bytes_to_words(ctx->buffer, B);
        sm3_compress(ctx->state, B);
        data += fill;
        len -= fill;
        ctx->buf_len = 0;
    }

    /* 处理完整块 */
    while (len >= SM3_BLOCK_SIZE) {
        uint32_t B[16];
        bytes_to_words(data, B);
        sm3_compress(ctx->state, B);
        data += SM3_BLOCK_SIZE;
        len -= SM3_BLOCK_SIZE;
    }

    /* 保存剩余数据 */
    if (len > 0) {
        memcpy(ctx->buffer, data, len);
        ctx->buf_len = len;
    }
}

void sm3_final(sm3_ctx_t *ctx, uint8_t digest[SM3_DIGEST_LENGTH])
{
    uint8_t pad[SM3_BLOCK_SIZE * 2];
    size_t pad_len;
    size_t buf_len = ctx->buf_len;
    uint64_t total_bits = ctx->total_bits;

    /* 计算填充后的长度 */
    pad_len = buf_len + 1;                     
    if (pad_len % SM3_BLOCK_SIZE > 56) {      
        pad_len += SM3_BLOCK_SIZE;             
    }
    pad_len = ((pad_len + SM3_BLOCK_SIZE - 1) / SM3_BLOCK_SIZE)
              * SM3_BLOCK_SIZE;

    memset(pad, 0, pad_len);
    memcpy(pad, ctx->buffer, buf_len);
    pad[buf_len] = 0x80;  /* 追加 bit 1 */

    /* 在最后8字节写入64位长度 */
    pad[pad_len - 8] = (uint8_t)(total_bits >> 56);
    pad[pad_len - 7] = (uint8_t)(total_bits >> 48);
    pad[pad_len - 6] = (uint8_t)(total_bits >> 40);
    pad[pad_len - 5] = (uint8_t)(total_bits >> 32);
    pad[pad_len - 4] = (uint8_t)(total_bits >> 24);
    pad[pad_len - 3] = (uint8_t)(total_bits >> 16);
    pad[pad_len - 2] = (uint8_t)(total_bits >> 8);
    pad[pad_len - 1] = (uint8_t)(total_bits);

    /* 逐块处理填充后的数据 */
    {
        size_t i;
        for (i = 0; i < pad_len; i += SM3_BLOCK_SIZE) {
            uint32_t B[16];
            bytes_to_words(pad + i, B);
            sm3_compress(ctx->state, B);
        }
    }

    /* 输出最终摘要 */
    words_to_bytes(ctx->state, digest);

    /* 清除上下文 */
    memset(ctx, 0, sizeof(*ctx));
}

void sm3_hash(const uint8_t *data, size_t len,
              uint8_t digest[SM3_DIGEST_LENGTH])
{
    sm3_ctx_t ctx;
    sm3_init(&ctx);
    sm3_update(&ctx, data, len);
    sm3_final(&ctx, digest);
}

const char *sm3_impl_name(void)
{
    return "SM3 Reference (Scalar / General-Purpose Registers)";
}
