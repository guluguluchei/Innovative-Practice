/*
 本实现基于 ARM64 NEON 指令集，采用 SIMD寄存器和通用寄存器混合优化策略。

 混合策略说明：
     SIMD寄存器 (Q0-Q15):  处理4路并行的状态更新、布尔函数、加法等
     通用寄存器 (x0-x30):   消息扩展标量计算、内存寻址、循环迭代
     消息扩展策略: 使用标量代码逐消息进行扩展，
 */

#include "sm3.h"
#include <string.h>
#include <stdlib.h>

#ifdef __ARM_NEON

#include <arm_neon.h>

/* 32位标量循环左移 */
#define ROTL32(x, n) (((x) << (n)) | ((x) >> (32 - (n))))

/* 轮常量 */
static inline uint32_t get_Tj(int j)
{
    return (j < 16) ? 0x79CC4519 : 0x7A879D8A;
}

/*
 4路32位循环左移 (NEON)
 ARM NEON有左移和右移，组合实现旋转
 */
static inline uint32x4_t neon_rotl32(uint32x4_t x, int n)
{
    uint32x4_t left  = vshlq_n_u32(x, n);
    uint32x4_t right = vshrq_n_u32(x, 32 - n);
    return vorrq_u32(left, right);
}

/* P_0(X) = X ⊕ (X<<<9) ⊕ (X<<<17) */
static inline uint32x4_t neon_P0(uint32x4_t x)
{
    /* NEON寄存器 */
    uint32x4_t t1 = neon_rotl32(x, 9);   
    uint32x4_t t2 = neon_rotl32(x, 17);  
    return veorq_u32(veorq_u32(x, t1), t2);
}

/* P_1(X) = X ⊕ (X<<<15) ⊕ (X<<<23) */
static inline uint32x4_t neon_P1(uint32x4_t x)
{
    uint32x4_t t1 = neon_rotl32(x, 15);  
    uint32x4_t t2 = neon_rotl32(x, 23);  
    return veorq_u32(veorq_u32(x, t1), t2);
}

/* FF_j 布尔函数 */
static inline uint32x4_t neon_FF(int j, uint32x4_t x,
                                  uint32x4_t y, uint32x4_t z)
{
    if (j < 16) {
        /* FF = X ⊕ Y ⊕ Z */
        return veorq_u32(veorq_u32(x, y), z);
    } else {
        /* FF = (X∧Y) ∨ (X∧Z) ∨ (Y∧Z) */
        uint32x4_t xy = vandq_u32(x, y);
        uint32x4_t xz = vandq_u32(x, z);
        uint32x4_t yz = vandq_u32(y, z);
        return vorrq_u32(vorrq_u32(xy, xz), yz);
    }
}

/* GG_j 布尔函数 */
static inline uint32x4_t neon_GG(int j, uint32x4_t x,
                                  uint32x4_t y, uint32x4_t z)
{
    if (j < 16) {
        /* GG = X ⊕ Y ⊕ Z */
        return veorq_u32(veorq_u32(x, y), z);
    } else {
        /* GG = (X∧Y) ∨ (¬X∧Z) */
        uint32x4_t xy  = vandq_u32(x, y);
        uint32x4_t nxz = vbicq_u32(z, x);  /* Z AND NOT X */
        return vorrq_u32(xy, nxz);
    }
}

/* 4路并行消息扩展 */
static void sm3_expand_x4(const uint32_t msg_words[4][16],
                          uint32_t W_buf[4][68])
{
    int lane;  
    int j;    

    for (lane = 0; lane < 4; lane++) {
        uint32_t *W = W_buf[lane];  /* 基地址 */

        /* W[0..15] */
        for (j = 0; j < 16; j++) {
            W[j] = msg_words[lane][j];
        }

        /* W[16..67] 标量扩展 */
        for (j = 16; j < 68; j++) {
            uint32_t tmp = W[j - 16] ^ W[j - 9] ^ ROTL32(W[j - 3], 15);
            /* P_1(x) = x ^ (x<<<15) ^ (x<<<23) */
            uint32_t p1_val = tmp ^ ROTL32(tmp, 15) ^ ROTL32(tmp, 23);
            W[j] = p1_val ^ ROTL32(W[j - 13], 7) ^ W[j - 6];
        }
    }
}

/* 4路并行压缩函数 */
static void sm3_compress_x4(uint32x4_t q_V[8],
                            const uint32_t W_buf[4][68])
{
    uint32x4_t q_A, q_B, q_C, q_D;   
    uint32x4_t q_E, q_F, q_G, q_H;  
    uint32x4_t q_SS1, q_SS2, q_TT1, q_TT2;  
    uint32x4_t q_Tj, q_Wj, q_Wpj;     
    uint32x4_t q_A_rot12;            
    int j;

    /* 从内存加载4组初始状态到NEON Q寄存器 */
    q_A = q_V[0];  q_B = q_V[1];
    q_C = q_V[2];  q_D = q_V[3];
    q_E = q_V[4];  q_F = q_V[5];
    q_G = q_V[6];  q_H = q_V[7];

    for (j = 0; j < 64; j++) {
        /* A <<< 12 (4 lane同步) */
        q_A_rot12 = neon_rotl32(q_A, 12);

        /* 加载W[j]和W'[j] */
        {
            uint32_t temp_w[4], temp_wp[4];  
            int lane;
            for (lane = 0; lane < 4; lane++) {
                temp_w[lane]  = W_buf[lane][j];
                temp_wp[lane] = W_buf[lane][j] ^ W_buf[lane][j + 4];
            }
            q_Wj  = vld1q_u32(temp_w);
            q_Wpj = vld1q_u32(temp_wp);
        }

        /* 广播轮常量(NEON vdupq_n_u32) */
        q_Tj = vdupq_n_u32(ROTL32(get_Tj(j), j & 31));

        /* SS1 = ((A<<<12) + E + T_j) <<< 7 */
        q_SS1 = vaddq_u32(q_A_rot12, q_E);
        q_SS1 = vaddq_u32(q_SS1, q_Tj);
        q_SS1 = neon_rotl32(q_SS1, 7);

        /* SS2 = SS1 ⊕ (A<<<12) */
        q_SS2 = veorq_u32(q_SS1, q_A_rot12);

        /* TT1 = FF_j(A,B,C) + D + SS2 + W'[j] */
        q_TT1 = neon_FF(j, q_A, q_B, q_C);
        q_TT1 = vaddq_u32(q_TT1, q_D);
        q_TT1 = vaddq_u32(q_TT1, q_SS2);
        q_TT1 = vaddq_u32(q_TT1, q_Wpj);

        /* TT2 = GG_j(E,F,G) + H + SS1 + W[j] */
        q_TT2 = neon_GG(j, q_E, q_F, q_G);
        q_TT2 = vaddq_u32(q_TT2, q_H);
        q_TT2 = vaddq_u32(q_TT2, q_SS1);
        q_TT2 = vaddq_u32(q_TT2, q_Wj);

        /* 状态旋转 */
        q_D = q_C;
        q_C = neon_rotl32(q_B, 9);
        q_B = q_A;
        q_A = q_TT1;
        q_H = q_G;
        q_G = neon_rotl32(q_F, 19);
        q_F = q_E;
        q_E = neon_P0(q_TT2);
    }

    /* V^(i+1) = 新状态 ⊕ 旧状态 */
    q_V[0] = veorq_u32(q_V[0], q_A);
    q_V[1] = veorq_u32(q_V[1], q_B);
    q_V[2] = veorq_u32(q_V[2], q_C);
    q_V[3] = veorq_u32(q_V[3], q_D);
    q_V[4] = veorq_u32(q_V[4], q_E);
    q_V[5] = veorq_u32(q_V[5], q_F);
    q_V[6] = veorq_u32(q_V[6], q_G);
    q_V[7] = veorq_u32(q_V[7], q_H);
}

/* 4路并行哈希 */
void sm3_hash_x4(const uint8_t *data[4], size_t len,
                 uint8_t digest[4][SM3_DIGEST_LENGTH])
{
    /* 通用寄存器层 */
    size_t total_bits;     
    size_t pad_len;       
    size_t num_blocks;    
    size_t blk_idx;       
    int lane, i;           

    /* NEON寄存器层 */
    uint32x4_t q_V[8];
    /* 初始化4路状态为SM3 IV */
    {
        const uint32_t SM3_IV[8] = {
            0x7380166F, 0x4914B2B9, 0x172442D7, 0xDA8A0600,
            0xA96F30BC, 0x163138AA, 0xE38DEE4D, 0xB0FB0E4E
        };
        for (i = 0; i < 8; i++) {
            q_V[i] = vdupq_n_u32(SM3_IV[i]);
        }
    }

    /* 计算填充长度 */
    total_bits = len * 8;
    pad_len = len + 1;
    if (pad_len % SM3_BLOCK_SIZE > 56) {
        pad_len += SM3_BLOCK_SIZE;
    }
    pad_len = ((pad_len + SM3_BLOCK_SIZE - 1) / SM3_BLOCK_SIZE)
              * SM3_BLOCK_SIZE;
    num_blocks = pad_len / SM3_BLOCK_SIZE;

    /* 分配填充缓冲区 */
    uint8_t **padded = (uint8_t **)malloc(4 * sizeof(uint8_t *));
    for (lane = 0; lane < 4; lane++) {
        padded[lane] = (uint8_t *)calloc(pad_len, 1);
        memcpy(padded[lane], data[lane], len);
        padded[lane][len] = 0x80;
        padded[lane][pad_len - 8] = (uint8_t)(total_bits >> 56);
        padded[lane][pad_len - 7] = (uint8_t)(total_bits >> 48);
        padded[lane][pad_len - 6] = (uint8_t)(total_bits >> 40);
        padded[lane][pad_len - 5] = (uint8_t)(total_bits >> 32);
        padded[lane][pad_len - 4] = (uint8_t)(total_bits >> 24);
        padded[lane][pad_len - 3] = (uint8_t)(total_bits >> 16);
        padded[lane][pad_len - 2] = (uint8_t)(total_bits >> 8);
        padded[lane][pad_len - 1] = (uint8_t)(total_bits);
    }

    {
        uint32_t W_buf[4][68];      /* 消息扩展缓冲区 */
        uint32_t msg_words[4][16];  /* 消息字暂存 */

        for (blk_idx = 0; blk_idx < num_blocks; blk_idx++) {
            for (lane = 0; lane < 4; lane++) {
                const uint8_t *blk = padded[lane] +
                                     blk_idx * SM3_BLOCK_SIZE;
                for (i = 0; i < 16; i++) {
                    msg_words[lane][i] =
                        ((uint32_t)blk[i * 4 + 0] << 24) |
                        ((uint32_t)blk[i * 4 + 1] << 16) |
                        ((uint32_t)blk[i * 4 + 2] << 8)  |
                        ((uint32_t)blk[i * 4 + 3]);
                }
            }

            sm3_expand_x4(msg_words, W_buf);

            sm3_compress_x4(q_V, W_buf);
        }
    }

    /* 输出4路摘要 */
    {
        uint32_t out_state[8][4];  /* [状态字索引][lane索引] */

        /* NEON -> 内存 */
        for (i = 0; i < 8; i++) {
            vst1q_u32(out_state[i], q_V[i]);
        }

        for (lane = 0; lane < 4; lane++) {
            for (i = 0; i < 8; i++) {
                uint32_t w = out_state[i][lane];
                digest[lane][i * 4 + 0] = (uint8_t)(w >> 24);
                digest[lane][i * 4 + 1] = (uint8_t)(w >> 16);
                digest[lane][i * 4 + 2] = (uint8_t)(w >> 8);
                digest[lane][i * 4 + 3] = (uint8_t)(w);
            }
        }
    }

    /* 清理 */
    for (lane = 0; lane < 4; lane++) {
        free(padded[lane]);
    }
    free(padded);
}

const char *sm3_neon_impl_name(void)
{
    return "SM3 ARM64 NEON Optimized (4-way SIMD + GPR Hybrid)";
}

#else 

#include <stdio.h>

void sm3_hash_x4(const uint8_t *data[4], size_t len,
                 uint8_t digest[4][SM3_DIGEST_LENGTH])
{
    (void)data; (void)len; (void)digest;
    fprintf(stderr, "ERROR: sm3_hash_x4 requires ARM NEON support.\n");
}

const char *sm3_neon_impl_name(void)
{
    return "SM3 ARM64 NEON (NOT COMPILED WITH NEON)";
}

#endif 
