/*
 本实现基于 x86 AVX2 指令集，采用 SIMD寄存器和通用寄存器混合优化策略。

 混合策略说明：
   - SIMD寄存器 (YMM0-15):  处理8路并行的状态更新、布尔函数、加法等
   - 通用寄存器 (RAX,RCX...):  消息扩展的标量计算、内存寻址、循环迭代
   - 消息扩展策略: 使用标量代码逐消息进行扩展，结果交错存储在内存中，
     轮函数执行时通过 gather/scalar load 读取，充分利用通用寄存器

 轮函数中每轮的操作:
   SS1 = ((A <<< 12) + E + (T_j <<< j)) <<< 7           -> 8路SIMD
   SS2 = SS1 ^ (A <<< 12)                               -> SIMD XOR
   TT1 = FF_j(A,B,C) + D + SS2 + W'[j]                  -> SIMD混合
   TT2 = GG_j(E,F,G) + H + SS1 + W[j]                   -> SIMD混合
   状态旋转: A->B->C->D, E->F->G->H                     -> 寄存器重命名
 */

#include "sm3.h"
#include <string.h>
#include <stdlib.h>

#ifdef __AVX2__

#include <immintrin.h>

/* 获取未经旋转的T_j常量 */
static inline uint32_t get_Tj(int j)
{
    return (j < 16) ? 0x79CC4519 : 0x7A879D8A;
}

/* 8路32位循环左移 */
static inline __m256i mm256_rotl32(__m256i x, int n)
{
    __m256i left  = _mm256_slli_epi32(x, n);
    __m256i right = _mm256_srli_epi32(x, 32 - n);
    return _mm256_or_si256(left, right);
}

/* P_0(X) = X ⊕ (X<<<9) ⊕ (X<<<17) */
static inline __m256i mm256_P0(__m256i x)
{
    return _mm256_xor_si256(
               _mm256_xor_si256(x, mm256_rotl32(x, 9)),
               mm256_rotl32(x, 17));
}

/* P_1(X) = X ⊕ (X<<<15) ⊕ (X<<<23) */
static inline __m256i mm256_P1(__m256i x)
{
    return _mm256_xor_si256(
               _mm256_xor_si256(x, mm256_rotl32(x, 15)),
               mm256_rotl32(x, 23));
}

/* FF_j 布尔函数 */
static inline __m256i mm256_FF(int j, __m256i x, __m256i y, __m256i z)
{
    if (j < 16) {
        /* FF = X ⊕ Y ⊕ Z */
        return _mm256_xor_si256(_mm256_xor_si256(x, y), z);
    } else {
        /* FF = (X ∧ Y) ∨ (X ∧ Z) ∨ (Y ∧ Z) */
        __m256i xy = _mm256_and_si256(x, y);
        __m256i xz = _mm256_and_si256(x, z);
        __m256i yz = _mm256_and_si256(y, z);
        return _mm256_or_si256(_mm256_or_si256(xy, xz), yz);
    }
}

/* GG_j 布尔函数 */
static inline __m256i mm256_GG(int j, __m256i x, __m256i y, __m256i z)
{
    if (j < 16) {
        /* GG = X ⊕ Y ⊕ Z */
        return _mm256_xor_si256(_mm256_xor_si256(x, y), z);
    } else {
        /* GG = (X ∧ Y) ∨ (¬X ∧ Z) */
        __m256i xy  = _mm256_and_si256(x, y);
        __m256i nxz = _mm256_andnot_si256(x, z);  /* (~X) & Z */
        return _mm256_or_si256(xy, nxz);
    }
}

/* 32位循环左移 */
#define SCALAR_ROTL32(x, n) (((x) << (n)) | ((x) >> (32 - (n))))

/* P_1(X) = X ⊕ (X<<<15) ⊕ (X<<<23) */
static inline uint32_t scalar_P1(uint32_t x)
{
    return x ^ SCALAR_ROTL32(x, 15) ^ SCALAR_ROTL32(x, 23);
}

/* P_0(X) = X ⊕ (X<<<9) ⊕ (X<<<17) */
static inline uint32_t scalar_P0(uint32_t x)
{
    return x ^ SCALAR_ROTL32(x, 9) ^ SCALAR_ROTL32(x, 17);
}

/* 8路并行消息扩展 */
static void sm3_expand_x8(const uint32_t msg_words[8][16],
                          uint32_t W_buf[8][68])
{
    int lane;  /* 循环索引 */
    int j;     /* 字索引 */

    for (lane = 0; lane < 8; lane++) {
        uint32_t *W = W_buf[lane];

        for (j = 0; j < 16; j++) {
            W[j] = msg_words[lane][j];
        }

        /* W[16..67] */
        for (j = 16; j < 68; j++) {

            uint32_t w16 = W[j - 16];    
            uint32_t w9  = W[j - 9];     
            uint32_t w3  = W[j - 3];     
            uint32_t w13 = W[j - 13];    
            uint32_t w6  = W[j - 6];     

            uint32_t tmp = w16 ^ w9 ^ SCALAR_ROTL32(w3, 15);
            W[j] = scalar_P1(tmp) ^ SCALAR_ROTL32(w13, 7) ^ w6;
        }
    }
}

/* 8路并行压缩函数 */
static void sm3_compress_x8(__m256i ymm_V[8],
                            const uint32_t W_buf[8][68])
{
    __m256i ymm_A, ymm_B, ymm_C, ymm_D;
    __m256i ymm_E, ymm_F, ymm_G, ymm_H;
    __m256i ymm_SS1, ymm_SS2, ymm_TT1, ymm_TT2;
    __m256i ymm_Tj, ymm_Wj, ymm_Wpj;
    __m256i ymm_A_rot12;
    int j;  

    /* 从内存加载8组初始状态到YMM寄存器 */
    ymm_A = ymm_V[0];  ymm_B = ymm_V[1];
    ymm_C = ymm_V[2];  ymm_D = ymm_V[3];
    ymm_E = ymm_V[4];  ymm_F = ymm_V[5];
    ymm_G = ymm_V[6];  ymm_H = ymm_V[7];

    /* 64轮迭代 */
    for (j = 0; j < 64; j++) {
        /* 使用 SIMD 指令，YMM寄存器中8路同时旋转 */
        ymm_A_rot12 = mm256_rotl32(ymm_A, 12);

        /* 加载 W[j] 和 W'[j] */
        {
            /* 地址计算 */
            uint32_t temp_w[8], temp_wp[8];
            int lane;
            /* 通用寄存器逐lane读取，然后SIMD加载 */
            for (lane = 0; lane < 8; lane++) {
                temp_w[lane]  = W_buf[lane][j];
                temp_wp[lane] = W_buf[lane][j] ^ W_buf[lane][j + 4];
            }
            ymm_Wj  = _mm256_loadu_si256((const __m256i *)temp_w);
            ymm_Wpj = _mm256_loadu_si256((const __m256i *)temp_wp);
        }

        /* 广播轮常量到所有8 lane */
        ymm_Tj = _mm256_set1_epi32(SCALAR_ROTL32(get_Tj(j), j & 31));

        /* SS1 = ((A<<<12) + E + T_j) <<< 7，使用SIMD寄存器操作 */
        ymm_SS1 = _mm256_add_epi32(ymm_A_rot12, ymm_E);
        ymm_SS1 = _mm256_add_epi32(ymm_SS1, ymm_Tj);
        ymm_SS1 = mm256_rotl32(ymm_SS1, 7);

        /* SS2 = SS1 ⊕ (A<<<12) */
        ymm_SS2 = _mm256_xor_si256(ymm_SS1, ymm_A_rot12);

        /* TT1 = FF_j(A,B,C) + D + SS2 + W'[j] */
        ymm_TT1 = mm256_FF(j, ymm_A, ymm_B, ymm_C);
        ymm_TT1 = _mm256_add_epi32(ymm_TT1, ymm_D);
        ymm_TT1 = _mm256_add_epi32(ymm_TT1, ymm_SS2);
        ymm_TT1 = _mm256_add_epi32(ymm_TT1, ymm_Wpj);

        /* TT2 = GG_j(E,F,G) + H + SS1 + W[j] */
        ymm_TT2 = mm256_GG(j, ymm_E, ymm_F, ymm_G);
        ymm_TT2 = _mm256_add_epi32(ymm_TT2, ymm_H);
        ymm_TT2 = _mm256_add_epi32(ymm_TT2, ymm_SS1);
        ymm_TT2 = _mm256_add_epi32(ymm_TT2, ymm_Wj);

        /* 状态旋转
         D <- C, C <- B<<<9, B <- A, A <- TT1
         H <- G, G <- F<<<19, F <- E, E <- P0
         */
        ymm_D = ymm_C;
        ymm_C = mm256_rotl32(ymm_B, 9);
        ymm_B = ymm_A;
        ymm_A = ymm_TT1;
        ymm_H = ymm_G;
        ymm_G = mm256_rotl32(ymm_F, 19);
        ymm_F = ymm_E;
        ymm_E = mm256_P0(ymm_TT2);
    }

    /* 输出: V^(i+1) = A||B||C||D||E||F||G||H ⊕ V^(i) */
    ymm_V[0] = _mm256_xor_si256(ymm_V[0], ymm_A);
    ymm_V[1] = _mm256_xor_si256(ymm_V[1], ymm_B);
    ymm_V[2] = _mm256_xor_si256(ymm_V[2], ymm_C);
    ymm_V[3] = _mm256_xor_si256(ymm_V[3], ymm_D);
    ymm_V[4] = _mm256_xor_si256(ymm_V[4], ymm_E);
    ymm_V[5] = _mm256_xor_si256(ymm_V[5], ymm_F);
    ymm_V[6] = _mm256_xor_si256(ymm_V[6], ymm_G);
    ymm_V[7] = _mm256_xor_si256(ymm_V[7], ymm_H);
}

/* 8路并行哈希 */
void sm3_hash_x8(const uint8_t *data[8], size_t len,
                 uint8_t digest[8][SM3_DIGEST_LENGTH])
{
    /* 通用寄存器层 */
    size_t total_bits;     
    size_t pad_len;        
    size_t num_blocks;     
    size_t blk_idx;       
    int lane, i;           

    /* SIMD寄存器层 */
    __m256i ymm_V[8];

    /* 初始化8路状态为SM3 IV */
    for (i = 0; i < 8; i++) {
        ymm_V[i] = _mm256_set1_epi32(
            ((const uint32_t[]){
                0x7380166F, 0x4914B2B9, 0x172442D7, 0xDA8A0600,
                0xA96F30BC, 0x163138AA, 0xE38DEE4D, 0xB0FB0E4E
            })[i]);
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

    /* 为每条消息分配填充缓冲区 */
    uint8_t **padded = (uint8_t **)malloc(8 * sizeof(uint8_t *));
    for (lane = 0; lane < 8; lane++) {
        padded[lane] = (uint8_t *)calloc(pad_len, 1);
        memcpy(padded[lane], data[lane], len);
        padded[lane][len] = 0x80;  /* 追加 bit 1 */
        /* 写入64位长度 */
        padded[lane][pad_len - 8] = (uint8_t)(total_bits >> 56);
        padded[lane][pad_len - 7] = (uint8_t)(total_bits >> 48);
        padded[lane][pad_len - 6] = (uint8_t)(total_bits >> 40);
        padded[lane][pad_len - 5] = (uint8_t)(total_bits >> 32);
        padded[lane][pad_len - 4] = (uint8_t)(total_bits >> 24);
        padded[lane][pad_len - 3] = (uint8_t)(total_bits >> 16);
        padded[lane][pad_len - 2] = (uint8_t)(total_bits >> 8);
        padded[lane][pad_len - 1] = (uint8_t)(total_bits);
    }

    /* 逐块处理 */
    {
        uint32_t W_buf[8][68];       /* 消息扩展缓冲区 */
        uint32_t msg_words[8][16];    /* 消息字暂存 */

        for (blk_idx = 0; blk_idx < num_blocks; blk_idx++) {
            /* 逐lane读取消息块并转为大端字(通用寄存器) */
            for (lane = 0; lane < 8; lane++) {
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

            sm3_expand_x8(msg_words, W_buf);

            sm3_compress_x8(ymm_V, W_buf);
        }
    }

    /* 输出8路摘要 */
    {
        uint32_t out_state[8][8];

        /* SIMD -> 内存: 将YMM寄存器中的结果存储到标量数组 */
        for (i = 0; i < 8; i++) {
            _mm256_storeu_si256((__m256i *)out_state[i], ymm_V[i]);
        }

        /* 逐lane写出32字节大端 */
        for (lane = 0; lane < 8; lane++) {
            for (i = 0; i < 8; i++) {
                uint32_t w = ((uint32_t *)out_state[i])[lane];
                digest[lane][i * 4 + 0] = (uint8_t)(w >> 24);
                digest[lane][i * 4 + 1] = (uint8_t)(w >> 16);
                digest[lane][i * 4 + 2] = (uint8_t)(w >> 8);
                digest[lane][i * 4 + 3] = (uint8_t)(w);
            }
        }
    }

    /* 清理 */
    for (lane = 0; lane < 8; lane++) {
        free(padded[lane]);
    }
    free(padded);
}

const char *sm3_avx2_impl_name(void)
{
    return "SM3 AVX2 Optimized (8-way SIMD + GPR Hybrid)";
}

#else 

#include <stdio.h>

void sm3_hash_x8(const uint8_t *data[8], size_t len,
                 uint8_t digest[8][SM3_DIGEST_LENGTH])
{
    (void)data; (void)len; (void)digest;
    fprintf(stderr, "ERROR: sm3_hash_x8 requires AVX2 support.\n");
}

const char *sm3_avx2_impl_name(void)
{
    return "SM3 AVX2 (NOT COMPILED WITH AVX2)";
}

#endif 
