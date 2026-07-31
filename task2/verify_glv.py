#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
try:
    sys.stdout.reconfigure(encoding="utf-8")  
except Exception:
    pass

p  = 2**256 - 2**32 - 977                                                     
a, b = 0, 7                                                                  
n  = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141       
Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798      
Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8

beta   = 0x7ae96a2b657c07106e64479eac3434e99cf0497512f58995c1396c28719501ee  
lam    = 0x5363ad4cc05c30e0a5261c028812645a122e22ea20816678df02967c1b23bd72  

minus_b1 = 0xe4437ed6010e88286f547fa90abfe4c3
minus_b2 = 0xfffffffffffffffffffffffffffffffe8a280ac50774346dd765cda83db1562c
g1 = 0x3086d221a7d46bcde86c90e49284eb153daa8a1471e8ca7fe893209a45dbb031
g2 = 0xe4437ed6010e88286f547fa90abfe4c4221208ac9df506c61571b4ae8ac47f71

INF = None 

def is_on_curve(P):
    if P is INF:
        return True
    x, y = P
    return (y * y - (x * x * x + a * x + b)) % p == 0

def ec_add(P, Q):
    if P is INF: return Q
    if Q is INF: return P
    x1, y1 = P
    x2, y2 = Q
    if x1 == x2 and (y1 + y2) % p == 0:
        return INF                       
    if P == Q:
        m = (3 * x1 * x1 + a) * pow(2 * y1, -1, p) % p          
    else:
        m = (y2 - y1) * pow(x2 - x1, -1, p) % p               
    x3 = (m * m - x1 - x2) % p
    y3 = (m * (x1 - x3) - y1) % p
    return (x3, y3)

def ec_mul(k, P):
    """double-and-add 标量乘法。"""
    k %= n
    R = INF
    while k:
        if k & 1:
            R = ec_add(R, P)
        P = ec_add(P, P)
        k >>= 1
    return R

def mul_shift(k, g, shift):
    """round(k*g / 2^shift)：对应 secp256k1_scalar_mul_shift_var。"""
    return (k * g + (1 << (shift - 1))) >> shift

def split_lambda(k):
    """把 k 分解为 (k1, k2)，使 k1 + λ*k2 == k (mod n)。复刻 C 代码逻辑。"""
    c1 = mul_shift(k, g1, 384)
    c2 = mul_shift(k, g2, 384)
    c1 = (c1 * minus_b1) % n
    c2 = (c2 * minus_b2) % n
    k2 = (c1 + c2) % n
    k1 = (k - k2 * lam) % n
    return k1, k2

def signed(x):
    """把 mod n 的值映到 (-n/2, n/2]，便于看真实绝对值大小。"""
    return x if x <= n // 2 else x - n

def line(t): print("\n" + "=" * 68 + "\n" + t + "\n" + "=" * 68)

ok = True
def check(name, cond):
    global ok
    ok = ok and cond
    print(f"  [{'通过' if cond else '失败'}] {name}")

line("验证 1：β、λ 是非平凡单位立方根")
check("β^3 ≡ 1 (mod p)", pow(beta, 3, p) == 1)
check("β  ≠ 1          ", beta != 1)
check("β^2 + β + 1 ≡ 0 (mod p)", (beta*beta + beta + 1) % p == 0)
check("λ^3 ≡ 1 (mod n)", pow(lam, 3, n) == 1)
check("λ  ≠ 1          ", lam != 1)
check("λ^2 + λ + 1 ≡ 0 (mod n)", (lam*lam + lam + 1) % n == 0)

line("验证 2：自同态 φ(x,y)=(βx,y) 等于 乘以 λ，即 φ(P) = λ·P")
G = (Gx, Gy)
check("G 在曲线上", is_on_curve(G))
phiG  = ((beta * Gx) % p, Gy)             
lamG  = ec_mul(lam, G)                   
check("φ(G) 在曲线上", is_on_curve(phiG))
check("φ(G) == λ·G", phiG == lamG)
import random
random.seed(2026)
for i in range(3):
    P = ec_mul(random.randrange(1, n), G)
    check(f"随机点 P{i}: (βx,y) == λ·P", ((beta*P[0]) % p, P[1]) == ec_mul(lam, P))

line("验证 3：GLV 分解 k = k1 + λ·k2 (mod n)，且 k1,k2 ~ 2^128")
maxbits = 0
for i in range(5):
    k = random.randrange(1, n)
    k1, k2 = split_lambda(k)
    assert (k1 + lam * k2) % n == k % n, "分解等式不成立！"
    b1 = signed(k1).bit_length()
    b2 = signed(k2).bit_length()
    maxbits = max(maxbits, b1, b2)
    print(f"  k(256bit) 拆成 -> |k1|={b1:>3}bit, |k2|={b2:>3}bit，且 k1+λk2 == k ✓")
check("所有分量位长 <= 129 bit（原始 256 bit 减半）", maxbits <= 129)
k = random.randrange(1, n)
k1, k2 = split_lambda(k)
def signed_mul(s, P):
    return ec_mul(s % n, P) if s >= 0 else ec_mul((-s) % n, (P[0], (-P[1]) % p))
lhs = ec_mul(k, G)
rhs = ec_add(signed_mul(signed(k1), G), signed_mul(signed(k2), phiG))
check("k·G == k1·G + k2·φ(G)（GLV 点乘等式）", lhs == rhs)

line("验证 4：退化 bug 根源 —— x1=β·x2 且 y1=-y2 触发统一公式 0/0")
Q = ec_mul(random.randrange(1, n), G)
P1 = Q                                    # (x, y)
P2 = ((beta * Q[0]) % p, (-Q[1]) % p)     # (βx, -y) = -φ(Q)
x1, y1 = P1
x2, y2 = P2
check("P1, P2 均在曲线上", is_on_curve(P1) and is_on_curve(P2))
check("x1 != x2", x1 != x2)
check("x1^3 == x2^3（立方相等）", pow(x1,3,p) == pow(x2,3,p))
check("x1 == β^2 · x2（差一个非平凡立方根）", x1 == (beta*beta*x2) % p)
check("y1 == -y2（触发 M=y1+y2=0）", (y1 + y2) % p == 0)
M_unified = (y1 + y2) % p
denom_alt = (x1 - x2) % p
print(f"  统一公式分母 M = y1+y2 = {M_unified}  -> 若不修复即 0/0")
check("统一公式分母 M == 0（bug 触发点）", M_unified == 0)
check("备用斜率分母 (x1-x2) != 0（修复可用）", denom_alt != 0)
m_alt = (y1 - y2) * pow(x1 - x2, -1, p) % p
x3 = (m_alt * m_alt - x1 - x2) % p
y3 = (m_alt * (x1 - x3) - y1) % p
check("备用斜率 (y1-y2)/(x1-x2) 算出的和 == 标准点加结果", (x3, y3) == ec_add(P1, P2))
check("P1+P2 == (1-λ)·Q（有限点，非无穷远）", ec_add(P1, P2) == signed_mul(signed((1-lam) % n), Q))

line("总结")
print(f"  全部验证：{'✅ 全部通过' if ok else '❌ 存在失败项'}")
