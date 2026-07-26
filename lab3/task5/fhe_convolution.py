import numpy as np
from phe import paillier
import time
import sys

INPUT_MATRIX = np.array([
    [10, 20, 30, 40],
    [50, 60, 70, 80],
    [90, 100, 110, 120],
    [130, 140, 150, 160]
], dtype=np.int64)

# 卷积核
# 使用边缘检测算子
KERNEL = np.array([
    [1, 0, -1],
    [2, 0, -2],
    [1, 0, -1]
], dtype=np.int64)

# 卷积参数
STRIDE = 1
PADDING = 0  

# 密钥长度 
KEY_SIZE = 512  


def plaintext_conv2d(input_matrix, kernel, stride=1, padding=0):
    H_in, W_in = input_matrix.shape
    H_k, W_k = kernel.shape

    H_out = (H_in + 2 * padding - H_k) // stride + 1
    W_out = (W_in + 2 * padding - W_k) // stride + 1

    output = np.zeros((H_out, W_out), dtype=np.int64)

    for i in range(H_out):
        for j in range(W_out):
            patch = input_matrix[i:i+H_k, j:j+W_k]
            output[i, j] = np.sum(patch * kernel)

    return output

def generate_keypair(key_size=512):
    """生成 Paillier 公私钥对"""
    print(f"[密钥生成] 正在生成 {key_size}-bit Paillier 密钥对...")
    start = time.time()
    public_key, private_key = paillier.generate_paillier_keypair(n_length=key_size)
    elapsed = time.time() - start
    print(f"[密钥生成] 完成，耗时: {elapsed:.3f}s")
    return public_key, private_key


def encrypt_input(input_matrix, public_key):
    H, W = input_matrix.shape
    encrypted_matrix = np.empty((H, W), dtype=object)

    total = H * W
    print(f"[加密] 正在加密 {H}x{W} = {total} 个输入元素...")
    start = time.time()

    for i in range(H):
        for j in range(W):
            encrypted_matrix[i, j] = public_key.encrypt(int(input_matrix[i, j]))

    elapsed = time.time() - start
    print(f"[加密] 完成，总耗时: {elapsed:.3f}s, 平均: {elapsed/total*1000:.2f}ms/元素")
    return encrypted_matrix


def homomorphic_conv2d(encrypted_input, kernel, stride=1):
    
    H_in, W_in = encrypted_input.shape
    H_k, W_k = kernel.shape

    H_out = (H_in - H_k) // stride + 1
    W_out = (W_in - W_k) // stride + 1

    encrypted_output = np.empty((H_out, W_out), dtype=object)

    total_positions = H_out * W_out
    print(f"\n[密文卷积] 输出尺寸: {H_out}x{W_out} = {total_positions} 个位置")
    print(f"[密文卷积] 每个位置需 {H_k}x{W_k} = {H_k*W_k} 次标量乘法 + {H_k*W_k-1} 次加法")
    print(f"[密文卷积] 总操作: {total_positions * H_k * W_k} 次标量乘法, "
          f"{total_positions * (H_k * W_k - 1)} 次同态加法")
    print()

    start = time.time()

    for i in range(H_out):
        for j in range(W_out):
            # 初始化累加器为 E(0)
            acc = None

            for r in range(H_k):
                for c in range(W_k):
                    in_val = encrypted_input[i + r, j + c]
                    k_val = int(kernel[r, c])

                    if k_val == 0:
                        # kernel[r,c] = 0 时跳过
                        if acc is None:
                            acc = k_val * in_val  
                        continue

                    # E(input) x kernel_weight
                    scaled = k_val * in_val

                    if acc is None:
                        acc = scaled
                    else:
                        # E(acc) + E(scaled)
                        acc = acc + scaled

            encrypted_output[i, j] = acc

            print(f"  位置 ({i},{j}): 完成 "
                  f"({(i*W_out + j + 1)}/{total_positions})")

    elapsed = time.time() - start
    print(f"\n[密文卷积] 完成，总耗时: {elapsed:.3f}s, "
          f"平均: {elapsed/total_positions*1000:.2f}ms/输出位置")
    return encrypted_output


def decrypt_output(encrypted_output, private_key):

    H, W = encrypted_output.shape
    output = np.zeros((H, W), dtype=np.int64)

    print(f"\n[解密] 正在解密 {H}x{W} 个输出元素...")
    start = time.time()

    for i in range(H):
        for j in range(W):
            output[i, j] = private_key.decrypt(encrypted_output[i, j])

    elapsed = time.time() - start
    print(f"[解密] 完成，耗时: {elapsed:.3f}s")
    return output


def detailed_verification(plaintext_output, decrypted_output, input_matrix, kernel):

    H_out, W_out = plaintext_output.shape
    H_k, W_k = kernel.shape

    all_match = True

    for i in range(H_out):
        for j in range(W_out):
            print(f"输出位置 ({i}, {j}):")
            
            # 展示该位置的局部感受野
            patch = input_matrix[i:i+H_k, j:j+W_k]
            print(f"  输入感受野 ({H_k}x{H_k}):")
            for ri in range(H_k):
                row_str = "    " + "  ".join(f"{patch[ri, ci]:4d}" for ci in range(W_k))
                print(row_str)

            print(f"\n  卷积核权重:")
            for ri in range(H_k):
                row_str = "    " + "  ".join(f"{kernel[ri, ci]:4d}" for ci in range(W_k))
                print(row_str)

            # 逐元素乘积
            print(f"\n  逐元素乘积 (感受野 x 核):")
            products = patch * kernel
            for ri in range(H_k):
                row_str = "    " + "  ".join(f"{products[ri, ci]:4d}" for ci in range(W_k))
                print(row_str)

            products_flat = products.flatten()
            kernel_flat = kernel.flatten()
            patch_flat = patch.flatten()

            # 展开累加过程
            sum_expr = " + ".join(
                f"({patch_flat[k]}x{kernel_flat[k]})"
                for k in range(len(products_flat))
            )
            print(f"\n  累加: {sum_expr}")
            print(f"     = {' + '.join(str(p) for p in products_flat)}")

            pt_val = plaintext_output[i, j]
            he_val = decrypted_output[i, j]

            print(f"\n  明文卷积结果:    {pt_val}")
            print(f"  同态解密结果:    {he_val}")

            if pt_val == he_val:
                print(f"  验证: [OK] 匹配!")
            else:
                print(f"  验证: [FAIL] 不匹配! 差异 = {abs(pt_val - he_val)}")
                all_match = False

    if all_match:
        print("  结论: 所有输出位置验证通过 [OK] — 密文域卷积结果与明文域完全一致")
    else:
        print("  结论: 存在不匹配 [FAIL]")
    print("=" * 70)

    return all_match

def print_performance_stats(encrypt_time, conv_time, decrypt_time,
                            plaintext_time, input_shape, kernel_shape):

    H_in, W_in = input_shape
    H_k, W_k = kernel_shape
    H_out = H_in - H_k + 1
    W_out = W_in - W_k + 1

 
    print("[性能统计]")
    print(f"  Paillier 密钥长度:     {KEY_SIZE} bits")
    print(f"  输入尺寸:              {H_in}x{W_in} = {H_in*W_in} 元素")
    print(f"  卷积核尺寸:            {H_k}x{H_k} = {H_k*H_k} 权重")
    print(f"  输出尺寸:              {H_out}x{W_out} = {H_out*W_out} 元素")
    print()
    print(f"  明文卷积耗时:          {plaintext_time*1000:.2f} ms")
    print(f"  密文加密耗时:          {encrypt_time:.3f} s")
    print(f"  密文卷积耗时:          {conv_time:.3f} s")
    print(f"  密文解密耗时:          {decrypt_time:.3f} s")
    print(f"  密文域总耗时:          {encrypt_time + conv_time + decrypt_time:.3f} s")
    print()
    overhead = (encrypt_time + conv_time + decrypt_time) / (plaintext_time + 1e-9)
    print(f"  密文/明文 时间比:      {overhead:.0f}x")
    print("=" * 70)


def demonstrate_homomorphic_properties(public_key, private_key):

    print("Paillier 同态性质演示")

    # 性质1: 加法同态 E(a) + E(b) = E(a+b)
    a, b = 42, 58
    enc_a = public_key.encrypt(a)
    enc_b = public_key.encrypt(b)
    enc_sum = enc_a + enc_b
    dec_sum = private_key.decrypt(enc_sum)

    print(f"\n  [性质1] 加法同态: E(a) + E(b) = E(a+b)")
    print(f"    a = {a}, b = {b}")
    print(f"    E(a) + E(b) -> 解密得: {dec_sum}")
    print(f"    a + b = {a + b}")
    status = "OK" if dec_sum == a + b else "FAIL"
    print(f"    验证: [{status}]")

    # 性质2: 标量乘法同态 E(a) x k = E(a x k)
    a, k = 17, 5
    enc_a = public_key.encrypt(a)
    enc_mul = enc_a * k
    dec_mul = private_key.decrypt(enc_mul)

    print(f"\n  [性质2] 标量乘法同态: E(a) x k = E(a x k)")
    print(f"    a = {a}, k = {k}")
    print(f"    E(a) x {k} -> 解密得: {dec_mul}")
    print(f"    a x {k} = {a * k}")
    status = "OK" if dec_mul == a * k else "FAIL"
    print(f"    验证: [{status}]")

    # 性质3: 混合运算 E(a)*k1 + E(b)*k2 = E(a*k1 + b*k2)
    a, b = 10, 20
    k1, k2 = 3, 4
    enc_a = public_key.encrypt(a)
    enc_b = public_key.encrypt(b)
    enc_mixed = enc_a * k1 + enc_b * k2
    dec_mixed = private_key.decrypt(enc_mixed)

    print(f"\n  [性质3] 线性组合: E(a)*k1 + E(b)*k2 = E(a*k1 + b*k2)")
    print(f"    a={a}, b={b}, k1={k1}, k2={k2}")
    print(f"    E(a)*{k1} + E(b)*{k2} -> 解密得: {dec_mixed}")
    print(f"    a*{k1} + b*{k2} = {a*k1 + b*k2}")
    status = "OK" if dec_mixed == a*k1 + b*k2 else "FAIL"
    print(f"    验证: [{status}]")

    print("=" * 70)


def main():

    # 展示输入和卷积核
    print("\n[输入矩阵] 4x4:")
    for row in INPUT_MATRIX:
        print("  " + "  ".join(f"{v:4d}" for v in row))

    print(f"\n[卷积核] {KERNEL.shape[0]}x{KERNEL.shape[1]} (Sobel-like 边缘检测):")
    for row in KERNEL:
        print("  " + "  ".join(f"{v:4d}" for v in row))

    H_out = (INPUT_MATRIX.shape[0] - KERNEL.shape[0]) // STRIDE + 1
    W_out = (INPUT_MATRIX.shape[1] - KERNEL.shape[1]) // STRIDE + 1
    print(f"\n[卷积参数] stride={STRIDE}, padding={PADDING}")
    print(f"[输出尺寸] {H_out}x{W_out}")

    # 明文卷积
    print("\n" + "-" * 50)
    print("  阶段1: 明文域卷积（基准）")
    print("-" * 50)

    start = time.time()
    plaintext_result = plaintext_conv2d(INPUT_MATRIX, KERNEL, STRIDE, PADDING)
    plaintext_time = time.time() - start

    print(f"\n[明文卷积结果] (耗时: {plaintext_time*1000:.2f}ms):")
    for row in plaintext_result:
        print("  " + "  ".join(f"{v:6d}" for v in row))

    # 同态加密卷积
    print("\n" + "-" * 50)
    print("  阶段2: 同态加密域卷积")
    print("-" * 50)

    # 生成密钥
    public_key, private_key = generate_keypair(KEY_SIZE)

    # 加密输入
    encrypt_start = time.time()
    encrypted_input = encrypt_input(INPUT_MATRIX, public_key)
    encrypt_time = time.time() - encrypt_start

    # 密文域卷积
    conv_start = time.time()
    encrypted_output = homomorphic_conv2d(encrypted_input, KERNEL, STRIDE)
    conv_time = time.time() - conv_start

    # 解密结果
    decrypt_start = time.time()
    decrypted_result = decrypt_output(encrypted_output, private_key)
    decrypt_time = time.time() - decrypt_start

    print(f"\n[同态加密卷积解密结果] (密文域总耗时: {encrypt_time + conv_time + decrypt_time:.3f}s):")
    for row in decrypted_result:
        print("  " + "  ".join(f"{v:6d}" for v in row))

    # 同态性质演示
    demonstrate_homomorphic_properties(public_key, private_key)

    # 详细验证
    all_pass = detailed_verification(plaintext_result, decrypted_result,
                                      INPUT_MATRIX, KERNEL)

    # 性能统计
    print_performance_stats(encrypt_time, conv_time, decrypt_time,
                            plaintext_time, INPUT_MATRIX.shape, KERNEL.shape)


    return 0 if all_pass else 1


if __name__ == "__main__":
    sys.exit(main())
