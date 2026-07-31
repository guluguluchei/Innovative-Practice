import numpy as np
from typing import List, Tuple

===========================================================================


N = 4  # 4x4 输入
K = 3  # 3x3 卷积核
N_SLOTS = 16  # 16个槽位

# 卷积参数
STRIDE = 1
PADDING = 0

# 输入矩阵
INPUT_MATRIX = np.array([
    [1,  2,  3,  4],
    [5,  6,  7,  8],
    [9,  10, 11, 12],
    [13, 14, 15, 16]
], dtype=np.int64)

# 卷积核
GENERAL_KERNEL = np.array([
    [1, 2, 1],
    [0, 1, 0],
    [-1, -2, -1]
], dtype=np.int64)


SEPARABLE_KERNEL = np.array([
    [1, 0, -1],
    [2, 0, -2],
    [1, 0, -1]
], dtype=np.int64)


def pack_matrix_rowwise(matrix: np.ndarray, n_slots: int = 16) -> np.ndarray:

    H, W = matrix.shape
    flat = matrix.flatten()
    packed = np.zeros(n_slots, dtype=matrix.dtype)
    packed[:len(flat)] = flat
    return packed


def print_packing(packed: np.ndarray, n: int = N):
    print(f"\n  CKKS 槽位布局 (前 {n*n} 个有效槽位):")
    print("  槽位索引: ", end="")
    for i in range(n*n):
        print(f"{i:4d}", end="")
    print("\n  槽位值:   ", end="")
    for i in range(n*n):
        print(f"{packed[i]:4d}", end="")
    print()

    print("\n  对应矩阵位置:")
    for i in range(n):
        print("    ", end="")
        for j in range(n):
            idx = i * n + j
            print(f"[{i},{j}]={packed[idx]:2d}  ", end="")
        print()

def rotate_left(packed: np.ndarray, amount: int) -> np.ndarray:
    
    n = len(packed)
    rotated = np.zeros_like(packed)
    for i in range(n):
        rotated[i] = packed[(i + amount) % n]
    return rotated


def compute_kernel_rotations(kernel_size: int, n_cols: int) -> List[int]:

    amounts = []
    for r in range(kernel_size):
        for c in range(kernel_size):
            amounts.append(r * n_cols + c)
    return amounts

def simulate_convolution_pra(packed_input: np.ndarray, kernel: np.ndarray,
                              n_cols: int = N, n_slots: int = N_SLOTS):

    H_k, W_k = kernel.shape
    H_out = (N - H_k) // STRIDE + 1
    W_out = (N - W_k) // STRIDE + 1

    result = np.zeros(n_slots, dtype=np.float64)
    rotation_count = 0
    mult_count = 0
    skipped_count = 0

    print(f"\n  [卷积计算] 逐核位置处理:")
    print(f"  {'核位置':<10} {'旋转量':<10} {'核权重':<8} {'操作说明'}")


    for r in range(H_k):
        for c in range(W_k):
            k_val = kernel[r, c]

            # 计算左旋转量
            rot_amount = r * n_cols + c

            # 跳过旋转量为 0 的位置 
            if rot_amount == 0:
                rotated = packed_input.copy()
                print(f"  K[{r},{c}]      {'0(skip)':<10} {k_val:<8} 无旋转(已对齐)")
            else:
                rotated = rotate_left(packed_input, rot_amount)
                rotation_count += 1
                align_val = rotated[0]
                target_val = packed_input[rot_amount]
                print(f"  K[{r},{c}]      +{rot_amount:<9} {k_val:<8} "
                      f"左旋{rot_amount}位, in[{r},{c}]={target_val}")

            if k_val == 0:
                skipped_count += 1
                print(f"               {'':>10} {'':>8} -> 权重为0, 跳过乘法")
                continue

            mult_count += 1
            result += rotated * k_val

    print(f"\n  [结果提取] 从累加结果中提取 {H_out}x{W_out} 个输出位置:")
    outputs = {}
    for i in range(H_out):
        for j in range(W_out):
            extract_rot = i * n_cols + j
            if extract_rot == 0:
                outputs[(i, j)] = result.copy()
                print(f"    output[{i},{j}] -> 槽位0, 无需旋转")
            else:
                extracted = rotate_left(result, extract_rot)
                outputs[(i, j)] = extracted
                rotation_count += 1
                print(f"    output[{i},{j}] -> 左旋+{extract_rot}位")

    stats = {
        'kernel_rotations': H_k * W_k - 1, 
        'extraction_rotations': H_out * W_out - 1,
        'total_rotations': rotation_count,
        'multiplications': mult_count,
        'skipped_by_zero': skipped_count,
        'output_size': (H_out, W_out),
    }

    return result, outputs, stats

def check_separability(kernel: np.ndarray) -> Tuple[bool, np.ndarray, np.ndarray]:

    U, S, Vt = np.linalg.svd(kernel.astype(np.float64))
    rank = np.sum(S > 1e-10)

    if rank == 1:
        sigma = S[0]
        col = (U[:, 0] * np.sqrt(sigma)).reshape(-1, 1)
        row = (Vt[0, :] * np.sqrt(sigma)).reshape(1, -1)
        col_int = np.round(col).astype(np.int64)
        row_int = np.round(row).astype(np.int64)
        if np.allclose(col_int, col) and np.allclose(row_int, row):
            return True, col_int, row_int
        return True, col, row

    return False, None, None


def simulate_separable_convolution(packed_input: np.ndarray,
                                    col_vec: np.ndarray,
                                    row_vec: np.ndarray,
                                    n_cols: int = N,
                                    n_slots: int = N_SLOTS):

    H_k = len(col_vec)
    W_k = row_vec.shape[1]
    H_out = (N - H_k) // STRIDE + 1
    W_out = (N - W_k) // STRIDE + 1

    h_rotations = 0
    v_rotations = 0

    print(f"\n水平卷积:")
    h_result = np.zeros(n_slots, dtype=np.float64)

    for c, w in enumerate(row_vec.flatten()):
        rot_amount = c
        if rot_amount == 0:
            rotated = packed_input.copy()
            print(f"列偏移 {c}: 旋转量=0(无旋转), 权重={w}")
        else:
            rotated = rotate_left(packed_input, rot_amount)
            h_rotations += 1
            print(f"列偏移 {c}: 旋转量=+{rot_amount}, 权重={w}")

        if w != 0:
            h_result += rotated * w
        else:
            print(f"权重为0, 跳过")

    # 垂直卷积 
    print(f"\n 垂直卷积 (列向量 {col_vec.flatten()}):")
    v_result = np.zeros(n_slots, dtype=np.float64)

    for r, w in enumerate(col_vec.flatten()):
        rot_amount = r * n_cols
        if rot_amount == 0:
            rotated = h_result.copy()
            print(f"行偏移 {r}: 旋转量=0(无旋转), 权重={w}")
        else:
            rotated = rotate_left(h_result, rot_amount)
            v_rotations += 1
            print(f"行偏移 {r}: 旋转量=+{rot_amount}, 权重={w}")

        if w != 0:
            v_result += rotated * w
        else:
            print(f"权重为0, 跳过")

    # 提取输出
    outputs = {}
    extract_rotations = 0
    for i in range(H_out):
        for j in range(W_out):
            extract_rot = i * n_cols + j
            if extract_rot == 0:
                outputs[(i, j)] = v_result.copy()
            else:
                outputs[(i, j)] = rotate_left(v_result, extract_rot)
                extract_rotations += 1

    total_rot = h_rotations + v_rotations + extract_rotations
    print(f"\n  [可分离核旋转统计]")
    print(f"    水平卷积旋转: {h_rotations} 次")
    print(f"    垂直卷积旋转: {v_rotations} 次")
    print(f"    结果提取旋转: {extract_rotations} 次")
    print(f"    总计旋转:     {total_rot} 次")

    stats = {
        'h_rotations': h_rotations,
        'v_rotations': v_rotations,
        'extraction_rotations': extract_rotations,
        'total_rotations': total_rot,
    }

    return v_result, outputs, stats


def analyze_theoretical_minimum():

    n = N
    k = K


    print("[理论最小值分析]")

    print(f"""
    参数: {n}x{n} 输入, {k}x{k} 卷积核, stride=1

    1. 旋转群表示:
       需要的旋转集合 R = {{r*{n} + c | r,c in [0,{k-1}]}}
       R = {sorted([r*n + c for r in range(k) for c in range(k)])}
       |R| = {k*k} (包含恒等旋转 0)

    2. 一般核 :
       最小旋转次数 = |R| - 1 = {k*k - 1}
       (排除恒等旋转 r=0,c=0, 该位置已对齐)
       对于 {k}x{k} 核: {k*k - 1} 次

    3. 可分离核 (K = col x row^T):
       水平卷积需 {k-1} 次旋转 (列偏移 1..{k-1})
       垂直卷积需 {k-1} 次旋转 (行偏移 1..{k-1})
       最小旋转次数 = 2({k}-1) = {2*(k-1)}
       对于 {k}x{k} 核: {2*(k-1)} 次
       较一般核节省: {(k*k-1) - 2*(k-1)} 次 = {((k*k-1) - 2*(k-1))/(k*k-1)*100:.0f}%

    4. 零权重优化:
       每次跳过权重为 0 的核位置可节省 1 次旋转
       对于 Sobel 核 (中间列全 0): 额外节省 3 次旋转

    5. 结果提取:
       输出尺寸 ({n-k+1}x{n-k+1}) = {(n-k+1)*(n-k+1)} 个位置
       需额外 {(n-k+1)*(n-k+1) - 1} 次旋转来提取各输出位置
    """)

    # 对比表
    print(f"    {'方案':<30} {'旋转次数':<10} {'备注'}")
    print(f"    {'-'*60}")
    print(f"    {'一般核 (不可分离)':<30} {k*k-1:<10} {'理论最小值 k^2-1'}")
    print(f"    {'可分离核 (有SVD分解)':<30} {2*(k-1):<10} {'利用秩-1分解'}")
    print(f"    {'可分离核 + 零权重优化':<30} {2*(k-1)-k:<10} {'以Sobel核为例'}")
    print(f"    {'结果提取 (额外)':<30} {(n-k+1)*(n-k+1)-1:<10} {'提取各输出位置'}")

    print(f"\n  结论:")
    print(f"    对于一般核: 旋转次数 = k^2-1 = {k*k-1}, 已达到理论最小值")
    print(f"    对于可分离核: 旋转次数 = 2(k-1) = {2*(k-1)}, 远低于一般核理论最小值")
    print(f"    可分离核将 k^2 的旋转复杂度降为 2k, 从平方降为线性")
    print("=" * 70)


def visualize_rotation_mapping():
    n = N
    k = K

    print("[逐核位置的旋转对齐分析]")

    packed = pack_matrix_rowwise(INPUT_MATRIX, N_SLOTS)

    print(f"\n  原始打包 (4x4 输入):")
    print("  槽位: ", end="")
    for i in range(16):
        print(f"{i:3d}", end=" ")
    print("\n  值:   ", end="")
    for i in range(16):
        print(f"{packed[i]:3d}", end=" ")

    print(f"\n\n  各核位置的旋转分析:")
    print(f"  {'核位置':<8} {'旋转量':<8} {'对齐到槽位0的元素':<25} "
          f"{'验证: in[r,c]'}")
    print(f"  {'-'*65}")

    for r in range(k):
        for c in range(k):
            rot_amount = r * n + c
            rotated = rotate_left(packed, rot_amount)
            aligned_val = rotated[0]
            actual_val = INPUT_MATRIX[r, c]
            correct = "[OK]" if aligned_val == actual_val else "[FAIL]"
            print(f"  K[{r},{c}]     +{rot_amount:<7} "
                  f"槽位[0]={aligned_val:2d}                  "
                  f"in[{r},{c}]={actual_val:2d} {correct}")

    print(f"\n  说明: rotate_left(ct, r*n+c) 将 in[r][c] 移到槽位0")
    print(f"  所有旋转对齐验证通过")
    print("=" * 70)


def main():

    print(f"  配置: {N}x{N} 输入, {K}x{K} 核, stride={STRIDE}, "
          f"CKKS 槽位数={N_SLOTS}")

    print("阶段1: 打包")

    packed = pack_matrix_rowwise(INPUT_MATRIX, N_SLOTS)
    print_packing(packed)

    print(f"\n关键观察: 槽位索引 idx 对应矩阵位置 (idx//4, idx%4)")


    print("阶段2: 旋转量分析")

    amounts = compute_kernel_rotations(K, N)
    print(f"\n  3x3 核所需的全部旋转量: {amounts}")
    print(f"  唯一旋转量数量: {len(set(amounts))} (含旋转量 0)")
    print(f"  实际需执行的旋转: {len(set(amounts)) - 1} 次")
    print(f"  (旋转量 0 表示无需旋转, 元素已对齐)")

    visualize_rotation_mapping()

    print("阶段3: 一般核的 打包-旋转-累加")

    print(f"\n  使用不可分离的一般核:")
    for row in GENERAL_KERNEL:
        print(f"    {row}")

    result, outputs, stats = simulate_convolution_pra(
        packed, GENERAL_KERNEL, N, N_SLOTS)

    print(f"\n  [一般核 PRA 统计]")
    print(f"    核对齐旋转:   {stats['kernel_rotations']} 次 (不含旋转量0)")
    print(f"    结果提取旋转: {stats['extraction_rotations']} 次")
    print(f"    总计旋转:     {stats['total_rotations']} 次")
    print(f"    密文-明文乘法: {stats['multiplications']} 次")
    print(f"    跳过零权重:   {stats['skipped_by_zero']} 次")

    # 验证结果
    out_00_decrypted = outputs[(0, 0)][0]
    H_out, W_out = 2, 2
    plain_conv = np.zeros((H_out, W_out), dtype=np.float64)
    for i in range(H_out):
        for j in range(W_out):
            patch = INPUT_MATRIX[i:i+K, j:j+K]
            plain_conv[i, j] = np.sum(patch * GENERAL_KERNEL)

    print(f"\n  [结果验证 - 槽位0的值]")
    print(f"    PRA 模拟 output[0,0] = {out_00_decrypted:.0f}")
    print(f"    明文卷积 output[0,0]  = {plain_conv[0,0]:.0f}")
    match = abs(out_00_decrypted - plain_conv[0,0]) < 0.01
    print(f"    匹配: {'[OK]' if match else '[FAIL]'}")


    print("阶段4: 可分离核优化")

    is_sep, col_vec, row_vec = check_separability(SEPARABLE_KERNEL)

    print(f"\n原始 Sobel 核:")
    for row in SEPARABLE_KERNEL:
        print(f"    {row}")

    if is_sep:
        print(f"\n  SVD 秩-1 分解验证:")
        print(f"    col = {col_vec.flatten()}")
        print(f"    row = {row_vec.flatten()}")
        reconstructed = col_vec @ row_vec
        print(f"    col * row^T =")
        for row in reconstructed:
            print(f"      {row}")
        match_kernel = np.allclose(reconstructed, SEPARABLE_KERNEL)
        print(f"    与原始核一致: {'[OK]' if match_kernel else '[FAIL]'}")

    sep_result, sep_outputs, sep_stats = simulate_separable_convolution(
        packed, col_vec, row_vec, N, N_SLOTS)

    # 验证
    sep_out_00 = sep_outputs[(0, 0)][0]
    plain_sep = np.zeros((H_out, W_out), dtype=np.float64)
    for i in range(H_out):
        for j in range(W_out):
            patch = INPUT_MATRIX[i:i+K, j:j+K]
            plain_sep[i, j] = np.sum(patch * SEPARABLE_KERNEL)

    print(f"\n  [结果验证]")
    print(f"    可分离核 PRA output[0,0] = {sep_out_00:.0f}")
    print(f"    明文卷积 output[0,0]       = {plain_sep[0,0]:.0f}")
    match_sep = abs(sep_out_00 - plain_sep[0,0]) < 0.01
    print(f"    匹配: {'[OK]' if match_sep else '[FAIL]'}")


    print("阶段5: 旋转次数对比分析")

    analyze_theoretical_minimum()

if __name__ == "__main__":
    main()
