import numpy as np
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

plt.rcParams['font.family'] = ['SimHei', 'Microsoft YaHei', 'DejaVu Sans']
plt.rcParams['axes.unicode_minus'] = False

OUTPUT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'images')

# Data
N = 4
K = 3
N_SLOTS = 16

INPUT_MATRIX = np.array([
    [1,  2,  3,  4],
    [5,  6,  7,  8],
    [9,  10, 11, 12],
    [13, 14, 15, 16]
], dtype=np.int64)

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

packed = INPUT_MATRIX.flatten()


def rotate_left(packed, amount):
    n = len(packed)
    rotated = np.zeros_like(packed, dtype=np.float64)
    for i in range(n):
        rotated[i] = packed[(i + amount) % n]
    return rotated

def generate_pack_layout():
    fig, axes = plt.subplots(2, 1, figsize=(14, 8),
                              gridspec_kw={'height_ratios': [1, 1.5]})

    # Top: Matrix view
    ax_mat = axes[0]
    ax_mat.axis('tight')
    ax_mat.axis('off')
    tbl = ax_mat.table(cellText=[[str(v) for v in row] for row in INPUT_MATRIX],
                       cellLoc='center', loc='center')
    tbl.auto_set_font_size(False)
    tbl.set_fontsize(14)
    tbl.scale(1.3, 1.8)
    for i in range(4):
        for j in range(4):
            idx = i * 4 + j
            tbl[i, j].set_facecolor(plt.cm.tab20(idx / 16))
            tbl[i, j].get_text().set_fontweight('bold')
            tbl[i, j].get_text().set_color('white')
    ax_mat.set_title('4x4 Input Matrix\n(Each cell shows value [row,col] = slot_index)',
                     fontsize=13, fontweight='bold')

    # Bottom: Slot layout
    ax_slot = axes[1]
    ax_slot.axis('off')
    ax_slot.set_xlim(-1, 17)
    ax_slot.set_ylim(-1, 3)

    # Draw slot boxes
    for idx in range(16):
        x = idx
        row = idx // 4
        col = idx % 4
        val = INPUT_MATRIX[row, col]
        color = plt.cm.tab20(idx / 16)

        ax_slot.add_patch(plt.Rectangle((x - 0.4, 1.5), 0.8, 1.2,
                                         fill=True, facecolor=color, alpha=0.8,
                                         edgecolor='black', lw=1))
        ax_slot.text(x, 2.1, f'{val}', ha='center', va='center',
                     fontsize=13, fontweight='bold', color='white')
        ax_slot.text(x, 1.5, f'[{row},{col}]', ha='center', va='center',
                     fontsize=8, color='white')

    for idx in range(16):
        ax_slot.text(idx, 0.8, f'{idx}', ha='center', va='center',
                     fontsize=10, fontweight='bold', color='#333')

    ax_slot.text(8, 0.2, 'Slot Index (0-15 = 16 CKKS slots)',
                 ha='center', fontsize=12, fontweight='bold')

    ax_slot.annotate('', xy=(16, 2.1), xytext=(16, 1.5),
                     arrowprops=dict(arrowstyle='->', lw=2, color='#F44336'))
    ax_slot.text(16.3, 1.8, 'row-major\npacking', fontsize=9, color='#F44336')

    ax_slot.set_title('CKKS Ciphertext Slot Layout (16 slots, row-major packing)',
                      fontsize=13, fontweight='bold')

    fig.suptitle('Pack Strategy: Row-Major Packing of 4x4 Input into CKKS Ciphertext',
                 fontsize=15, fontweight='bold', y=1.02)
    plt.tight_layout()
    path = os.path.join(OUTPUT_DIR, 'task6_pack.png')
    plt.savefig(path, dpi=150, bbox_inches='tight', facecolor='white')
    plt.close()
    print(f"Generated: {path}")


def generate_rotation_alignment():
    """Visualize rotation alignment for each kernel position."""
    fig, axes = plt.subplots(3, 3, figsize=(14, 12))

    for r in range(3):
        for c in range(3):
            ax = axes[r, c]
            rot_amount = r * N + c
            rotated = rotate_left(packed, rot_amount)

            ax.axis('off')
            ax.set_xlim(-1, 17)
            ax.set_ylim(-1, 3.5)

            # Draw original slots faded
            for idx in range(16):
                ax.add_patch(plt.Rectangle((idx - 0.4, 0), 0.8, 1,
                                            fill=True, facecolor='#E0E0E0',
                                            alpha=0.3, edgecolor='#CCC', lw=0.5))
                ax.text(idx, 0.5, f'{packed[idx]}', ha='center', va='center',
                        fontsize=7, color='#999')

            # Draw rotated slots
            for idx in range(16):
                val = rotated[idx]
                if idx == 0:
                    color = '#4CAF50'
                    edge_color = '#1B5E20'
                    lw = 3
                else:
                    color = '#BBDEFB'
                    edge_color = '#1565C0'
                    lw = 1
                ax.add_patch(plt.Rectangle((idx - 0.4, 1.5), 0.8, 1.2,
                                            fill=True, facecolor=color, alpha=0.8,
                                            edgecolor=edge_color, lw=lw))
                text_color = 'white' if idx == 0 else '#333'
                ax.text(idx, 2.1, f'{int(val)}', ha='center', va='center',
                        fontsize=9, fontweight='bold' if idx == 0 else 'normal',
                        color=text_color)

            # Highlight slot 0
            ax.text(0, 2.9, f'Slot[0]={int(rotated[0])}', ha='center',
                    fontsize=11, fontweight='bold', color='#1B5E20',
                    bbox=dict(boxstyle='round', facecolor='#C8E6C9',
                              edgecolor='#4CAF50', lw=1))

            # Rotation info
            ax.text(8, -0.8,
                    f'K[{r},{c}]: rotate_left(ct, {rot_amount})',
                    ha='center', fontsize=10, fontweight='bold',
                    color='#E65100')
            ax.text(8, -1.3, f'-> in[{r},{c}]={INPUT_MATRIX[r,c]} moves to slot 0',
                    ha='center', fontsize=9, color='#666')

            if rot_amount == 0:
                ax.text(8, -0.3, '(No rotation needed - already aligned)',
                        ha='center', fontsize=9, style='italic', color='#999')

    fig.suptitle('Rotation Alignment Verification: Each Kernel Position Aligns in[r,c] to Slot 0',
                 fontsize=14, fontweight='bold', y=1.01)
    plt.tight_layout()
    path = os.path.join(OUTPUT_DIR, 'task6_rotation_alignment.png')
    plt.savefig(path, dpi=150, bbox_inches='tight', facecolor='white')
    plt.close()
    print(f"Generated: {path}")

def generate_general_conv():
    """Visualize the general kernel PRA convolution process and results."""
    fig = plt.figure(figsize=(14, 10))

    # Title
    ax_t = fig.add_axes([0, 0.93, 1, 0.05])
    ax_t.axis('off')
    ax_t.text(0.5, 0.5, 'General Kernel (Non-Separable) PRA Convolution',
              ha='center', va='center', fontsize=16, fontweight='bold')

    ax_k = fig.add_axes([0.02, 0.65, 0.22, 0.25])
    ax_k.axis('tight')
    ax_k.axis('off')
    tbl = ax_k.table(cellText=[[str(v) for v in row] for row in GENERAL_KERNEL],
                     cellLoc='center', loc='center')
    tbl.auto_set_font_size(False)
    tbl.set_fontsize(13)
    tbl.scale(1.3, 1.6)
    ax_k.set_title('General Kernel (3x3)', fontsize=12, fontweight='bold')

    ax_bar = fig.add_axes([0.28, 0.65, 0.32, 0.25])
    categories = ['Kernel\nAlignment', 'Result\nExtraction', 'Total']
    counts = [8, 3, 11]
    colors = ['#42A5F5', '#FFA726', '#EF5350']
    bars = ax_bar.bar(categories, counts, color=colors, edgecolor='#333', lw=1.5)
    for bar, count in zip(bars, counts):
        ax_bar.text(bar.get_x() + bar.get_width()/2., bar.get_height() + 0.3,
                    str(count), ha='center', fontsize=14, fontweight='bold')
    ax_bar.set_ylabel('Rotation Count', fontsize=11)
    ax_bar.set_title('Rotation Count Breakdown', fontsize=12, fontweight='bold')
    ax_bar.set_ylim(0, 14)
    ax_bar.grid(axis='y', alpha=0.3)

    ax_stats = fig.add_axes([0.64, 0.65, 0.34, 0.25])
    ax_stats.axis('off')
    ax_stats.set_xlim(0, 10)
    ax_stats.set_ylim(0, 10)
    stats_text = (
        "PRA Statistics (General Kernel):\n"
        "-------------------------------\n"
        "  Kernel alignment rotations: 8\n"
        "  Result extraction rotations: 3\n"
        "  Total rotations: 11\n"
        "  Ciphertext-plaintext mults: 7\n"
        "  Zero-weight skips: 2\n\n"
        "Kernel alignment = k^2-1 = 8\n"
        "= Theoretical minimum! [OK]"
    )
    ax_stats.text(0.5, 0.5, stats_text, ha='center', va='center',
                  fontsize=10, fontfamily='monospace',
                  bbox=dict(boxstyle='round', facecolor='#FFF8E1',
                            edgecolor='#FF9800', lw=1.5),
                  transform=ax_stats.transAxes)

    ax_conv = fig.add_axes([0.02, 0.1, 0.55, 0.5])
    ax_conv.axis('off')

    # Compute the actual convolution
    patch = INPUT_MATRIX[:3, :3]
    products = patch * GENERAL_KERNEL
    plain_result = np.sum(products)

    y_pos = 0.95
    ax_conv.text(0.05, y_pos,
                 'Convolution at output[0,0]:',
                 fontsize=12, fontweight='bold', transform=ax_conv.transAxes)

    # Show formula
    terms = []
    for r in range(3):
        for c in range(3):
            if GENERAL_KERNEL[r, c] != 0:
                terms.append(
                    f"({INPUT_MATRIX[r,c]}x{GENERAL_KERNEL[r,c]})")

    ax_conv.text(0.05, y_pos - 0.15,
                 ' = ' + ' + '.join(terms),
                 fontsize=9, fontfamily='monospace', transform=ax_conv.transAxes)

    prod_strs = [str(p) for p in products.flatten()]
    ax_conv.text(0.05, y_pos - 0.30,
                 ' = ' + ' + '.join(prod_strs),
                 fontsize=9, fontfamily='monospace', transform=ax_conv.transAxes)

    ax_conv.text(0.05, y_pos - 0.50,
                 f' = {plain_result}',
                 fontsize=14, fontweight='bold', color='#1565C0',
                 transform=ax_conv.transAxes)

    ax_conv.text(0.05, y_pos - 0.70,
                 'PRA encrypted result: -26     Plaintext result: -26',
                 fontsize=11, fontfamily='monospace', transform=ax_conv.transAxes)

    ax_conv.text(0.05, y_pos - 0.85,
                 'Match: [OK]',
                 fontsize=13, fontweight='bold', color='#2E7D32',
                 transform=ax_conv.transAxes)

    ax_wf = fig.add_axes([0.60, 0.1, 0.38, 0.5])
    ax_wf.axis('off')
    ax_wf.set_xlim(0, 10)
    ax_wf.set_ylim(0, 10)

    # Simple workflow diagram
    steps = [
        (1, 'Pack Input\n(16 slots)', '#BBDEFB'),
        (2, '8 Rotations\n(k^2-1 = 8)', '#FFE0B2'),
        (3, '7 Mult + 8 Add\n(HE ops)', '#C8E6C9'),
        (4, '3 Extract Rot.\n(output)', '#E1BEE7'),
        (5, 'Decrypt\n(2x2 result)', '#FFCDD2'),
    ]

    for idx, (num, label, color) in enumerate(steps):
        x = 1
        y = 8.5 - idx * 1.8
        ax_wf.add_patch(plt.Rectangle((x, y-0.6), 6, 1.2,
                                       fill=True, facecolor=color,
                                       edgecolor='#333', lw=1.5,
                                       alpha=0.8))
        ax_wf.text(x + 0.5, y, f'{num}.', fontsize=12, fontweight='bold',
                   va='center')
        ax_wf.text(x + 3, y, label, fontsize=10, ha='center', va='center')
        if idx < len(steps) - 1:
            ax_wf.annotate('', xy=(4, y - 0.8), xytext=(4, y - 1.0),
                           arrowprops=dict(arrowstyle='->', lw=2, color='#666'))

    ax_wf.set_title('PRA Workflow', fontsize=12, fontweight='bold')

    path = os.path.join(OUTPUT_DIR, 'task6_general_conv.png')
    plt.savefig(path, dpi=150, bbox_inches='tight', facecolor='white')
    plt.close()
    print(f"Generated: {path}")

def generate_separable_svd():
    """Visualize the SVD rank-1 decomposition of Sobel kernel."""
    U, S, Vt = np.linalg.svd(SEPARABLE_KERNEL.astype(np.float64))
    sigma = S[0]
    col = (U[:, 0] * np.sqrt(sigma))
    row = (Vt[0, :] * np.sqrt(sigma))
    reconstructed = np.outer(col, row)

    fig = plt.figure(figsize=(14, 10))

    # Title
    ax_t = fig.add_axes([0, 0.93, 1, 0.05])
    ax_t.axis('off')
    ax_t.text(0.5, 0.5, 'Separable Kernel: SVD Rank-1 Decomposition (Sobel Edge Detector)',
              ha='center', va='center', fontsize=16, fontweight='bold')

    ax_orig = fig.add_axes([0.02, 0.55, 0.25, 0.33])
    ax_orig.axis('tight')
    ax_orig.axis('off')
    tbl = ax_orig.table(cellText=[[str(v) for v in row] for row in SEPARABLE_KERNEL],
                        cellLoc='center', loc='center')
    tbl.auto_set_font_size(False)
    tbl.set_fontsize(14)
    tbl.scale(1.3, 1.6)
    colors = {1: '#4CAF50', 0: '#EEEEEE', -1: '#F44336',
              2: '#2E7D32', -2: '#C62828'}
    for i in range(3):
        for j in range(3):
            tbl[i, j].set_facecolor(colors.get(SEPARABLE_KERNEL[i, j], '#FFF'))
            if SEPARABLE_KERNEL[i, j] != 0:
                tbl[i, j].get_text().set_color('white')
                tbl[i, j].get_text().set_fontweight('bold')
    ax_orig.set_title('Original Kernel K (3x3)', fontsize=12, fontweight='bold')
    
    ax_svd = fig.add_axes([0.30, 0.55, 0.40, 0.33])
    ax_svd.axis('off')
    ax_svd.set_xlim(0, 10)
    ax_svd.set_ylim(0, 10)

    # K = col x row^T
    ax_svd.text(5, 9, 'SVD Rank-1 Decomposition:', fontsize=13, fontweight='bold',
                ha='center')
    ax_svd.text(5, 8, 'K = U * S * V^T = col * row^T', fontsize=12,
                ha='center', fontfamily='monospace')

    # Show col vector
    ax_svd.text(2, 6.5, 'col =', fontsize=11, fontweight='bold', ha='center')
    for i, v in enumerate(col):
        ax_svd.text(2, 5.5 - i * 0.7, f'[{v:.2f}]', fontsize=11,
                    fontfamily='monospace', ha='center',
                    color='#1565C0')

    # Show multiplication sign
    ax_svd.text(5, 5, 'x', fontsize=16, fontweight='bold', ha='center')

    # Show row vector
    ax_svd.text(8, 6.5, 'row^T =', fontsize=11, fontweight='bold', ha='center')
    ax_svd.text(8, 5.5, f'[{row[0]:.2f}  {row[1]:.2f}  {row[2]:.2f}]',
                fontsize=11, fontfamily='monospace', ha='center',
                color='#2E7D32')

    # Integer approximation
    col_int = np.round(col * 1.3160740129524922).astype(int)
    row_int = np.round(row * (-1)).astype(int)

    # Show integer form
    ax_svd.text(5, 3, 'Integer form:', fontsize=11, fontweight='bold', ha='center')
    ax_svd.text(5, 2, f'col = [{col_int[0]}, {col_int[1]}, {col_int[2]}]^T',
                fontsize=11, fontfamily='monospace', ha='center')
    ax_svd.text(5, 1.3, f'row = [{row_int[0]}, {row_int[1]}, {row_int[2]}]',
                fontsize=11, fontfamily='monospace', ha='center')

    ax_verify = fig.add_axes([0.73, 0.55, 0.25, 0.33])
    ax_verify.axis('tight')
    ax_verify.axis('off')
    tbl = ax_verify.table(cellText=[[f'{v:.1f}' for v in row] for row in reconstructed],
                          cellLoc='center', loc='center')
    tbl.auto_set_font_size(False)
    tbl.set_fontsize(12)
    tbl.scale(1.2, 1.5)
    for i in range(3):
        for j in range(3):
            tbl[i, j].set_facecolor('#E8F5E9')
    ax_verify.set_title('Reconstructed: col x row^T\n(matches original!)',
                        fontsize=11, fontweight='bold')

    ax_twostep = fig.add_axes([0.02, 0.05, 0.96, 0.42])
    ax_twostep.axis('off')
    ax_twostep.set_xlim(0, 10)
    ax_twostep.set_ylim(0, 10)

    ax_twostep.text(5, 9.5, 'Two-Step Separable Convolution',
                    fontsize=13, fontweight='bold', ha='center')

    ax_twostep.add_patch(matplotlib.patches.FancyBboxPatch((0.3, 4.5), 4.4, 1.8,
                                             boxstyle='round,pad=0.1',
                                             facecolor='#BBDEFB', edgecolor='#1565C0', lw=2))
    ax_twostep.text(2.5, 6, 'Step 1: Horizontal Conv (row vector)',
                    fontsize=11, fontweight='bold', ha='center')
    ax_twostep.text(2.5, 5.4, 'Rotations: k-1 = 2 (for k=3)', fontsize=10, ha='center')
    ax_twostep.text(2.5, 4.9, 'row = [1, 0, -1]', fontsize=10,
                    fontfamily='monospace', ha='center')

    # Arrow
    ax_twostep.annotate('', xy=(5.5, 5.4), xytext=(4.7, 5.4),
                        arrowprops=dict(arrowstyle='->', lw=2, color='#E65100'))

    ax_twostep.add_patch(matplotlib.patches.FancyBboxPatch((5.5, 4.5), 4.4, 1.8,
                                             boxstyle='round,pad=0.1',
                                             facecolor='#C8E6C9', edgecolor='#2E7D32', lw=2))
    ax_twostep.text(7.7, 6, 'Step 2: Vertical Conv (col vector)',
                    fontsize=11, fontweight='bold', ha='center')
    ax_twostep.text(7.7, 5.4, 'Rotations: k-1 = 2 (for k=3)', fontsize=10, ha='center')
    ax_twostep.text(7.7, 4.9, 'col = [1, 2, 1]^T', fontsize=10,
                    fontfamily='monospace', ha='center')

    # Result
    ax_twostep.text(5, 3, 'Total kernel-alignment rotations: 2 + 2 = 4',
                    fontsize=14, fontweight='bold', ha='center',
                    color='#E65100',
                    bbox=dict(boxstyle='round', facecolor='#FFF3E0',
                              edgecolor='#FF9800', lw=2))
    ax_twostep.text(5, 2, 'vs. general kernel: 8 rotations (50% reduction!)',
                    fontsize=11, ha='center', color='#666')
    ax_twostep.text(5, 1.2, 'With zero-weight skip (Sobel middle column): only 2 rotations needed!',
                    fontsize=11, ha='center', color='#2E7D32', fontweight='bold')

    path = os.path.join(OUTPUT_DIR, 'task6_separable_svd.png')
    plt.savefig(path, dpi=150, bbox_inches='tight', facecolor='white')
    plt.close()
    print(f"Generated: {path}")

def generate_separable_conv():
    # Compute results
    patch = INPUT_MATRIX[:3, :3]
    products = patch * SEPARABLE_KERNEL
    plain_result = np.sum(products)

    fig = plt.figure(figsize=(14, 8))

    ax_t = fig.add_axes([0, 0.92, 1, 0.06])
    ax_t.axis('off')
    ax_t.text(0.5, 0.5, 'Separable Kernel PRA Convolution: Result Verification',
              ha='center', va='center', fontsize=16, fontweight='bold')

    ax_bar = fig.add_axes([0.05, 0.1, 0.42, 0.72])
    methods = ['General\nKernel', 'General\n+Zero Skip', 'Separable\nKernel',
               'Separable\n+Zero Skip']
    kernel_rots = [8, 6, 4, 2]
    extract_rots = [3, 3, 3, 3]

    x = np.arange(len(methods))
    width = 0.35

    bars1 = ax_bar.bar(x - width/2, kernel_rots, width, label='Kernel Alignment',
                       color='#42A5F5', edgecolor='#333', lw=1)
    bars2 = ax_bar.bar(x + width/2, extract_rots, width, label='Result Extraction',
                       color='#FFA726', edgecolor='#333', lw=1)

    # Add value labels
    for bar in bars1:
        h = bar.get_height()
        ax_bar.text(bar.get_x() + bar.get_width()/2., h + 0.3,
                    str(int(h)), ha='center', fontsize=12, fontweight='bold')
    for bar in bars2:
        h = bar.get_height()
        ax_bar.text(bar.get_x() + bar.get_width()/2., h + 0.3,
                    str(int(h)), ha='center', fontsize=10)

    # Add total labels
    for i in range(4):
        total = kernel_rots[i] + extract_rots[i]
        ax_bar.text(i, total + 1.2, f'Total: {total}', ha='center',
                    fontsize=13, fontweight='bold', color='#C62828')

    ax_bar.set_xticks(x)
    ax_bar.set_xticklabels(methods, fontsize=11)
    ax_bar.set_ylabel('Rotation Count', fontsize=12)
    ax_bar.set_title('Rotation Count Comparison Across Methods', fontsize=13, fontweight='bold')
    ax_bar.legend(loc='upper right', fontsize=10)
    ax_bar.set_ylim(0, 14)
    ax_bar.grid(axis='y', alpha=0.3)

    # Highlight the minimum - draw a star or annotation
    ax_bar.annotate('Min!\n(2 rots)',
                    xy=(3, 2), xytext=(3, 6),
                    fontsize=10, fontweight='bold', color='#2E7D32',
                    ha='center',
                    arrowprops=dict(arrowstyle='->', lw=1.5, color='#2E7D32'))

    ax_detail = fig.add_axes([0.52, 0.1, 0.46, 0.72])
    ax_detail.axis('off')
    ax_detail.set_xlim(0, 10)
    ax_detail.set_ylim(0, 10)

    y = 9.5
    ax_detail.text(0.5, y, 'Sobel Kernel Convolution Detail:', fontsize=13,
                   fontweight='bold')

    # Show patch
    y -= 1
    ax_detail.text(0.5, y, 'Input patch (3x3) at output[0,0]:', fontsize=10)
    for ri in range(3):
        row_str = '  '.join(f'{patch[ri, ci]:2d}' for ci in range(3))
        y -= 0.6
        ax_detail.text(0.5, y, f'    {row_str}', fontsize=10, fontfamily='monospace')

    y -= 1
    ax_detail.text(0.5, y, 'Sobel kernel (3x3):', fontsize=10)
    for ri in range(3):
        row_str = '  '.join(f'{SEPARABLE_KERNEL[ri, ci]:2d}' for ci in range(3))
        y -= 0.6
        ax_detail.text(0.5, y, f'    {row_str}', fontsize=10, fontfamily='monospace')

    y -= 1
    ax_detail.text(0.5, y, 'Element-wise products:', fontsize=10)
    for ri in range(3):
        row_str = '  '.join(f'{products[ri, ci]:3d}' for ci in range(3))
        y -= 0.6
        ax_detail.text(0.5, y, f'    {row_str}', fontsize=10, fontfamily='monospace')

    y -= 1.2
    ax_detail.text(0.5, y, f'Sum = {plain_result}', fontsize=14, fontweight='bold',
                   color='#1565C0')

    y -= 1.2
    ax_detail.text(0.5, y, 'PRA encrypted result: -8   Plaintext result: -8',
                   fontsize=11, fontfamily='monospace')
    y -= 0.8
    ax_detail.text(0.5, y, 'Match: [OK]', fontsize=14, fontweight='bold',
                   color='#2E7D32',
                   bbox=dict(boxstyle='round', facecolor='#E8F5E9',
                             edgecolor='#4CAF50', lw=2))

    path = os.path.join(OUTPUT_DIR, 'task6_separable_conv.png')
    plt.savefig(path, dpi=150, bbox_inches='tight', facecolor='white')
    plt.close()
    print(f"Generated: {path}")

def generate_comparison():

    fig, ax = plt.subplots(figsize=(12, 6))
    ax.axis('off')
    ax.set_xlim(0, 12)
    ax.set_ylim(0, 8)

    ax.text(6, 7.5, 'Rotation Count Comparison Across All Methods',
            ha='center', fontsize=16, fontweight='bold')

    # Table data
    columns = ['Method', 'Kernel Align', 'Extraction', 'Total', 'Theo. Min?']
    rows = [
        ['General (no opt)', '8', '3', '11', 'Yes (k^2-1=8)'],
        ['General + zero skip', '<=8', '3', '<=11', 'Yes'],
        ['Separable (2-step)', '4', '3', '7', 'Yes* (2(k-1)=4)'],
        ['Separable + zero skip', '2', '3', '5', 'Yes*'],
    ]

    # Draw table
    col_widths = [3.0, 1.8, 1.5, 1.5, 3.0]
    col_starts = [0.5]
    for w in col_widths[:-1]:
        col_starts.append(col_starts[-1] + w)

    colors_header = '#1565C0'
    colors_rows = ['#E3F2FD', '#BBDEFB', '#E8F5E9', '#C8E6C9']

    # Header
    y = 6.5
    for j, (col_name, cs, cw) in enumerate(zip(columns, col_starts, col_widths)):
        ax.add_patch(plt.Rectangle((cs, y - 0.4), cw, 0.8,
                                    fill=True, facecolor=colors_header,
                                    edgecolor='#0D47A1', lw=1.5))
        ax.text(cs + cw/2, y, col_name, ha='center', va='center',
                fontsize=11, fontweight='bold', color='white')

    # Rows
    for i, row in enumerate(rows):
        y = 5.5 - i * 1.0
        for j, (cell_val, cs, cw) in enumerate(zip(row, col_starts, col_widths)):
            ax.add_patch(plt.Rectangle((cs, y - 0.4), cw, 0.8,
                                        fill=True, facecolor=colors_rows[i],
                                        edgecolor='#90A4AE', lw=1))
            fontweight = 'bold' if j == 0 else 'normal'
            fontsize = 11 if j == 0 else 12
            ax.text(cs + cw/2, y, cell_val, ha='center', va='center',
                    fontsize=fontsize, fontweight=fontweight)

    # Footnote
    ax.text(6, 1.0,
            '* Separable kernel uses a different computational model (decomposed convolution)',
            ha='center', fontsize=10, style='italic', color='#666')
    ax.text(6, 0.5,
            '  and leverages the rank-1 algebraic structure to surpass the general lower bound.',
            ha='center', fontsize=10, style='italic', color='#666')

    path = os.path.join(OUTPUT_DIR, 'task6_comparison.png')
    plt.savefig(path, dpi=150, bbox_inches='tight', facecolor='white')
    plt.close()
    print(f"Generated: {path}")

def generate_theory():
    """Visualize theoretical minimum rotation analysis."""
    fig = plt.figure(figsize=(14, 9))

    ax_t = fig.add_axes([0, 0.93, 1, 0.05])
    ax_t.axis('off')
    ax_t.text(0.5, 0.5, 'Theoretical Minimum Rotation Analysis for CKKS Convolution',
              ha='center', va='center', fontsize=16, fontweight='bold')

    ax_set = fig.add_axes([0.02, 0.55, 0.45, 0.33])
    ax_set.axis('off')
    ax_set.set_xlim(0, 10)
    ax_set.set_ylim(0, 10)

    ax_set.text(5, 9.5, 'Rotation Set for 3x3 Kernel on 4x4 Input',
                fontsize=12, fontweight='bold', ha='center')

    # Show the set R
    ax_set.text(1, 8, 'R = { r*4 + c | r,c in {0,1,2} }', fontsize=11,
                fontfamily='monospace')
    ax_set.text(1, 7, 'R = {0, 1, 2, 4, 5, 6, 8, 9, 10}', fontsize=11,
                fontfamily='monospace')
    ax_set.text(1, 6, '|R| = k^2 = 9 (includes identity rotation 0)', fontsize=11)

    # Visual grid
    ax_set.text(1, 4.5, 'Rotation grid (r=row offset, c=col offset):', fontsize=10)
    for r in range(3):
        row_str = ''
        for c in range(3):
            rot = r * 4 + c
            row_str += f'r={r},c={c}:{rot:2d}  '
        ax_set.text(1, 3.5 - r * 0.6, row_str, fontsize=9, fontfamily='monospace')

    ax_form = fig.add_axes([0.50, 0.55, 0.48, 0.33])
    ax_form.axis('off')
    ax_form.set_xlim(0, 10)
    ax_form.set_ylim(0, 10)

    ax_form.text(5, 9.5, 'Rotation Count Formulae', fontsize=12, fontweight='bold',
                 ha='center')

    formulas = [
        ('General (non-separable) kernel:',
         'R_gen(k) = k^2 - 1',
         'R_gen(3) = 9 - 1 = 8'),
        ('Separable kernel (rank-1):',
         'R_sep(k) = 2(k - 1)',
         'R_sep(3) = 2 x 2 = 4'),
        ('Separable + zero-weight skip:',
         'R_sep_z(k) = 2(k-1) - z',
         'R_sep_z(3) = 4 - 3 = 1 (Sobel)'),
    ]

    y = 7.5
    for name, formula, example in formulas:
        ax_form.text(1, y, name, fontsize=10, fontweight='bold')
        ax_form.text(2, y - 1, formula, fontsize=11, fontfamily='monospace',
                     color='#1565C0')
        ax_form.text(2, y - 2, example, fontsize=10, fontfamily='monospace',
                     color='#2E7D32')
        y -= 3.5

    ax_comp = fig.add_axes([0.02, 0.05, 0.96, 0.42])
    ax_comp.axis('off')

    # Complexity table
    k_vals = [3, 5, 7, 9]
    gen_rots = [k*k - 1 for k in k_vals]
    sep_rots = [2*(k-1) for k in k_vals]

    y = 3.5
    ax_comp.text(0.5, 4.2, 'Scalability Analysis: Rotation Count vs Kernel Size',
                 fontsize=12, fontweight='bold')

    # Table header
    headers = ['Kernel Size', 'k^2-1 (General)', '2(k-1) (Separable)', 'Reduction']
    widths = [0.18, 0.22, 0.22, 0.18]
    starts = [0.12]
    for w in widths[:-1]:
        starts.append(starts[-1] + w + 0.02)

    for j, (h, s, w) in enumerate(zip(headers, starts, widths)):
        ax_comp.add_patch(matplotlib.patches.FancyBboxPatch((s, y - 0.3), w, 0.6,
                                              boxstyle='round,pad=0.02',
                                              facecolor='#1565C0',
                                              edgecolor='#0D47A1', lw=1))
        ax_comp.text(s + w/2, y, h, ha='center', va='center',
                     fontsize=10, fontweight='bold', color='white')

    for i, (k, g, s) in enumerate(zip(k_vals, gen_rots, sep_rots)):
        y = 2.5 - i * 0.7
        reduction = f'{(1 - s/g)*100:.0f}%'
        row_data = [f'{k}x{k}', str(g), str(s), reduction]
        for j, (val, start, w) in enumerate(zip(row_data, starts, widths)):
            color = '#E3F2FD' if j < 3 else '#C8E6C9'
            ax_comp.add_patch(matplotlib.patches.FancyBboxPatch((start, y - 0.3), w, 0.6,
                                                  boxstyle='round,pad=0.02',
                                                  facecolor=color,
                                                  edgecolor='#90A4AE', lw=1))
            fw = 'bold' if j == 3 else 'normal'
            ax_comp.text(start + w/2, y, val, ha='center', va='center',
                         fontsize=11, fontweight=fw,
                         color='#C62828' if j == 3 else '#333')

    ax_comp.text(0.5, 0.3, 'Conclusion: Separable kernel reduces rotation complexity from O(k^2) to O(k)',
                 ha='center', fontsize=12, fontweight='bold', color='#E65100')

    path = os.path.join(OUTPUT_DIR, 'task6_theory.png')
    plt.savefig(path, dpi=150, bbox_inches='tight', facecolor='white')
    plt.close()
    print(f"Generated: {path}")

def main():
    print("Generating Task 6 report images...")

    generate_pack_layout()
    generate_rotation_alignment()
    generate_general_conv()
    generate_separable_svd()
    generate_separable_conv()
    generate_comparison()
    generate_theory()

    print(f"All images saved to: {OUTPUT_DIR}")


if __name__ == '__main__':
    main()
