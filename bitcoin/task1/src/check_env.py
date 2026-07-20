# -*- coding: utf-8 -*-
"""
环境自检脚本 
"""
import hashlib
import sys


def double_sha256(raw: bytes) -> bytes:
    """比特币里到处都在用的哈希:对数据做两次 SHA256。"""
    return hashlib.sha256(hashlib.sha256(raw).digest()).digest()


def main() -> int:
    print("Python 版本:", sys.version.split()[0])

    # 创世区块的 80 字节区块头(十六进制)
    genesis_header_hex = (
        "01000000"                                                          # 版本号
        "0000000000000000000000000000000000000000000000000000000000000000"  # 前一区块哈希
        "3ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a"  # Merkle 根
        "29ab5f49"                                                          # 时间戳
        "ffff001d"                                                          # 难度目标 (bits)
        "1dac2b7c"                                                          # 随机数 (nonce)
    )
    header = bytes.fromhex(genesis_header_hex)
    print("区块头字节数:", len(header), "(应为 80)")

    # 区块哈希 = 对区块头做双 SHA256,再把字节顺序反转(小端 -> 显示用大端)
    block_hash = double_sha256(header)[::-1].hex()
    print("算出的区块哈希:", block_hash)

    expected = "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"
    print("公认的创世哈希:", expected)

    if block_hash == expected and len(header) == 80:
        print("\n[OK] 环境检查通过 —— 可以开始做作业了!")
        return 0
    print("\n[FAIL] 结果不一致,请检查环境。")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
