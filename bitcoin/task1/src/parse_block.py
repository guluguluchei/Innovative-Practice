# -*- coding: utf-8 -*-

import sys

from btc_common import (Cursor, read_varint, double_sha256, le_bytes_to_int,
                        http_get, http_get_bytes)
from parse_tx import parse_transaction

API = "https://blockstream.info/testnet/api"


def bits_to_target(bits: int) -> int:
    exponent = bits >> 24
    mantissa = bits & 0xFFFFFF
    return mantissa * (1 << (8 * (exponent - 3)))


def parse_block_header(raw80: bytes):
    cur = Cursor(raw80)
    fields = []

    def add(name, chunk, meaning):
        offset = cur.pos - len(chunk)
        fields.append((offset, chunk, name, meaning))

    version = cur.read(4)
    add("版本号 Version", version, f"版本 = {le_bytes_to_int(version)}(声明遵循的协议规则集)")

    prev = cur.read(32)
    add("前区块哈希 Prev block hash", prev,
        f"上一个区块的哈希(显示序):{prev[::-1].hex()} —— 这就是把区块连成链的那根「链条」")

    merkle = cur.read(32)
    add("默克尔根 Merkle root", merkle,
        f"本区块所有交易压缩成的单一哈希(显示序):{merkle[::-1].hex()}")

    ts = cur.read(4)
    t = le_bytes_to_int(ts)
    import datetime
    utc = datetime.datetime.fromtimestamp(t, datetime.timezone.utc)
    add("时间戳 Timestamp", ts, f"出块时间 = {t}(UTC {utc:%Y-%m-%d %H:%M:%S})")

    bits = cur.read(4)
    bits_int = le_bytes_to_int(bits)
    target = bits_to_target(bits_int)
    add("难度目标 Bits", bits, f"压缩难度 = 0x{bits_int:08x};区块哈希必须小于此目标才有效")

    nonce = cur.read(4)
    add("随机数 Nonce", nonce,
        f"矿工不断尝试的随机数 = {le_bytes_to_int(nonce)}(为了凑出符合难度的哈希)")

    block_hash = double_sha256(raw80)[::-1].hex()
    return fields, block_hash, target


def print_header_report(fields, block_hash, target):
    print("=" * 78)
    print("区块头 (80 字节) 逐字段解析")
    print("=" * 78)
    print(f"{'偏移':>4} | {'长度':>4} | {'字节(hex)':<40} | 字段")
    print("-" * 78)
    for offset, chunk, name, meaning in fields:
        h = chunk.hex()
        shown = h if len(h) <= 40 else h[:36] + "..."
        print(f"{offset:>4} | {len(chunk):>4} | {shown:<40} | {name}")
        print(f"{'':>4} | {'':>4} | {'':<40} |   -> {meaning}")
    print("-" * 78)
    hash_int = int(block_hash, 16)
    print(f"算出的区块哈希 : {block_hash}")
    print(f"难度目标 target: {target:064x}")
    ok = hash_int < target
    print(f"PoW 验证        : 区块哈希 {'<' if ok else '>='} 目标  ->  "
          f"{'有效 ✅(工作量证明成立)' if ok else '无效'}")
    print("=" * 78)


def parse_block(raw: bytes):
    header_fields, block_hash, target = parse_block_header(raw[:80])
    print_header_report(header_fields, block_hash, target)

    # 区块头之后:交易数量 (VarInt) + 各笔交易
    cur = Cursor(raw)
    cur.pos = 80
    tx_count, tx_count_raw = read_varint(cur)
    print(f"\n交易数量 Transaction count (偏移 80): "
          f"{tx_count_raw.hex()} -> 本区块含 {tx_count} 笔交易(含 coinbase)\n")

    pos = cur.pos
    for i in range(tx_count):
        one_tx_bytes = raw[pos:]
        fields, info = parse_transaction(one_tx_bytes)
        consumed = info["bytes_consumed"]
        kind = "coinbase(铸币交易)" if i == 0 else "普通交易"
        print("#" * 78)
        print(f"第 {i} 笔交易 [{kind}]  TXID={info['txid']}  "
              f"大小 {consumed} 字节  {info['vin_count']}入/{info['vout_count']}出")
        print("#" * 78)
        # 为节省篇幅,只详细展示前 3 笔;其余只打印摘要
        if i < 3:
            from parse_tx import print_report
            print_report(fields, info)
        pos += consumed
    print(f"\n解析完成:共 {tx_count} 笔交易,区块总长 {len(raw)} 字节,游标停在 {pos}。")


def load_raw_from_args(argv):
    if len(argv) >= 3 and argv[1] == "--hash":
        h = argv[2].strip()
    elif len(argv) >= 3 and argv[1] == "--height":
        h = http_get(f"{API}/block-height/{argv[2].strip()}").strip()
    elif len(argv) >= 2 and not argv[1].startswith("--"):
        return bytes.fromhex(argv[1].strip())
    else:
        # 默认:测试网最新区块
        tip = http_get(f"{API}/blocks/tip/hash").strip()
        h = tip
        print(f"(未指定区块,使用测试网最新区块)")
    print(f"正在下载区块 {h} ...")
    # blockstream 的 /block/<hash>/raw 返回的是二进制,直接取字节。
    return http_get_bytes(f"{API}/block/{h}/raw")


if __name__ == "__main__":
    raw = load_raw_from_args(sys.argv)
    parse_block(raw)
