# -*- coding: utf-8 -*-

import sys

from btc_common import Cursor, read_varint, double_sha256, le_bytes_to_int, http_get


class Field:

    def __init__(self, offset, raw_bytes, name, meaning):
        self.offset = offset
        self.raw = raw_bytes
        self.name = name
        self.meaning = meaning

    def hex(self):
        return self.raw.hex()


def parse_transaction(raw: bytes):
    
    cur = Cursor(raw)
    fields = []

    def add(name, chunk, meaning):
        offset = cur.pos - len(chunk)
        fields.append(Field(offset, chunk, name, meaning))

    version_b = cur.read(4)
    add("版本号 Version", version_b, f"交易版本 = {le_bytes_to_int(version_b)}")

    is_segwit = False
    if cur.peek(2) == b"\x00\x01":
        marker = cur.read(1)
        add("SegWit 标记 Marker", marker, "0x00,表明这是隔离见证交易")
        flag = cur.read(1)
        add("SegWit 标志 Flag", flag, "0x01,隔离见证标志")
        is_segwit = True

    inputs_start = cur.pos
    vin_count, vin_raw = read_varint(cur)
    add("输入数量 Input count", vin_raw, f"共 {vin_count} 个输入")

    for i in range(vin_count):
        prev_hash = cur.read(32)
        add(f"输入#{i} 前交易哈希 Prev txid", prev_hash,
            f"引用的上一笔交易(显示序):{prev_hash[::-1].hex()}")
        prev_index = cur.read(4)
        add(f"输入#{i} 输出索引 Vout", prev_index,
            f"花的是上一笔交易的第 {le_bytes_to_int(prev_index)} 个输出")
        script_len, script_len_raw = read_varint(cur)
        add(f"输入#{i} 解锁脚本长度", script_len_raw, f"解锁脚本 {script_len} 字节")
        script = cur.read(script_len)
        add(f"输入#{i} 解锁脚本 scriptSig", script,
            "解锁脚本(证明你有权花这笔钱;SegWit 交易此处通常为空)"
            if script_len else "空(SegWit 交易的签名放在见证数据里)")
        sequence = cur.read(4)
        add(f"输入#{i} 序列号 Sequence", sequence,
            f"序列号 = 0x{sequence[::-1].hex()}(多用于 RBF/时间锁,一般 0xffffffff)")

    vout_count, vout_raw = read_varint(cur)
    add("输出数量 Output count", vout_raw, f"共 {vout_count} 个输出")

    total_out = 0
    for i in range(vout_count):
        value = cur.read(8)
        sats = le_bytes_to_int(value)
        total_out += sats
        add(f"输出#{i} 金额 Value", value,
            f"{sats} 聪 = {sats / 1e8:.8f} BTC")
        script_len, script_len_raw = read_varint(cur)
        add(f"输出#{i} 锁定脚本长度", script_len_raw, f"锁定脚本 {script_len} 字节")
        script = cur.read(script_len)
        add(f"输出#{i} 锁定脚本 scriptPubKey", script,
            "锁定脚本(规定谁能花这笔钱,即收款条件)")

    inputs_end = cur.pos  # 非见证部分(不含 locktime)在这里结束

    if is_segwit:
        for i in range(vin_count):
            stack_count, stack_raw = read_varint(cur)
            add(f"见证#{i} 元素个数", stack_raw, f"该输入的见证栈有 {stack_count} 个元素")
            for j in range(stack_count):
                item_len, item_len_raw = read_varint(cur)
                add(f"见证#{i}.{j} 元素长度", item_len_raw, f"{item_len} 字节")
                item = cur.read(item_len)
                add(f"见证#{i}.{j} 元素数据", item, "见证数据(签名 / 公钥等)")

    locktime_start = cur.pos
    locktime = cur.read(4)
    lt = le_bytes_to_int(locktime)
    add("锁定时间 Locktime", locktime,
        f"锁定时间 = {lt}" + ("(0 表示立即生效)" if lt == 0 else ""))
    locktime_end = cur.pos

    
    if is_segwit:
        legacy_ser = raw[0:4] + raw[inputs_start:inputs_end] + raw[locktime_start:locktime_end]
    else:
        legacy_ser = raw
    txid = double_sha256(legacy_ser)[::-1].hex()
    wtxid = double_sha256(raw)[::-1].hex()

    info = {
        "is_segwit": is_segwit,
        "vin_count": vin_count,
        "vout_count": vout_count,
        "total_out_sats": total_out,
        "txid": txid,
        "wtxid": wtxid,
        "size_bytes": cur.pos,
        "bytes_consumed": cur.pos,
    }
    return fields, info


def print_report(fields, info):
    print("=" * 78)
    print("比特币交易逐字节解析结果")
    print("=" * 78)
    print(f"交易类型 : {'SegWit(隔离见证)' if info['is_segwit'] else 'Legacy(传统)'}")
    print(f"总大小   : {info['size_bytes']} 字节 (已解析 {info['bytes_consumed']} 字节)")
    print(f"输入/输出: {info['vin_count']} 输入 / {info['vout_count']} 输出")
    print(f"输出总额 : {info['total_out_sats']} 聪 = {info['total_out_sats']/1e8:.8f} BTC")
    print(f"TXID     : {info['txid']}")
    if info["is_segwit"]:
        print(f"wTXID    : {info['wtxid']}")
    print("-" * 78)
    print(f"{'偏移':>5} | {'长度':>4} | {'字节(hex)':<28} | 字段 / 含义")
    print("-" * 78)
    for f in fields:
        h = f.hex()
        shown = h if len(h) <= 28 else h[:24] + "..."
        print(f"{f.offset:>5} | {len(f.raw):>4} | {shown:<28} | {f.name}")
        print(f"{'':>5} | {'':>4} | {'':<28} |   -> {f.meaning}")
    print("=" * 78)


def load_raw_from_args(argv):
    if len(argv) >= 3 and argv[1] == "--txid":
        txid = argv[2].strip()
        url = f"https://blockstream.info/testnet/api/tx/{txid}/hex"
        print(f"正在从测试网下载交易 {txid} ...")
        return bytes.fromhex(http_get(url).strip())
    if len(argv) >= 2:
        return bytes.fromhex(argv[1].strip())
    print("(未提供参数,解析内置示例交易)")
    sample = (
        "0100000001c997a5e56e104102fa209c6a852dd90660a20b2d9c352423edce25857f"
        "cd3704000000004847304402204e45e16932b8af514961a1d3a1a25fdf3f4f7732e9"
        "d624c6c61548ab5fb8cd410220181522ec8eca07de4860a4acdd12909d831cc56cbb"
        "ac4622082221a8768d1d0901ffffffff0200ca9a3b00000000434104ae1a62fe09c5"
        "f51b13905f07f06b99a2f7159b2225f374cd378d71302fa28414e7aab37397f554a7"
        "df5f142c21c1b7303b8a0626f1baded5c72a704f7e6cd84cac00286bee0000000043"
        "410411db93e1dcdb8a016b49840f8c53bc1eb68a382e97b1482ecad7b148a6909a5c"
        "b2e0eaddfb84ccf9744464f82e160bfa9b8b64f9d4c03f999b8643f656b412a3ac00"
        "000000"
    )
    return bytes.fromhex(sample)


if __name__ == "__main__":
    raw = load_raw_from_args(sys.argv)
    fields, info = parse_transaction(raw)
    print_report(fields, info)
