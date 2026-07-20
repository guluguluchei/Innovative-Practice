# -*- coding: utf-8 -*-

import hashlib
import json
import urllib.request


def double_sha256(raw: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(raw).digest()).digest()


def le_bytes_to_int(b: bytes) -> int:
    return int.from_bytes(b, "little")


class Cursor:
   

    def __init__(self, raw: bytes):
        self.raw = raw
        self.pos = 0

    def read(self, n: int) -> bytes:
        if self.pos + n > len(self.raw):
            raise ValueError(f"数据不足:想读 {n} 字节,偏移 {self.pos},总长 {len(self.raw)}")
        chunk = self.raw[self.pos:self.pos + n]
        self.pos += n
        return chunk

    def peek(self, n: int) -> bytes:
        return self.raw[self.pos:self.pos + n]

    def remaining(self) -> int:
        return len(self.raw) - self.pos


def read_varint(cur: Cursor):
   
    first = cur.read(1)
    prefix = first[0]
    if prefix < 0xFD:
        return prefix, first
    elif prefix == 0xFD:
        data = cur.read(2)
        return le_bytes_to_int(data), first + data
    elif prefix == 0xFE:
        data = cur.read(4)
        return le_bytes_to_int(data), first + data
    else:  # 0xFF
        data = cur.read(8)
        return le_bytes_to_int(data), first + data


def http_get_bytes(url: str) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": "btc-parser/1.0"})
    with urllib.request.urlopen(req, timeout=30) as resp:
        return resp.read()


def http_get(url: str) -> str:
    return http_get_bytes(url).decode("utf-8")


def http_get_json(url: str):
    return json.loads(http_get(url))
