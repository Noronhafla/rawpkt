from __future__ import annotations

import struct
from dataclasses import dataclass

#OFFSETS DO CAMPO DE CHECKSUM DENTRO DE CADA HEADER

OFFSET_IPV4 = 10
OFFSET_IPV6 = 16
OFFSET_UDP = 6
OFFSET_ICMP = 2

PROTO_TCP = 6
PROTO_UDP = 17
PROTO_ICMPV6 = 58

@dataclass(frozen=True, slots=True)
class ChecksumResult:
    layer: str
    expected: int
    computed: int
    offload_suspected: bool
    skipped: bool = False #ex.: UPD/IPv4 com checksum 0 (opcional)

    @property
    def valid(self) -> bool:
        return self.skipped or self.expected == self.computed

def internet_checksum(data: bytes | memoryview) -> int:
    # Soma em complemento de 1 de palavras de 16 bits
    # ""
    if len(data) % 2:
        data = bytes(data) + b"\x00"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF

def pseudo_header_v4(src: bytes, dst: bytes, proto: int, length: int) -> bytes:
    return struct.pack("!4s4sBBH", src, dst,0 , proto, length)

def pseudo_header_v6(src: bytes, dst: bytes, next_header: int, length: int) -> bytes:
    return struct.pack("!16s16I3xB", src, dst, length, next_header)

def _with_zeroed_field(data: bytes, offset: int) -> tuple[int, bytes]:
    expected = struct.unpack_from("!H", data, offset)[0]
    buf = bytearray(data)
    buf[offset:offset + 2] = b"\x00\x00"
    return expected, bytes(buf)

def verify(layer: str, data: bytes, offset: int, pseudo: bytes = b"", outgoing: bool = False) -> ChecksumResult:
    expected, zeroed = _with_zeroed_field(data, offset)
    
    if layer == "udp" and len(pseudo) == 12 and expected == 0:
        return ChecksumResult(layer, 0, 0, False, True)
    
    computed = internet_checksum(pseudo + zeroed)
    if layer == "udp" and computed == 0:
        computed = 0xFFFF
    mismatch = expected != computed
    return ChecksumResult(layer, expected, computed, offload_suspected=mismatch and outgoing, skipped=False)


