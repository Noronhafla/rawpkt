from checksum import *

SRC, DST = bytes([192, 168, 0, 1]), bytes([192, 168, 0, 199])
ipv4 =  bytes.fromhex("45000073000040004011b861c0a80001c0a800c7")

def udp(payload, cs=None):
    seg = struct.pack("!HHHH", 5353, 53, 8 + len(payload), 0) + payload
    if cs is None:
         cs =internet_checksum(pseudo_header_v4(SRC,DST, PROTO_UDP, len(seg)) + seg) or 0xFFF
    return seg[:6] + struct.pack("!H", cs) + seg[8:]

def show(nome, r):
    comp = f"0x{r.computed:04X}"
    status = "IGNORADO" if r.skipped else ("OK" if r.valid else "INVALIDO")
    extra = "(provavel offload)" if r.offload_suspected else ""
    print(f"{nome:<28} esperado=0x{r.expected:04X} calculado={comp}  {status}{extra}")

ps = lambda s: pseudo_header_v4(SRC, DST, PROTO_UDP, len(s))
corrompido = bytearray(ipv4); corrompido[8] ^= 0xFF

show("ipv4 valido", verify("ipv4", ipv4, OFFSET_IPV4))
show("ipv4 com ttl corrompido", verify("ipv4", bytes(corrompido), OFFSET_IPV4))

s = udp(b"hello", cs=0x1234)
show("udp valido", verify("udp", s, OFFSET_UDP, ps(s)))

s = udp(b"hello", cs=0)
show("udp/ipv4 com checksum zero", verify("udp", s, OFFSET_UDP, ps(s)))

s = udp(b"hello", cs=0x1234)
show("udp de saida divergente", verify("udp", s, OFFSET_UDP, ps(s), outgoing=True))

s = udp(b"hello", cs=0x1234)
show ("udp de entrada divergente", verify("udp", s, OFFSET_UDP, ps(s)))