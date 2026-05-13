#!/usr/bin/env python3
"""HL→AG redirect: intercept NFQUEUE 1, modify connect/A2S packets."""

from __future__ import annotations

import struct

from netfilterqueue import NetfilterQueue
from scapy.all import Raw
from scapy.layers.inet import IP
from scapy.layers.inet import UDP

HL_SERVER_IP = "172.18.0.9"
HL_PORT = 29428
AG_PORT = 29420
QUEUE_NUM = 1

A2S_HEADER = b"\xff\xff\xff\xff"


def read_cstring(data: bytes, offset: int) -> tuple[str, int]:
    """Read a null-terminated string from data starting at offset.
    Returns (string_bytes, offset_after_null)."""
    null = data.find(b"\x00", offset)
    if null == -1:
        raise ValueError("Unterminated string")
    return data[offset:null], null + 1


def modify_connect_packet(payload: bytes) -> bytes:
    """Append ` /_gd=ag` to connect packet info string."""
    if not payload.startswith(A2S_HEADER):
        return payload
    data = payload[4:]
    if not data.startswith(b"connect "):
        return payload
    if b"_gd=ag" in data or b"_gd\\ag" in data:
        return payload

    for suffix in (b"\n", b"\x00"):
        idx = data.rfind(suffix)
        if idx != -1:
            new_data = data[:idx] + b" /_gd=ag" + data[idx:]
            return payload[:4] + new_data
    return payload[:4] + data + b" /_gd=ag"


def modify_a2s_info_source(payload: bytes) -> bytes | None:
    """Rewrite A2S_INFO response in Source format (0x49).

    Fields: header(I) protocol name map folder game id players max bots
            type env vis vac [Ship...] version EDF [port(EDF&0x80) ...]
    """
    data = payload[4:]
    if len(data) < 6 or data[0] != 0x49:
        return None

    offset = 1  # skip header type
    # protocol
    proto = data[offset]
    offset += 1
    # name
    name, offset = read_cstring(data, offset)
    # map
    map_, offset = read_cstring(data, offset)
    # folder
    folder, offset = read_cstring(data, offset)
    # game
    game, offset = read_cstring(data, offset)

    # Rebuild up to and including game
    rebuilt = A2S_HEADER + bytes([0x49, proto])
    rebuilt += name + b"\x00"
    rebuilt += map_ + b"\x00"
    rebuilt += folder + b"\x00"
    rebuilt += b"HL" + b"\x00"

    return rebuilt + data[offset:]


def modify_a2s_info_goldsource(payload: bytes) -> bytes | None:
    """Rewrite A2S_INFO response in GoldSource format (0x6D).

    Fields: header(m) address name map folder game
            players max protocol type env vis mod [mod_info...] vac bots
    """
    data = payload[4:]
    if len(data) < 6 or data[0] != 0x6D:
        return None

    offset = 1
    # address
    address, offset = read_cstring(data, offset)
    # name
    name, offset = read_cstring(data, offset)
    # map
    map_, offset = read_cstring(data, offset)
    # folder
    folder, offset = read_cstring(data, offset)
    # game
    game, offset = read_cstring(data, offset)

    # Rewrite address port: 29428 → 29420
    addr_str = address.decode("ascii", errors="replace")
    if f":{HL_PORT}" in addr_str:
        addr_str = addr_str.replace(f":{HL_PORT}", f":{AG_PORT}")
    elif f":{HL_PORT}" not in addr_str and b":" in address:
        pass
    new_address = addr_str.encode("ascii")

    rebuilt = A2S_HEADER + b"\x6d"
    rebuilt += new_address + b"\x00"
    rebuilt += name + b"\x00"
    rebuilt += map_ + b"\x00"
    rebuilt += folder + b"\x00"
    rebuilt += b"HL" + b"\x00"

    return rebuilt + data[offset:]


def modify_a2s_info_response(payload: bytes) -> bytes:
    result = modify_a2s_info_source(payload)
    if result is not None:
        return result
    result = modify_a2s_info_goldsource(payload)
    if result is not None:
        return result
    return payload


def process_packet(packet):
    pkt = IP(packet.get_payload())
    if not pkt.haslayer(UDP) or not pkt.haslayer(Raw):
        packet.accept()
        return

    ip_layer = pkt[IP]
    udp_layer = pkt[UDP]
    raw = bytes(pkt[Raw])

    modified = None

    if ip_layer.dst == HL_SERVER_IP and udp_layer.dport == HL_PORT:
        modified = modify_connect_packet(raw)

    elif ip_layer.src == HL_SERVER_IP and udp_layer.sport == HL_PORT:
        modified = modify_a2s_info_response(raw)

    if modified is not None and modified is not raw:
        new_pkt = IP(bytes(pkt))
        new_pkt[Raw].load = modified
        del new_pkt[IP].len
        del new_pkt[IP].chksum
        del new_pkt[UDP].len
        del new_pkt[UDP].chksum
        packet.set_payload(bytes(new_pkt))

    packet.accept()


def main():
    print(f"Starting HL->AG redirect on NFQUEUE {QUEUE_NUM}...")
    nfqueue = NetfilterQueue()
    nfqueue.bind(QUEUE_NUM, process_packet)
    try:
        nfqueue.run()
    except KeyboardInterrupt:
        print("\nShutting down...")
        nfqueue.unbind()


if __name__ == "__main__":
    main()
