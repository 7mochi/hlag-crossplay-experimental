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


def modify_a2s_info_response(payload: bytes) -> bytes:
    if not payload.startswith(A2S_HEADER):
        return payload

    data = payload[4:]
    if len(data) < 6 or data[0] != 0x49:
        return payload

    idx = 1
    fields = []
    for _ in range(4):
        null_pos = data.find(b"\x00", idx)
        if null_pos == -1:
            return payload
        fields.append(data[idx:null_pos])
        idx = null_pos + 1

    # fields: [protocol, name, map, folder]; game string follows folder
    game_null = data.find(b"\x00", idx)
    if game_null == -1:
        return payload
    # game = data[idx:game_null]
    idx = game_null + 1

    rebuilt = A2S_HEADER + b"\x49"
    rebuilt += bytes([data[1]])
    rebuilt += fields[1] + b"\x00"
    rebuilt += fields[2] + b"\x00"
    rebuilt += fields[0] + b"\x00"
    rebuilt += b"HL" + b"\x00"

    remaining = data[idx:]
    if len(remaining) < 10:
        return payload

    pos = 2
    pos += 7
    port_bytes = struct.pack("<H", AG_PORT)

    rebuilt += remaining[:pos]
    rebuilt += port_bytes
    rebuilt += remaining[pos + 2 :]
    return rebuilt


def modify_connect_packet(payload: bytes) -> bytes:
    if not payload.startswith(A2S_HEADER):
        return payload
    data = payload[4:]
    info_marker = b" /_gd=ag"
    if info_marker in data:
        return payload
    try:
        space_idx = data.index(b" ", 4)
        new_data = data[: space_idx + 1] + b"/_gd=ag " + data[space_idx + 1 :]
        return payload[:4] + new_data
    except ValueError:
        return payload


def process_packet(packet):
    pkt = IP(packet.get_payload())
    if not pkt.haslayer(UDP) or not pkt.haslayer(Raw):
        packet.accept()
        return

    ip_layer = pkt[IP]
    udp_layer = pkt[UDP]
    raw = bytes(pkt[Raw])

    if ip_layer.dst == HL_SERVER_IP and udp_layer.dport == HL_PORT:
        modified = modify_connect_packet(raw)
        if modified is not raw:
            new_pkt = IP(bytes(pkt))
            new_pkt[Raw].load = modified
            del new_pkt[IP].len
            del new_pkt[IP].chksum
            del new_pkt[UDP].len
            del new_pkt[UDP].chksum
            packet.set_payload(bytes(new_pkt))

    elif ip_layer.src == HL_SERVER_IP and udp_layer.sport == HL_PORT:
        modified = modify_a2s_info_response(raw)
        if modified is not raw:
            new_pkt = IP(bytes(pkt))
            new_pkt[Raw].load = modified
            del new_pkt[IP].len
            del new_pkt[IP].chksum
            del new_pkt[UDP].len
            del new_pkt[UDP].chksum
            packet.set_payload(bytes(new_pkt))

    packet.accept()


def main():
    print(f"Starting HL→AG redirect on NFQUEUE {QUEUE_NUM}...")
    nfqueue = NetfilterQueue()
    nfqueue.bind(QUEUE_NUM, process_packet)
    try:
        nfqueue.run()
    except KeyboardInterrupt:
        print("\nShutting down...")
        nfqueue.unbind()


if __name__ == "__main__":
    main()
