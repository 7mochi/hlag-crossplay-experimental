from __future__ import annotations

import struct

from netfilterqueue import NetfilterQueue
from scapy.all import Raw
from scapy.layers.inet import IP
from scapy.layers.inet import UDP


def cb(packet):
    raw = packet.get_payload()
    ip = IP(raw)

    if ip.haslayer(UDP):
        payload = bytes(ip[UDP].payload)

        if payload.startswith(b"\xff\xff\xff\xffconnect "):

            idx = payload.find(b"\n")

            if idx != -1:
                ascii_part = payload[: idx + 1]
                binary_part = payload[idx + 1 :]

                print("=== ASCII ===")
                print(ascii_part)

                print("=== BINARY ===")
                print(binary_part[:32].hex())

    packet.accept()


nf = NetfilterQueue()
nf.bind(30, cb)
nf.run()
