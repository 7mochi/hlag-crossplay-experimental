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

        print("==== PACKET ====")
        print(payload)
        print(payload.hex())

    packet.accept()


nf = NetfilterQueue()
nf.bind(30, cb)
nf.run()
