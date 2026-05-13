from __future__ import annotations

import struct

from netfilterqueue import NetfilterQueue
from scapy.all import Raw
from scapy.layers.inet import IP
from scapy.layers.inet import UDP

HL_PORT = 29428
AG_PORT = 29420


def rewrite_a2s(payload):
    payload = payload.replace(b"Adrenaline Gamer", b"Half-Life\x00\x00\x00\x00")

    payload = payload.replace(struct.pack("<H", HL_PORT), struct.pack("<H", AG_PORT))

    return payload


def rewrite_connect(payload):
    if b"_gd=ag" not in payload:
        payload += b"\\_gd\\ag"

    return payload


def process(pkt):
    scapy_pkt = IP(pkt.get_payload())

    if not scapy_pkt.haslayer(UDP):
        pkt.accept()
        return

    udp = scapy_pkt[UDP]

    if not scapy_pkt.haslayer(Raw):
        pkt.accept()
        return

    payload = bytes(scapy_pkt[Raw].load)

    if udp.dport == AG_PORT:
        if payload.startswith(b"\xff\xff\xff\xff"):
            if b"connect" in payload:
                new_payload = rewrite_connect(payload)

                scapy_pkt[Raw].load = new_payload

                del scapy_pkt[IP].len
                del scapy_pkt[IP].chksum
                del scapy_pkt[UDP].len
                del scapy_pkt[UDP].chksum

                pkt.set_payload(bytes(scapy_pkt))
    elif udp.sport == HL_PORT:
        if payload.startswith(b"\xff\xff\xff\xff"):
            new_payload = rewrite_a2s(payload)

            scapy_pkt[Raw].load = new_payload

            scapy_pkt[UDP].sport = AG_PORT

            del scapy_pkt[IP].len
            del scapy_pkt[IP].chksum
            del scapy_pkt[UDP].len
            del scapy_pkt[UDP].chksum

            pkt.set_payload(bytes(scapy_pkt))

    pkt.accept()


nfqueue = NetfilterQueue()
nfqueue.bind(10, process)

try:
    print("Running...")
    nfqueue.run()
except KeyboardInterrupt:
    pass
