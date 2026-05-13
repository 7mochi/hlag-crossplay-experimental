from __future__ import annotations

import re

from netfilterqueue import NetfilterQueue
from scapy.layers.inet import IP
from scapy.layers.inet import UDP
from scapy.packet import Raw

HL_INTERNAL_IP = "172.18.0.11"
HL_PORT = 29428
AG_PORT = 29420


def is_connectionless(payload: bytes) -> bool:
    return payload.startswith(b"\xff\xff\xff\xff")


def modify_packet(pkt):
    packet = IP(pkt.get_payload())

    if not packet.haslayer(Raw):
        pkt.accept()
        return

    payload = bytes(packet[Raw].load)

    if not is_connectionless(payload):
        pkt.accept()
        return

    modified = False

    if packet.haslayer(UDP) and packet[UDP].dport == AG_PORT:
        if b"connect" in payload:
            if b"\\_gd\\ag" in payload:
                payload = payload.replace(b"\\_gd\\ag", b"\\_gd\\valve")
            elif b"\\_gd\\" not in payload:
                payload += b"\\_gd\\valve"

            packet[Raw].load = payload
            modified = True

    elif packet[IP].src == HL_INTERNAL_IP and packet[UDP].sport == HL_PORT:
        if b"Half-Life" in payload:
            payload = payload.replace(b"Half-Life", b"Adrenaline Gamer")

        if b"valve" in payload:
            payload = payload.replace(b"valve", b"ag")

        packet[UDP].sport = AG_PORT
        packet[Raw].load = payload
        modified = True

    if modified:
        del packet[IP].len
        del packet[IP].chksum
        del packet[UDP].len
        del packet[UDP].chksum

        pkt.set_payload(bytes(packet))

    pkt.accept()


nfqueue = NetfilterQueue()
nfqueue.bind(1, modify_packet)

try:
    nfqueue.run()
except KeyboardInterrupt:
    pass
finally:
    nfqueue.unbind()
