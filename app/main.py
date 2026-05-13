from __future__ import annotations

from netfilterqueue import NetfilterQueue
from scapy.layers.inet import IP
from scapy.layers.inet import UDP
from scapy.packet import Raw

HL_INTERNAL_IP = "172.18.0.11"
HL_PORT = 29428
AG_PORT = 29420
A2S_INFO_RESPONSE = b"\x49"


def is_connectionless(payload: bytes) -> bool:
    return payload.startswith(b"\xff\xff\xff\xff")


def modify_packet(pkt):
    packet = IP(pkt.get_payload())

    if not packet.haslayer(UDP) or not packet.haslayer(Raw):
        pkt.accept()
        return

    payload = bytes(packet[Raw].load)
    modified = False

    if packet[UDP].dport == AG_PORT:
        packet[IP].dst = HL_INTERNAL_IP
        packet[UDP].dport = HL_PORT
        modified = True

        if b"connect" in payload:
            if b"/_gd=ag" in payload:
                payload = payload.replace(b"/_gd=ag", b"/_gd=valve")
            elif b"/_gd=" not in payload:
                payload = payload.rstrip(b"\x00") + b"/_gd=valve\x00"
            packet[Raw].load = payload

    elif packet[UDP].sport == HL_PORT:
        packet[UDP].sport = AG_PORT
        modified = True

        if (
            is_connectionless(payload)
            and len(payload) > 5
            and payload[4:5] == A2S_INFO_RESPONSE
        ):
            payload = payload.replace(b"\x00valve\x00", b"\x00ag\x00")
            payload = payload.replace(b"Half-Life", b"Adrenaline Gamer")
            packet[Raw].load = payload

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
