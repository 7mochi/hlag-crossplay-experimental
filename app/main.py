from __future__ import annotations

import struct
import threading

from netfilterqueue import NetfilterQueue
from scapy.all import Raw
from scapy.layers.inet import IP
from scapy.layers.inet import UDP

AG_PORT = 29420
HL_PORT = 29428
HL_IP = "172.18.0.11"


def is_connectionless(payload: bytes) -> bool:
    return payload.startswith(b"\xff\xff\xff\xff")


def process(pkt):
    raw = pkt.get_payload()
    ip = IP(raw)

    if not ip.haslayer(UDP):
        pkt.accept()
        return

    udp = ip[UDP]
    payload = bytes(udp.payload)

    # SOLO tráfico connectionless
    if not is_connectionless(payload):
        pkt.accept()
        return

    # -------------------------
    # CLIENT -> SERVER (AG FAKE PORT)
    # -------------------------
    if udp.dport == AG_PORT:

        # connect spoof fix
        if b"connect" in payload and b"/_gd=ag" not in payload:
            payload = payload + b" /_gd=ag"

        udp.remove_payload()
        udp.add_payload(payload)

        del ip.len
        del ip.chksum
        del udp.len
        del udp.chksum

        pkt.set_payload(bytes(ip))
        pkt.accept()
        return

    # -------------------------
    # SERVER -> CLIENT (HL RESPONSE)
    # -------------------------
    if udp.sport == HL_PORT:

        # spoof port HL -> AG
        payload = payload.replace(
            struct.pack("<H", HL_PORT),
            struct.pack("<H", AG_PORT),
        )

        udp.remove_payload()
        udp.add_payload(payload)

        del ip.len
        del ip.chksum
        del udp.len
        del udp.chksum

        pkt.set_payload(bytes(ip))
        pkt.accept()
        return

    pkt.accept()


def run_queue(q):
    nfq = NetfilterQueue()
    nfq.bind(q, process)
    print(f"[+] queue {q} ready")
    nfq.run()


threading.Thread(target=run_queue, args=(30,), daemon=True).start()
threading.Thread(target=run_queue, args=(31,), daemon=True).start()

print("[*] HL/AG bridge running")

while True:
    pass
