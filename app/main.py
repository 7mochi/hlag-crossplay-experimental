from __future__ import annotations

import struct
import threading

from netfilterqueue import NetfilterQueue
from scapy.all import Raw
from scapy.layers.inet import IP
from scapy.layers.inet import UDP

AG_PORT = 29420
HL_PORT = 29428
REAL_SERVER_IP = "172.18.0.11"


def is_connectionless(payload: bytes) -> bool:
    return payload.startswith(b"\xff\xff\xff\xff")


def patch_connect(payload: bytes) -> bytes:
    # inject AG marker
    if b"connect" in payload and b"/_gd=ag" not in payload:
        payload += b" /_gd=ag"
    return payload


def patch_a2s_response(payload: bytes) -> bytes:
    # spoof HL → AG view
    payload = payload.replace(
        struct.pack("<H", HL_PORT),
        struct.pack("<H", AG_PORT),
    )
    return payload


# -------------------------
# NFQUEUE handler
# -------------------------


def process(pkt):
    raw = pkt.get_payload()

    try:
        ip = IP(raw)
    except:
        pkt.accept()
        return

    if not ip.haslayer(UDP):
        pkt.accept()
        return

    udp = ip[UDP]
    payload = bytes(udp.payload)

    # ignore non game traffic
    if not is_connectionless(payload):
        pkt.accept()
        return

    # ----------------------------------
    # CLIENT -> SERVER (QUEUE 30)
    # ----------------------------------
    if udp.dport == AG_PORT:

        payload = patch_connect(payload)

        if payload != bytes(udp.payload):
            udp.remove_payload()
            udp.add_payload(payload)
            del ip.len, ip.chksum, udp.len, udp.chksum
            pkt.set_payload(bytes(ip))

        pkt.accept()
        return

    # ----------------------------------
    # SERVER -> CLIENT (QUEUE 31)
    # ----------------------------------
    if udp.sport == HL_PORT:

        payload = patch_a2s_response(payload)

        if payload != bytes(udp.payload):
            udp.remove_payload()
            udp.add_payload(payload)
            del ip.len, ip.chksum, udp.len, udp.chksum
            pkt.set_payload(bytes(ip))

        pkt.accept()
        return

    pkt.accept()


# -------------------------
# Workers
# -------------------------


def run_queue(num):
    nfq = NetfilterQueue()
    nfq.bind(num, process)
    print(f"[+] queue {num} ready")
    nfq.run()


threading.Thread(target=run_queue, args=(30,), daemon=True).start()
threading.Thread(target=run_queue, args=(31,), daemon=True).start()

print("[*] HL/AG bridge running")

while True:
    pass
