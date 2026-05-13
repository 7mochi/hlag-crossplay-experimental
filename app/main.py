from __future__ import annotations

import struct
import threading

from netfilterqueue import NetfilterQueue
from scapy.all import Raw
from scapy.layers.inet import IP
from scapy.layers.inet import UDP

HL_IP = "172.18.0.11"
HL_PORT = 29428


def is_connect(payload: bytes) -> bool:
    return payload.startswith(b"\xff\xff\xff\xffconnect")


def is_a2s(payload: bytes) -> bool:
    return payload.startswith(b"\xff\xff\xff\xffT") or payload.startswith(
        b"\xff\xff\xff\xffU",
    )


# ───────── CLIENT → SERVER ─────────
def process_c2s(packet):
    ip = IP(packet.get_payload())

    if not ip.haslayer(UDP):
        packet.accept()
        return

    udp = ip[UDP]
    payload = bytes(udp.payload)

    print(f"[C->S] {ip.src}:{udp.sport} -> {ip.dst}:{udp.dport} len={len(payload)}")

    # SOLO connect real
    if is_connect(payload):
        print("[+] injecting /_gd=ag")

        if b"/_gd=ag" not in payload:
            payload = payload.replace(b"connect", b"connect /_gd=ag", 1)

        ip[UDP].remove_payload()
        ip[UDP].add_payload(payload)

        packet.set_payload(bytes(ip))

    packet.accept()


# ───────── SERVER → CLIENT ─────────
def process_s2c(packet):
    ip = IP(packet.get_payload())

    if not ip.haslayer(UDP):
        packet.accept()
        return

    udp = ip[UDP]
    payload = bytes(udp.payload)

    print(f"[S->C] {ip.src}:{udp.sport} -> {ip.dst}:{udp.dport} len={len(payload)}")

    # SOLO modificar A2S
    if is_a2s(payload):
        payload = payload.replace(b"Half-Life", b"HL/70\x00")

        ip[UDP].remove_payload()
        ip[UDP].add_payload(payload)

        packet.set_payload(bytes(ip))

    packet.accept()


def run_queue(q, fn):
    nfq = NetfilterQueue()
    nfq.bind(q, fn)
    print(f"[+] queue {q} ready")
    nfq.run()


threading.Thread(target=run_queue, args=(30, process_c2s), daemon=True).start()
threading.Thread(target=run_queue, args=(31, process_s2c), daemon=True).start()

print("[*] HL/AG bridge running")

while True:
    pass
