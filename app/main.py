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


def process_client(packet):
    raw = packet.get_payload()

    ip = IP(raw)
    if not ip.haslayer(UDP):
        packet.accept()
        return

    udp = ip[UDP]
    payload = bytes(udp.payload)

    src = f"{ip.src}:{udp.sport}"
    dst = f"{ip.dst}:{udp.dport}"

    print(f"[C->S] {src} -> {dst} len={len(payload)} head={payload[:32]!r}")

    # 🔥 CONNECT PATCH
    if is_connect(payload):
        print("[+] injecting /_gd=ag")

        if b"/_gd=ag" not in payload:
            payload = payload.replace(b"connect", b"connect /_gd=ag", 1)

        ip[UDP].remove_payload()
        ip[UDP].add_payload(payload)

        packet.set_payload(bytes(ip))

    packet.accept()


def process_server(packet):
    raw = packet.get_payload()

    ip = IP(raw)
    if not ip.haslayer(UDP):
        packet.accept()
        return

    udp = ip[UDP]
    payload = bytes(udp.payload)

    src = f"{ip.src}:{udp.sport}"
    dst = f"{ip.dst}:{udp.dport}"

    # 🔥 A2S RESPONSE SPOOF (HL → AG disguise)
    if is_a2s(payload):
        # ejemplo básico de spoof (game string + port mask conceptual)
        payload = payload.replace(b"Half-Life", b"HL/70\x00")

        ip[UDP].remove_payload()
        ip[UDP].add_payload(payload)

        packet.set_payload(bytes(ip))

    packet.accept()


def run_queue(qnum, handler):
    nfq = NetfilterQueue()
    nfq.bind(qnum, handler)
    print(f"[+] queue {qnum} ready")
    nfq.run()


threading.Thread(target=run_queue, args=(30, process_client), daemon=True).start()
threading.Thread(target=run_queue, args=(31, process_server), daemon=True).start()

print("[*] HL/AG bridge running")

while True:
    pass
