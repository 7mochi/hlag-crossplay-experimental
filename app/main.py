from __future__ import annotations

import socket
import struct
import threading

from netfilterqueue import NetfilterQueue
from scapy.all import Raw
from scapy.layers.inet import IP
from scapy.layers.inet import UDP

# =========================
# CONFIG
# =========================

HL_IP = "172.18.0.11"
HL_PORT = 29428
AG_PORT = 29420

# socket real hacia HL
hl_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)


# =========================
# HELPERS
# =========================


def is_connect(payload: bytes) -> bool:
    return payload.startswith(b"\xff\xff\xff\xffconnect")


def inject_gd(payload: bytes) -> bytes:
    if b"/_gd=ag" not in payload:
        return payload.replace(b"connect", b"connect /_gd=ag", 1)
    return payload


# =========================
# CLIENT -> SERVER (AG → HL)
# =========================


def process_c2s(packet):
    raw = packet.get_payload()

    ip = IP(raw)

    if not ip.haslayer(UDP):
        packet.accept()
        return

    udp = ip[UDP]
    payload = bytes(udp.payload)

    print(
        f"[C->S] {ip.src}:{udp.sport} -> {ip.dst}:{udp.dport} len={len(payload)} head={payload[:32]!r}",
    )

    # SOLO tocar connect real
    if is_connect(payload):
        print("[+] injecting /_gd=ag")
        payload = inject_gd(payload)

    # 🔥 IMPORTANTE:
    # reenviamos al HL real y descartamos el paquete original
    hl_sock.sendto(payload, (HL_IP, HL_PORT))

    packet.drop()


# =========================
# SERVER -> CLIENT (HL → AG)
# =========================


def process_s2c(packet):
    raw = packet.get_payload()

    ip = IP(raw)

    if not ip.haslayer(UDP):
        packet.accept()
        return

    udp = ip[UDP]
    payload = bytes(udp.payload)

    print(
        f"[S->C] {ip.src}:{udp.sport} -> {ip.dst}:{udp.dport} len={len(payload)} head={payload[:32]!r}",
    )

    # No spoof agresivo aquí (crítico para estabilidad)
    # solo forward normal

    packet.accept()


# =========================
# QUEUES
# =========================


def run_queue(qnum, handler):
    nfq = NetfilterQueue()
    nfq.bind(qnum, handler)
    print(f"[+] queue {qnum} ready")
    nfq.run()


# =========================
# MAIN
# =========================

threading.Thread(target=run_queue, args=(30, process_c2s), daemon=True).start()
threading.Thread(target=run_queue, args=(31, process_s2c), daemon=True).start()

print("[*] HL/AG bridge running")

while True:
    pass
