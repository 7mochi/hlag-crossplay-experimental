from __future__ import annotations

import struct
import threading

from netfilterqueue import NetfilterQueue
from scapy.all import Raw
from scapy.layers.inet import IP
from scapy.layers.inet import UDP

REAL_IP = "172.18.0.11"
REAL_PORT = 29428

FAKE_PORT = 29420


def is_connectionless(payload: bytes) -> bool:
    return payload.startswith(b"\xff\xff\xff\xff")


def process(packet):
    raw = packet.get_payload()

    try:
        ip = IP(raw)
    except Exception:
        packet.accept()
        return

    if not ip.haslayer(UDP):
        packet.accept()
        return

    udp = ip[UDP]
    payload = bytes(udp.payload)

    #
    # SOLO connectionless
    #
    if not is_connectionless(payload):
        packet.accept()
        return

    #
    # CLIENT -> SERVER
    #
    if udp.dport == FAKE_PORT:

        print(f"[CLIENT -> SERVER] " f"{ip.src}:{udp.sport} -> {ip.dst}:{udp.dport}")

        #
        # AQUI MAS ADELANTE:
        # inject /_gd=ag
        #

        packet.accept()
        return

    #
    # SERVER -> CLIENT
    #
    if udp.sport == REAL_PORT:

        print(f"[SERVER -> CLIENT] " f"{ip.src}:{udp.sport} -> {ip.dst}:{udp.dport}")

        #
        # Reescribir puerto reportado
        #
        real_port = struct.pack("<H", REAL_PORT)
        fake_port = struct.pack("<H", FAKE_PORT)

        if real_port in payload:

            payload = payload.replace(real_port, fake_port)

            udp.remove_payload()
            udp.add_payload(payload)

            del ip.len
            del ip.chksum
            del udp.len
            del udp.chksum

            packet.set_payload(bytes(ip))

            print(f"[+] Rewrote reported port " f"{REAL_PORT} -> {FAKE_PORT}")

        packet.accept()
        return

    packet.accept()


def run_queue(num: int):
    nfq = NetfilterQueue()
    nfq.bind(num, process)

    print(f"[*] NFQUEUE {num} running")

    try:
        nfq.run()
    except KeyboardInterrupt:
        pass


threading.Thread(target=run_queue, args=(30,), daemon=True).start()
threading.Thread(target=run_queue, args=(31,), daemon=True).start()

print("[*] AG Spoof active")

try:
    while True:
        pass
except KeyboardInterrupt:
    print("bye")
