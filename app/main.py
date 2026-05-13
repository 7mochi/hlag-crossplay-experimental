from __future__ import annotations

import threading

from netfilterqueue import NetfilterQueue
from scapy.all import Raw
from scapy.layers.inet import IP
from scapy.layers.inet import UDP


def is_connect(payload: bytes) -> bool:
    return payload.startswith(b"\xff\xff\xff\xffconnect")


def process_c2s(packet):
    ip = IP(packet.get_payload())

    if not ip.haslayer(UDP):
        packet.accept()
        return

    udp = ip[UDP]
    payload = bytes(udp.payload)

    print(f"[C->S] {ip.src}:{udp.sport} -> {ip.dst}:{udp.dport} len={len(payload)}")

    if is_connect(payload):
        print("[+] injecting /_gd=ag")
        if b"/_gd=ag" not in payload:
            payload = payload.replace(b"connect", b"connect /_gd=ag", 1)

        ip[UDP].remove_payload()
        ip[UDP].add_payload(payload)
        packet.set_payload(bytes(ip))

    packet.accept()


def process_s2c(packet):
    ip = IP(packet.get_payload())

    if not ip.haslayer(UDP):
        packet.accept()
        return

    udp = ip[UDP]
    payload = bytes(udp.payload)

    print(f"[S->C] {ip.src}:{udp.sport} -> {ip.dst}:{udp.dport} len={len(payload)}")

    packet.accept()


def run(q, fn):
    nfq = NetfilterQueue()
    nfq.bind(q, fn)
    print(f"[+] queue {q} ready")
    nfq.run()


threading.Thread(target=run, args=(30, process_c2s), daemon=True).start()
threading.Thread(target=run, args=(31, process_s2c), daemon=True).start()

print("[*] HL/AG bridge running")

while True:
    pass
