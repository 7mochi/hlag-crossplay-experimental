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


def debug(pkt, ip, udp, payload, tag=""):
    print(
        f"[{tag}] {ip.src}:{udp.sport} -> {ip.dst}:{udp.dport} "
        f"len={len(payload)} head={payload[:16]!r}",
    )


def process(pkt):
    raw = pkt.get_payload()

    try:
        ip = IP(raw)
    except Exception:
        pkt.accept()
        return

    if not ip.haslayer(UDP):
        pkt.accept()
        return

    udp = ip[UDP]
    payload = bytes(udp.payload)

    # SOLO traffic relevante
    if not is_connectionless(payload):
        pkt.accept()
        return

    # ----------------------------
    # CLIENT -> SERVER (AG PORT)
    # ----------------------------
    if udp.dport == AG_PORT:

        debug(pkt, ip, udp, payload, "C->S")

        # inject tag de compatibilidad AG
        if b"connect" in payload and b"/_gd=ag" not in payload:
            print("[+] injecting /_gd=ag")
            payload += b" /_gd=ag"

        udp.remove_payload()
        udp.add_payload(payload)

        del ip.len
        del ip.chksum
        del udp.len
        del udp.chksum

        pkt.set_payload(bytes(ip))
        pkt.accept()
        return

    # ----------------------------
    # SERVER -> CLIENT (HL RESPONSE)
    # ----------------------------
    if udp.sport == HL_PORT:

        debug(pkt, ip, udp, payload, "S->C")

        # spoof port HL -> AG
        try:
            payload = payload.replace(
                struct.pack("<H", HL_PORT),
                struct.pack("<H", AG_PORT),
            )
        except Exception:
            pass

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


def run_queue(num: int):
    nfq = NetfilterQueue()
    nfq.bind(num, process)
    print(f"[+] queue {num} ready")
    nfq.run()


def main():
    threading.Thread(target=run_queue, args=(30,), daemon=True).start()
    threading.Thread(target=run_queue, args=(31,), daemon=True).start()

    print("[*] HL/AG bridge running")

    while True:
        pass


if __name__ == "__main__":
    main()
