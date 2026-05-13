from __future__ import annotations

import struct

from netfilterqueue import NetfilterQueue
from scapy.all import Raw
from scapy.layers.inet import IP
from scapy.layers.inet import UDP

REAL_SERVER = ("172.18.0.11", 29428)
FAKE_PORT = 29420


def is_connectionless(payload):
    return payload.startswith(b"\xff\xff\xff\xff")


def process(pkt):
    raw = pkt.get_payload()
    ip = IP(raw)

    if not ip.haslayer(UDP):
        pkt.accept()
        return

    udp = ip[UDP]
    payload = bytes(udp.payload)

    if not is_connectionless(payload):
        pkt.accept()
        return

    print(f"[+] Connectionless packet {ip.src}:{udp.sport}")

    #
    # CLIENT -> SERVER
    #
    if udp.dport == 29420:

        #
        # inject /_gd=ag
        #
        if b"connect" in payload and b"/_gd=ag" not in payload:
            print("[+] Injecting /_gd=ag")

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

    #
    # SERVER -> CLIENT
    #
    if udp.sport == 29428:

        #
        # spoof reported port
        #
        port_bytes = struct.pack("<H", 29428)
        fake_bytes = struct.pack("<H", 29420)

        if port_bytes in payload:
            payload = payload.replace(port_bytes, fake_bytes)

            print("[+] Rewriting port 29428 -> 29420")

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


nfqueue = NetfilterQueue()
nfqueue.bind(30, process)

print("[*] AG Spoof running")

try:
    nfqueue.run()
except KeyboardInterrupt:
    print("bye")
