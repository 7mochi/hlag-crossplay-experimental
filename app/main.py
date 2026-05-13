from __future__ import annotations

import struct

from netfilterqueue import NetfilterQueue
from scapy.all import Raw
from scapy.layers.inet import IP
from scapy.layers.inet import UDP

HL_CONTAINER_IP = "172.18.0.11"
HL_CONTAINER_PORT = 29428


def cb(packet):
    raw = packet.get_payload()
    ip = IP(raw)

    if not ip.haslayer(UDP):
        packet.accept()
        return

    udp = ip[UDP]

    payload = bytes(udp.payload)

    #
    # Solo GoldSrc connectionless
    #
    if not payload.startswith(b"\xff\xff\xff\xff"):
        packet.accept()
        return

    #
    # Solo CONNECT
    #
    if not payload.startswith(b"\xff\xff\xff\xffconnect "):
        #
        # Igual redirigimos A2S packets
        #
        ip.dst = HL_CONTAINER_IP
        udp.dport = HL_CONTAINER_PORT

        del ip.len
        del ip.chksum
        del udp.len
        del udp.chksum

        packet.set_payload(bytes(ip))

        packet.accept()
        return

    idx = payload.find(b"\n")

    if idx == -1:
        packet.accept()
        return

    ascii_part = payload[: idx + 1]
    binary_part = payload[idx + 1 :]

    print("\n==== CONNECT PACKET ====")

    print("\n=== ASCII ===")
    print(ascii_part.decode("latin1", errors="ignore"))

    #
    # Inyectar _gd=ag
    #
    text = ascii_part.decode("latin1", errors="ignore")

    if "\\_gd\\ag" not in text:
        text = text.replace(
            '"\n',
            '\\_gd\\ag"\n',
        )

    new_payload = text.encode("latin1") + binary_part

    #
    # Reemplazar payload
    #
    udp.remove_payload()
    udp.add_payload(new_payload)

    #
    # Redirigir al HL real
    #
    ip.dst = HL_CONTAINER_IP
    udp.dport = HL_CONTAINER_PORT

    #
    # Recalcular checksums
    #
    del ip.len
    del ip.chksum
    del udp.len
    del udp.chksum

    packet.set_payload(bytes(ip))

    print("\n=== CONNECT REDIRECTED TO HL ===")

    packet.accept()


nf = NetfilterQueue()

try:
    nf.bind(30, cb)

    print("Listening on NFQUEUE 30...")
    nf.run()

except KeyboardInterrupt:
    print("\nStopping...")

finally:
    nf.unbind()
