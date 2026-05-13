from __future__ import annotations

import struct

from netfilterqueue import NetfilterQueue
from scapy.all import Raw
from scapy.layers.inet import IP
from scapy.layers.inet import UDP


def cb(packet):
    raw = packet.get_payload()
    ip = IP(raw)

    if not ip.haslayer(UDP):
        packet.accept()
        return

    payload = bytes(ip[UDP].payload)

    # Solo paquetes GoldSrc connectionless
    if not payload.startswith(b"\xff\xff\xff\xff"):
        packet.accept()
        return

    # Solo paquetes connect
    if not payload.startswith(b"\xff\xff\xff\xffconnect "):
        packet.accept()
        return

    idx = payload.find(b"\n")

    if idx == -1:
        print("No newline found in connect packet")
        packet.accept()
        return

    # Separar ASCII y blob binario
    ascii_part = payload[: idx + 1]
    binary_part = payload[idx + 1 :]

    print("\n==== CONNECT PACKET ====")

    print("\n=== ASCII ===")
    print(ascii_part)

    print("\n=== ASCII TEXT ===")
    print(ascii_part.decode("latin1", errors="ignore"))

    print("\n=== BINARY ===")
    print(binary_part[:32].hex())

    print("\n=== BINARY LEN ===")
    print(len(binary_part))

    # -------------------------------------------------
    # MODIFICACIÓN SEGURA (solo ASCII)
    # -------------------------------------------------

    text = ascii_part.decode("latin1", errors="ignore")

    # Cambio de prueba inocente
    text = text.replace(
        "\\rate\\30000",
        "\\rate\\25000",
    )

    new_payload = text.encode("latin1") + binary_part

    # Reemplazar payload UDP
    ip[UDP].remove_payload()
    ip[UDP].add_payload(new_payload)

    # Recalcular checksums/lengths
    del ip.len
    del ip.chksum
    del ip[UDP].len
    del ip[UDP].chksum

    packet.set_payload(bytes(ip))

    print("\n=== PACKET MODIFIED ===")

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
