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

    udp = ip[UDP]
    payload = bytes(udp.payload)

    direction = "UNKNOWN"

    if udp.dport == 29420:
        direction = "CLIENT -> SERVER"

    elif udp.sport == 29428:
        direction = "SERVER -> CLIENT"

    print("\n====", direction, "====")
    print(payload)
    print(payload.hex())

    try:
        print(payload.decode("latin1", errors="ignore"))
    except:
        pass

    packet.accept()


nf1 = NetfilterQueue()
nf1.bind(30, cb)

nf2 = NetfilterQueue()
nf2.bind(31, cb)

try:
    import threading

    t = threading.Thread(target=nf1.run)
    t.start()

    nf2.run()

except KeyboardInterrupt:
    pass
