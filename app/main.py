from __future__ import annotations

import struct
import threading

from netfilterqueue import NetfilterQueue
from scapy.all import Raw
from scapy.layers.inet import IP
from scapy.layers.inet import UDP


def process(packet):

    raw = packet.get_payload()

    try:
        ip = IP(raw)
    except:
        packet.accept()
        return

    if not ip.haslayer(UDP):
        packet.accept()
        return

    udp = ip[UDP]
    payload = bytes(udp.payload)

    print(
        f"{ip.src}:{udp.sport} "
        f"-> "
        f"{ip.dst}:{udp.dport} "
        f"len={len(payload)} "
        f"head={payload[:16]!r}",
    )

    packet.accept()


def run_queue(num):
    nfq = NetfilterQueue()
    nfq.bind(num, process)

    print(f"queue {num}")

    nfq.run()


threading.Thread(target=run_queue, args=(30,), daemon=True).start()
threading.Thread(target=run_queue, args=(31,), daemon=True).start()

while True:
    pass
