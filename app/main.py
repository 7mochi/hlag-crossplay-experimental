from __future__ import annotations

import re

from netfilterqueue import NetfilterQueue
from netfilterqueue import Packet
from scapy.layers.inet import IP
from scapy.layers.inet import UDP
from scapy.packet import Raw

HL_INTERNAL_IP = "172.18.0.11"
HL_PORT = 29428
AG_PORT = 29420


def modify_packet(pkt: Packet) -> None:
    data = pkt.get_payload()
    packet = IP(data)

    if packet.haslayer(Raw):
        payload = packet[Raw].load
        modified = False

        if packet[IP].src == HL_INTERNAL_IP and packet[UDP].sport == HL_PORT:
            packet[UDP].sport = AG_PORT
            if re.search(b"valve", payload, re.IGNORECASE):
                payload = re.sub(b"valve", b"ag", payload, flags=re.IGNORECASE)
                packet[Raw].load = payload
            modified = True

        elif packet[UDP].dport == AG_PORT:
            packet[UDP].dport = HL_PORT
            if b"connect" in payload and b"/_gd=valve" not in payload:
                if b"\\" in payload:
                    parts = payload.split(b"\\", 1)
                    payload = parts[0] + b"\\/_gd\\valve" + b"\\" + parts[1]
                elif b'0 "' in payload:
                    payload = payload.replace(b'0 "', b'0 "/_gd=valve')
                packet[Raw].load = payload
            modified = True

        if modified:
            del packet[IP].len
            del packet[IP].chksum
            del packet[UDP].len
            del packet[UDP].chksum
            pkt.set_payload(bytes(packet))

    pkt.accept()


def main() -> None:
    nfqueue = NetfilterQueue()
    nfqueue.bind(1, modify_packet)
    try:
        nfqueue.run()
    except KeyboardInterrupt:
        nfqueue.unbind()


if __name__ == "__main__":
    main()
