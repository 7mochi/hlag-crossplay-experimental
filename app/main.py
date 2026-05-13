from __future__ import annotations

from netfilterqueue import NetfilterQueue
from netfilterqueue import Packet
from scapy.layers.inet import IP
from scapy.layers.inet import UDP
from scapy.packet import Raw


def modify_packet(pkt: Packet) -> None:
    data = pkt.get_payload()
    packet = IP(data)

    if packet.haslayer(Raw):
        payload = packet[Raw].load

        if packet[UDP].sport == 29428:
            new_payload = payload.replace(b"valve", b"ag")
            packet[UDP].sport = 29420
            packet[Raw].load = new_payload

        elif packet[UDP].dport == 29420:
            if b"connect" in payload and b"/_gd=valve" not in payload:
                new_payload = payload.replace(b'0 "', b'0 "/_gd=valve')
                packet[Raw].load = new_payload

            packet[UDP].dport = 29428

        if (
            packet[Raw].load != payload
            or packet[UDP].sport == 29420
            or packet[UDP].dport == 29428
        ):
            del packet[IP].len
            del packet[IP].chksum
            del packet[UDP].len
            del packet[UDP].chksum
            pkt.set_payload(bytes(packet))

    pkt.accept()


def main() -> None:
    nfqueue = NetfilterQueue()
    nfqueue.bind(1, modify_packet)
    print("Masking HL packets with AG packets... Press Ctrl+C to stop.")
    try:
        nfqueue.run()
    except KeyboardInterrupt:
        nfqueue.unbind()


if __name__ == "__main__":
    main()
