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

        if payload.startswith(b"\xff\xff\xff\xffI"):
            new_payload = payload.replace(b"valve", b"ag")

            if packet[UDP].sport == 29428:
                packet[UDP].sport = 29420

            packet[Raw].load = new_payload

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
