from __future__ import annotations

import struct

from netfilterqueue import NetfilterQueue
from scapy.all import IP
from scapy.all import UDP
from scapy.all import Raw

HL_SERVER_PORT = 29428
AG_DUMMY_PORT = 29420


def modify_a2s_response(payload):
    if not payload.startswith(b"\xff\xff\xff\xffI"):
        return payload

    try:
        parts = payload.split(b"\x00")
        if len(parts) > 3:
            parts[3] = b"ag"
            return b"\x00".join(parts)
    except Exception as e:
        print(f"Error modificando A2S: {e}")
    return payload


def callback(packet):
    raw_data = packet.get_payload()
    ip_pkt = IP(raw_data)

    if not ip_pkt.haslayer(UDP):
        packet.accept()
        return

    udp = ip_pkt[UDP]
    payload = bytes(udp.payload)
    modified = False

    if udp.dport == AG_DUMMY_PORT:
        udp.dport = HL_SERVER_PORT

        if b"connect" in payload:
            if b"_gd\\ag" not in payload:
                new_payload = payload.replace(b"\n", b"") + b"\\_gd\\ag\n"
                udp.remove_payload()
                udp.add_payload(Raw(load=new_payload))

        modified = True

    elif udp.sport == HL_SERVER_PORT:
        udp.sport = AG_DUMMY_PORT

        if payload.startswith(b"\xff\xff\xff\xffI"):
            new_payload = modify_a2s_response(payload)
            udp.remove_payload()
            udp.add_payload(Raw(load=new_payload))

        modified = True

    if modified:
        del ip_pkt[IP].len
        del ip_pkt[IP].chksum
        del udp.len
        del udp.chksum
        packet.set_payload(bytes(ip_pkt))

    packet.accept()


nfqueue = NetfilterQueue()
nfqueue.bind(0, callback)

try:
    nfqueue.run()
except KeyboardInterrupt:
    print("Detenido.")
