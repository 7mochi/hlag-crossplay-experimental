from __future__ import annotations

import struct
import sys

from netfilterqueue import NetfilterQueue
from scapy.layers.inet import IP
from scapy.layers.inet import UDP
from scapy.packet import Raw

QUEUE_NUM = 0
HL_SERVER_PORT = 29428
AG_CLIENT_PORT = 29420
HL_APP_ID = 70
GAME_NAME = b"Half-Life"


def modify_a2s_response(payload, src_port):
    if payload[:5] != b"\xff\xff\xff\xffI":
        return payload, src_port

    offset = 5
    # protocol (byte)
    offset += 1
    # name (null-terminated string)
    offset += payload[offset:].index(b"\x00") + 1
    # map (null-terminated string)
    offset += payload[offset:].index(b"\x00") + 1
    # folder (null-terminated string)
    offset += payload[offset:].index(b"\x00") + 1
    # game (null-terminated string) - CAMBIAR
    game_start = offset
    offset += payload[offset:].index(b"\x00") + 1
    # app ID (short LE)
    app_id_start = offset
    offset += 2

    payload = bytearray(payload)
    # Overwrite game name
    payload[game_start:offset] = GAME_NAME + b"\x00"
    # Overwrite app ID
    struct.pack_into("<H", payload, app_id_start, HL_APP_ID)
    # Change source port to AG port so client thinks it's from port 29420
    src_port = AG_CLIENT_PORT

    return bytes(payload), src_port


def modify_connect_packet(payload):
    # The connect string from AG looks like: "connect ... \n\_gd\ag"
    # We need to ensure _gd=ag is present
    if b"_gd" in payload:
        return payload
    # Append AG identifier
    return payload + b"\\_gd\\ag"


def callback(packet):
    data = packet.get_payload()
    ip_pkt = IP(data)

    if not ip_pkt.haslayer(UDP):
        packet.accept()
        return

    udp = ip_pkt[UDP]
    sport = udp.sport
    dport = udp.dport
    payload = bytes(udp.payload)

    modified = False
    new_sport, new_dport = sport, dport

    if dport == AG_CLIENT_PORT:
        # Client -> Server: A2S query or connect
        if payload.startswith(b"\xff\xff\xff\xff"):
            if b"connect" in payload or b"challenge" in payload:
                payload = modify_connect_packet(payload)
                modified = True
            # A2S query (0x54 = 'T' for Source, or "info" for GoldSrc)
            # Just forward to HL server
            new_dport = HL_SERVER_PORT
            modified = True
    elif sport == HL_SERVER_PORT and dport != AG_CLIENT_PORT:
        # Server -> Client: A2S response
        payload, new_sport = modify_a2s_response(payload, sport)
        if new_sport != sport:
            modified = True

    if modified:
        udp.sport = new_sport
        udp.dport = new_dport
        udp.len = 8 + len(payload)
        del udp.chksum
        ip_pkt[IP].len = ip_pkt[IP].ihl * 4 + 8 + len(payload)
        del ip_pkt[IP].chksum
        packet.set_payload(bytes(ip_pkt))

    packet.accept()


nfqueue = NetfilterQueue()
nfqueue.bind(QUEUE_NUM, callback)
try:
    nfqueue.run()
except KeyboardInterrupt:
    pass
