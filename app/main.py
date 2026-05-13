#!/usr/bin/env python3

from __future__ import annotations

import struct
from datetime import datetime

from netfilterqueue import NetfilterQueue
from scapy.all import Raw
from scapy.layers.inet import IP
from scapy.layers.inet import UDP

HL_SERVER_IP = "172.18.0.9"
HL_PORT = 29428
AG_PORT = 29420
QUEUE_NUM = 1
LOG_FILE = "/tmp/hlag-redirect.log"

A2S_HEADER = b"\xff\xff\xff\xff"
A2S_TYPE_INFO_SOURCE = 0x49
A2S_TYPE_INFO_GOLD = 0x6D

log_fh = None


def log(msg: str):
    ts = datetime.now().strftime("%H:%M:%S.%f")[:-3]
    line = f"[{ts}] {msg}"
    print(line, flush=True)
    if log_fh:
        log_fh.write(line + "\n")
        log_fh.flush()


def hexdump(b: bytes, maxlen: int = 32) -> str:
    return b[:maxlen].hex(" ", 1)


def read_cstring(data: bytes, offset: int) -> tuple[bytes, int]:
    null = data.find(b"\x00", offset)
    if null == -1:
        raise ValueError("Unterminated string")
    return data[offset:null], null + 1


def modify_connect_packet(payload: bytes) -> bytes | None:
    if not payload.startswith(A2S_HEADER):
        return None
    data = payload[4:]
    if not data.startswith(b"connect "):
        return None
    if b"_gd=ag" in data:
        return None

    idx = data.rfind(b"\n")
    if idx != -1:
        new_data = data[:idx] + b" /_gd=ag" + data[idx:]
        log(">>> connect packet, injected /_gd=ag before newline, len=%d" % len(data))
        return payload[:4] + new_data

    idx = data.rfind(b"\x00")
    if idx != -1:
        new_data = data[:idx] + b" /_gd=ag" + data[idx:]
        log(">>> connect packet, injected /_gd=ag before null, len=%d" % len(data))
        return payload[:4] + new_data

    return None


def modify_a2s_info_source(payload: bytes) -> bytes | None:
    data = payload[4:]
    if len(data) < 6 or data[0] != A2S_TYPE_INFO_SOURCE:
        return None

    offset = 1
    proto = data[offset]
    offset += 1
    name, offset = read_cstring(data, offset)
    map_, offset = read_cstring(data, offset)
    folder, offset = read_cstring(data, offset)
    game, offset = read_cstring(data, offset)

    rebuilt = A2S_HEADER + bytes([0x49, proto])
    rebuilt += name + b"\x00"
    rebuilt += map_ + b"\x00"
    rebuilt += b"ag" + b"\x00"
    rebuilt += b"HL" + b"\x00"
    rebuilt += data[offset:]

    log(
        ">>> A2S SOURCE: folder '%s' -> 'ag', game '%s' -> 'HL'"
        % (folder.decode(errors="replace"), game.decode(errors="replace")),
    )
    return rebuilt


def modify_a2s_info_goldsource(payload: bytes) -> bytes | None:
    data = payload[4:]
    if len(data) < 6 or data[0] != A2S_TYPE_INFO_GOLD:
        return None

    offset = 1
    address, offset = read_cstring(data, offset)
    name, offset = read_cstring(data, offset)
    map_, offset = read_cstring(data, offset)
    folder, offset = read_cstring(data, offset)
    game, offset = read_cstring(data, offset)

    addr_str = address.decode("ascii", errors="replace")
    if f":{HL_PORT}" in addr_str:
        addr_str = addr_str.replace(f":{HL_PORT}", f":{AG_PORT}")
    new_address = addr_str.encode("ascii")

    rebuilt = A2S_HEADER + b"\x6d"
    rebuilt += new_address + b"\x00"
    rebuilt += name + b"\x00"
    rebuilt += map_ + b"\x00"
    rebuilt += b"ag" + b"\x00"
    rebuilt += b"HL" + b"\x00"
    rebuilt += data[offset:]

    log(
        ">>> A2S GOLD: folder '%s' -> 'ag', game '%s' -> 'HL'"
        % (folder.decode(errors="replace"), game.decode(errors="replace")),
    )
    return rebuilt


def modify_a2s_info_response(payload: bytes) -> bytes | None:
    result = modify_a2s_info_source(payload)
    if result is not None:
        return result
    return modify_a2s_info_goldsource(payload)


def process_packet(packet):
    pkt = IP(packet.get_payload())
    if not pkt.haslayer(UDP) or not pkt.haslayer(Raw):
        packet.accept()
        return

    ip_layer = pkt[IP]
    udp_layer = pkt[UDP]
    raw = bytes(pkt[Raw])

    modified = None

    if ip_layer.dst == HL_SERVER_IP and udp_layer.dport == HL_PORT:
        if raw.startswith(A2S_HEADER):
            modified = modify_connect_packet(raw)
        else:
            pass

    elif ip_layer.src == HL_SERVER_IP and udp_layer.sport == HL_PORT:
        if raw.startswith(A2S_HEADER):
            modified = modify_a2s_info_response(raw)

    if modified is not None and modified is not raw:
        new_pkt = IP(bytes(pkt))
        new_pkt[Raw].load = modified
        del new_pkt[IP].len
        del new_pkt[IP].chksum
        del new_pkt[UDP].len
        del new_pkt[UDP].chksum
        packet.set_payload(bytes(new_pkt))

    packet.accept()


def main():
    global log_fh
    try:
        log_fh = open(LOG_FILE, "w")
    except Exception:
        pass

    log(">>> script up, waiting on queue %d" % QUEUE_NUM)

    nfqueue = NetfilterQueue()
    nfqueue.bind(QUEUE_NUM, process_packet)
    try:
        nfqueue.run()
    except KeyboardInterrupt:
        log(">>> shutting down")
        nfqueue.unbind()
    finally:
        if log_fh:
            log_fh.close()


if __name__ == "__main__":
    main()
