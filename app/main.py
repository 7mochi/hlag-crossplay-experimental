#!/usr/bin/env python3
"""HL->AG redirect: rewrite A2S folder (valve->ag) and game (->HL)."""

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


def hexdump(b: bytes, maxlen: int = 64) -> str:
    return b[:maxlen].hex(" ", 1)


def read_cstring(data: bytes, offset: int) -> tuple[bytes, int]:
    null = data.find(b"\x00", offset)
    if null == -1:
        raise ValueError("Unterminated string")
    return data[offset:null], null + 1


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

    log(
        f"  -> A2S SOURCE: proto={proto} name={name!r} map={map_!r} folder={folder!r} game={game!r}",
    )

    rebuilt = A2S_HEADER + bytes([0x49, proto])
    rebuilt += name + b"\x00"
    rebuilt += map_ + b"\x00"
    rebuilt += b"ag" + b"\x00"
    rebuilt += b"HL" + b"\x00"
    rebuilt += data[offset:]

    log(f"  -> A2S: rewrote folder {folder!r} -> 'ag', game {game!r} -> 'HL'")
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

    log(
        f"  -> A2S GOLD: addr={address!r} name={name!r} map={map_!r} folder={folder!r} game={game!r}",
    )

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
        f"  -> A2S: rewrote folder {folder!r} -> 'ag', game {game!r} -> 'HL', addr {address!r} -> {new_address!r}",
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
    src = f"{ip_layer.src}:{udp_layer.sport}"
    dst = f"{ip_layer.dst}:{udp_layer.dport}"
    direction = (
        "IN"
        if ip_layer.dst == HL_SERVER_IP
        else "OUT" if ip_layer.src == HL_SERVER_IP else "??"
    )
    is_a2s = raw.startswith(A2S_HEADER)

    log(
        f"PKT {direction}: {src} -> {dst} | len={len(raw)} | a2s={is_a2s} | hex={hexdump(raw)}",
    )

    modified_payload = None
    if direction == "OUT" and is_a2s:
        modified_payload = modify_a2s_info_response(raw)

    if modified_payload is not None and modified_payload is not raw:
        log(f"  -> APPLYING MODIFICATION")
        log(f"     BEFORE: {hexdump(raw)}")
        log(f"     AFTER:  {hexdump(modified_payload)}")
        new_pkt = IP(bytes(pkt))
        new_pkt[Raw].load = modified_payload
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
    except Exception as e:
        print(f"Warning: cannot open {LOG_FILE}: {e}")

    log(
        f"HL->AG redirect (folder=ag game=HL) | HL={HL_SERVER_IP}:{HL_PORT} | AG_PORT={AG_PORT} | QUEUE={QUEUE_NUM}",
    )
    print("", flush=True)

    nfqueue = NetfilterQueue()
    nfqueue.bind(QUEUE_NUM, process_packet)
    try:
        nfqueue.run()
    except KeyboardInterrupt:
        log("\nShutting down...")
        nfqueue.unbind()
    finally:
        if log_fh:
            log_fh.close()


if __name__ == "__main__":
    main()
