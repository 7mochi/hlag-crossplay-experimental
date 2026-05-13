#!/usr/bin/env python3
"""HL→AG redirect: intercept NFQUEUE 1, modify connect/A2S packets."""

from __future__ import annotations

import struct
import sys
import time
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

    log(f"CONNECT FULL: {data!r}")
    log(f"CONNECT HEX: {' '.join(f'{b:02x}' for b in data)}")
    log(f"CONNECT ASCII: {''.join(chr(b) if 32 <= b < 127 else '.' for b in data)}")

    if b"_gd=ag" in data or b"_gd\\ag" in data:
        log("  -> connect: _gd=ag already present")
        return None

    for suffix in (b"\n", b"\x00"):
        idx = data.rfind(suffix)
        if idx != -1:
            new_data = data[:idx] + b" /_gd=ag" + data[idx:]
            log(f"  -> connect: INJECTED /_gd=ag (suffix={suffix!r}, at offset {idx})")
            return payload[:4] + new_data

    log("  -> connect: no suffix found, appending at end")
    return payload[:4] + data + b" /_gd=ag"


def modify_a2s_info_source(payload: bytes) -> bytes | None:
    """Rewrite A2S_INFO in Source format (0x49)."""
    data = payload[4:]
    if len(data) < 6 or data[0] != 0x49:
        return None

    offset = 1
    proto = data[offset]
    offset += 1
    name, offset = read_cstring(data, offset)
    map_, offset = read_cstring(data, offset)
    folder, offset = read_cstring(data, offset)
    game, offset = read_cstring(data, offset)

    log(
        f"  -> A2S: Source format | proto={proto} | name={name!r} | map={map_!r} | folder={folder!r} | game={game!r}",
    )

    rebuilt = A2S_HEADER + bytes([0x49, proto])
    rebuilt += name + b"\x00"
    rebuilt += map_ + b"\x00"
    rebuilt += folder + b"\x00"
    rebuilt += b"HL" + b"\x00"

    log(f"  -> A2S: rewrote game from {game!r} to 'HL'")
    return rebuilt + data[offset:]


def modify_a2s_info_goldsource(payload: bytes) -> bytes | None:
    """Rewrite A2S_INFO in GoldSource format (0x6D)."""
    data = payload[4:]
    if len(data) < 6 or data[0] != 0x6D:
        return None

    offset = 1
    address, offset = read_cstring(data, offset)
    name, offset = read_cstring(data, offset)
    map_, offset = read_cstring(data, offset)
    folder, offset = read_cstring(data, offset)
    game, offset = read_cstring(data, offset)

    log(
        f"  -> A2S: GoldSource format | addr={address!r} | name={name!r} | map={map_!r} | folder={folder!r} | game={game!r}",
    )

    addr_str = address.decode("ascii", errors="replace")
    if f":{HL_PORT}" in addr_str:
        addr_str = addr_str.replace(f":{HL_PORT}", f":{AG_PORT}")
    new_address = addr_str.encode("ascii")

    rebuilt = A2S_HEADER + b"\x6d"
    rebuilt += new_address + b"\x00"
    rebuilt += name + b"\x00"
    rebuilt += map_ + b"\x00"
    rebuilt += folder + b"\x00"
    rebuilt += b"HL" + b"\x00"

    log(
        f"  -> A2S: rewrote game from {game!r} to 'HL', address from {address!r} to {new_address!r}",
    )
    return rebuilt + data[offset:]


def modify_a2s_info_response(payload: bytes) -> bytes:
    result = modify_a2s_info_source(payload)
    if result is not None:
        return result
    result = modify_a2s_info_goldsource(payload)
    if result is not None:
        return result
    return payload


def process_packet(packet):
    pkt = IP(packet.get_payload())

    if not pkt.haslayer(UDP):
        packet.accept()
        return

    ip_layer = pkt[IP]
    udp_layer = pkt[UDP]
    raw = bytes(pkt[Raw]) if pkt.haslayer(Raw) else b""

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

    if not pkt.haslayer(Raw):
        packet.accept()
        return

    modified = False
    modified_payload = None

    if ip_layer.dst == HL_SERVER_IP and udp_layer.dport == HL_PORT:
        orig = raw
        modified_payload = modify_connect_packet(raw)
        if modified_payload is not None and modified_payload is not raw:
            modified = True
            log(
                f"  -> MODIFIED CONNECT: {hexdump(orig)} -> {hexdump(modified_payload)}",
            )

    elif ip_layer.src == HL_SERVER_IP and udp_layer.sport == HL_PORT:
        orig = raw
        modified_payload = modify_a2s_info_response(raw)
        if modified_payload is not None and modified_payload is not raw:
            modified = True
            log(f"  -> MODIFIED A2S: {hexdump(orig)} -> {hexdump(modified_payload)}")

    if modified and modified_payload is not None:
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
        print(f"Warning: cannot open log file {LOG_FILE}: {e}")

    log(
        f"HL->AG redirect starting | HL={HL_SERVER_IP}:{HL_PORT} | AG_PORT={AG_PORT} | QUEUE={QUEUE_NUM}",
    )
    log("Logging all packets to stdout and " + LOG_FILE)
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
