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


def to_ascii(b: bytes) -> str:
    return "".join(chr(x) if 32 <= x < 127 else "." for x in b)


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

    newline_idx = data.find(b"\n")
    text_part = data[:newline_idx] if newline_idx != -1 else data

    last_quote = text_part.rfind(b'"')
    if last_quote == -1:
        return None

    core = text_part[:last_quote]
    closing = text_part[last_quote:]
    changed = False

    # _gd: add if missing, never replace
    if b"\\_gd\\" not in core:
        core += b"\\_gd\\ag"
        changed = True

    # _xplay: add if missing, replace if not ag
    xp_idx = core.find(b"\\_xplay\\")
    if xp_idx != -1:
        vs = xp_idx + len(b"\\_xplay\\")
        ve = core.find(b"\\", vs)
        ve = len(core) if ve == -1 else ve
        if core[vs:ve] != b"ag":
            core = core[:vs] + b"ag" + core[ve:]
            changed = True
    else:
        core += b"\\_xplay\\ag"
        changed = True

    if not changed:
        return None

    new_text = core + closing
    new_data = new_text + data[newline_idx:] if newline_idx != -1 else new_text
    log(">>> connect packet, _gd=ag, _xplay=ag")
    return payload[:4] + new_data


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

    log(">>> A2S SOURCE RAW: %s" % hexdump(data, len(data)))
    log(">>> A2S SOURCE ASC: %s" % to_ascii(data))
    log(
        ">>> parsed: proto=%d name='%s' map='%s' folder='%s' game='%s'"
        % (
            proto,
            name.decode(errors="replace"),
            map_.decode(errors="replace"),
            folder.decode(errors="replace"),
            game.decode(errors="replace"),
        ),
    )

    rebuilt = A2S_HEADER + bytes([0x49, proto])
    rebuilt += name + b"\x00"
    rebuilt += map_ + b"\x00"
    rebuilt += b"ag" + b"\x00"
    rebuilt += game + b"\x00"

    rest = data[offset:]
    rest_offset = 2  # skip short AppID
    rest_offset += 7  # players, max, bots, type, env, vis, vac
    _, rest_offset = read_cstring(rest, rest_offset)  # version string
    edf = rest[rest_offset]
    rest_offset += 1
    if edf & 0x80:
        port_bytes = struct.pack("<H", AG_PORT)
        rest = rest[:rest_offset] + port_bytes + rest[rest_offset + 2 :]
        log(">>> port rewritten to %d" % AG_PORT)
    rebuilt += rest

    log(">>> folder '%s' -> 'ag'" % folder.decode(errors="replace"))
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

    log(">>> A2S GOLD RAW: %s" % hexdump(data, len(data)))
    log(">>> A2S GOLD ASC: %s" % to_ascii(data))
    log(
        ">>> parsed: address='%s' name='%s' map='%s' folder='%s' game='%s'"
        % (
            to_ascii(address),
            name.decode(errors="replace"),
            map_.decode(errors="replace"),
            folder.decode(errors="replace"),
            game.decode(errors="replace"),
        ),
    )
    log(">>> address raw bytes: %s" % repr(address))

    addr_str = address.decode("ascii", errors="replace")
    if f":{HL_PORT}" in addr_str:
        addr_str = addr_str.replace(f":{HL_PORT}", f":{AG_PORT}")
    new_address = addr_str.encode("ascii")

    rebuilt = A2S_HEADER + b"\x6d"
    rebuilt += new_address + b"\x00"
    rebuilt += name + b"\x00"
    rebuilt += map_ + b"\x00"
    rebuilt += b"ag" + b"\x00"
    rebuilt += game + b"\x00"
    rebuilt += data[offset:]

    log(
        ">>> folder '%s' -> 'ag', address '%s' -> '%s'"
        % (
            folder.decode(errors="replace"),
            address.decode(errors="replace"),
            new_address.decode(errors="replace"),
        ),
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
