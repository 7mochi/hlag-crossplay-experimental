from __future__ import annotations

import threading

from netfilterqueue import NetfilterQueue
from scapy.all import Raw
from scapy.layers.inet import IP
from scapy.layers.inet import UDP

HL_IP = "172.18.0.3"
HL_PORT = 29428
AG_PORT = 29420


def rebuild(pkt):
    del pkt[IP].len
    del pkt[IP].chksum
    del pkt[UDP].len
    del pkt[UDP].chksum
    return pkt


def process_incoming(packet):
    raw = packet.get_payload()
    ip = IP(raw)

    if not ip.haslayer(UDP):
        packet.accept()
        return

    udp = ip[UDP]

    # SOLO tráfico hacia AG fake port
    if udp.dport != AG_PORT:
        packet.accept()
        return

    # DEBUG
    print(f"[IN] {ip.src}:{udp.sport} -> {ip.dst}:{udp.dport}")

    # 🔥 REDIRIGIR A HL REAL
    ip.dst = HL_IP
    udp.dport = HL_PORT

    # opcional: marcar como HL compatible
    if udp.haslayer(Raw):
        payload = bytes(udp[Raw].load)

        # injerto mínimo sin romper protocolo
        if b"connect" in payload:
            print("[+] connect detected -> patching _gd=ag")
            if b"/_gd=ag" not in payload:
                payload += b" /_gd=ag"

        udp.remove_payload()
        udp.add_payload(payload)

    pkt = rebuild(ip)
    packet.set_payload(bytes(pkt))
    packet.accept()


def process_outgoing(packet):
    raw = packet.get_payload()
    ip = IP(raw)

    if not ip.haslayer(UDP):
        packet.accept()
        return

    udp = ip[UDP]

    if udp.sport != HL_PORT:
        packet.accept()
        return

    print(f"[OUT] {ip.src}:{udp.sport} -> {ip.dst}:{udp.dport}")

    # 🔥 engañar cliente AG: HL responde como 29420
    udp.sport = AG_PORT

    pkt = rebuild(ip)
    packet.set_payload(bytes(pkt))
    packet.accept()


def run():
    nfq_in = NetfilterQueue()
    nfq_out = NetfilterQueue()

    nfq_in.bind(30, process_incoming)
    nfq_out.bind(31, process_outgoing)

    print("[*] HL/AG bridge running (FINAL MODE)")

    t1 = threading.Thread(target=nfq_in.run, daemon=True)
    t2 = threading.Thread(target=nfq_out.run, daemon=True)

    t1.start()
    t2.start()

    t1.join()
    t2.join()


if __name__ == "__main__":
    run()
