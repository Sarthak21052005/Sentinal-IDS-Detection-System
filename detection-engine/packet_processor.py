
from datetime import datetime, timezone

from scapy.all import (
    ARP,
    DNS,
    DNSQR,
    DNSRR,
    Ether,
    IP,
    IPv6,
    TCP,
    UDP,
)


def _decode_dns_name(value):
    """Convert DNS byte strings into readable text."""
    if isinstance(value, bytes):
        return value.rstrip(b"\x00").decode("utf-8", errors="replace")
    return str(value) if value is not None else None


def process_packet(packet):
    """
    Extract and normalize packet metadata.

    Returns a dictionary or None if the packet has no
    supported network-layer information.
    """

    event = {
        "timestamp": datetime.fromtimestamp(
            float(packet.time), tz=timezone.utc
        ).isoformat(),
        "src_mac": None,
        "dst_mac": None,
        "src_ip": None,
        "dst_ip": None,
        "protocol": "OTHER",
        "src_port": None,
        "dst_port": None,
        "packet_size": len(packet),
        "arp": None,
        "dns": None,
    }

    # Ethernet metadata
    if Ether in packet:
        event["src_mac"] = packet[Ether].src
        event["dst_mac"] = packet[Ether].dst

    # ARP metadata
    if ARP in packet:
        arp = packet[ARP]

        event["protocol"] = "ARP"
        event["src_ip"] = arp.psrc
        event["dst_ip"] = arp.pdst

        event["arp"] = {
            "operation": int(arp.op),
            "source_mac": arp.hwsrc,
            "source_ip": arp.psrc,
            "destination_mac": arp.hwdst,
            "destination_ip": arp.pdst,
        }

    # IPv4 metadata
    elif IP in packet:
        ip = packet[IP]

        event["src_ip"] = ip.src
        event["dst_ip"] = ip.dst

        if TCP in packet:
            event["protocol"] = "TCP"
            event["src_port"] = int(packet[TCP].sport)
            event["dst_port"] = int(packet[TCP].dport)

        elif UDP in packet:
            event["protocol"] = "UDP"
            event["src_port"] = int(packet[UDP].sport)
            event["dst_port"] = int(packet[UDP].dport)

        else:
            event["protocol"] = "IP"

    # IPv6 metadata
    elif IPv6 in packet:
        ipv6 = packet[IPv6]

        event["src_ip"] = ipv6.src
        event["dst_ip"] = ipv6.dst
        event["protocol"] = "IPv6"

        if TCP in packet:
            event["protocol"] = "TCP"
            event["src_port"] = int(packet[TCP].sport)
            event["dst_port"] = int(packet[TCP].dport)

        elif UDP in packet:
            event["protocol"] = "UDP"
            event["src_port"] = int(packet[UDP].sport)
            event["dst_port"] = int(packet[UDP].dport)

    else:
        return None

    # DNS metadata
    if DNS in packet:
        dns = packet[DNS]

        dns_data = {
            "transaction_id": int(dns.id),
            "is_response": bool(dns.qr),
            "query_name": None,
            "query_type": None,
            "answers": [],
        }

        if dns.qd is not None and isinstance(dns.qd, DNSQR):
            dns_data["query_name"] = _decode_dns_name(
                dns.qd.qname
            )
            dns_data["query_type"] = int(dns.qd.qtype)

        answer = dns.an
        for _ in range(int(dns.ancount)):
            if not isinstance(answer, DNSRR):
                break

            dns_data["answers"].append({
                "name": _decode_dns_name(answer.rrname),
                "type": int(answer.type),
                "ttl": int(answer.ttl),
                "data": _decode_dns_name(answer.rdata),
            })

            answer = answer.payload

        event["dns"] = dns_data
        event["protocol"] = "DNS"

    return event
