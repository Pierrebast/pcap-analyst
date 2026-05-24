from scapy.all import rdpcap, IP, TCP, UDP, ARP, DNS, DNSQR

PROTO_MAP = {
    6: "TCP",
    17: "UDP",
    1: "ICMP",
}

def resolve_proto(number):
    return PROTO_MAP.get(number, "OTHER")

def parse_pcap(filepath):
    packets = rdpcap(filepath)
    result = []

    for packet in packets:
        if IP in packet:
            if TCP in packet:
                sport = packet[TCP].sport
                dport = packet[TCP].dport
                flags = str(packet[TCP].flags)
                qname = None
            elif UDP in packet:
                sport = packet[UDP].sport
                dport = packet[UDP].dport
                flags = None
                if dport == 53:
                    if DNS in packet and DNSQR in packet:
                        qname = packet[DNSQR].qname.decode("utf-8", errors="ignore")
                    else:
                        qname = None
                else:
                    qname = None
            else:
                sport = None
                dport = None
                flags = None

            entry = {
                "src": packet[IP].src,
                "dst": packet[IP].dst,
                "mac": None,
                "sport": sport,
                "dport": dport,
                "flags": flags,
                "protocol": resolve_proto(packet[IP].proto),
                "qname": qname,
                "length": len(packet),
                "time": packet.time
            }
            result.append(entry)

        if ARP in packet:
            entry = {
                "src": packet[ARP].psrc,      # IP claiming
                "mac": packet[ARP].hwsrc,     # MAC claiming it
                "protocol": "ARP",
                "dst": packet[ARP].pdst,
                "qname": None,
                "sport": None,
                "dport": None,
                "flags": None,
                "length": len(packet),
                "time": packet.time
            }
            result.append(entry)
    return result
