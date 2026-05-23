from scapy.all import rdpcap, IP, TCP, UDP

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
            elif UDP in packet:
                sport = packet[UDP].sport
                dport = packet[UDP].dport
            else:
                sport = None
                dport = None

            entry = {
                "src": packet[IP].src,
                "dst": packet[IP].dst,
                "sport": sport,
                "dport": dport,
                "protocol": resolve_proto(packet[IP].proto),
                "length": len(packet),
                "time": packet.time
            }
            result.append(entry)
    return result
