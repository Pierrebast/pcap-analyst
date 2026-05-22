from scapy.all import rdpcap, IP, TCP, UDP

def resolve_proto(number):
    if number==6:
        return "TCP"
    elif number==17:
        return "UDP"
    else:
        return "OTHER"

def parse_pcap(filepath):
    packets = rdpcap(filepath)
    result = []

    for packet in packets:
        if IP in packet:
            entry = {
                "src": packet[IP].src,
                "dst": packet[IP].dst,
                "protocol": resolve_proto(packet[IP].proto),
                "length": len(packet),
                "time": packet.time
            }
            result.append(entry)
    return result
