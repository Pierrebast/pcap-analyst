from collections import defaultdict
from config import PORTSCAN_THRESHOLD, DNSQ_THRESHOLD, DNS_LENGTH_THRESHOLD, ICMP_FLOOD_THRESHOLD, SYN_FLOOD_THRESHOLD

def detect_port_scan(packets):
    # packets is the list of dicts from parser.py
    findings = []
    
    # step 1 - group destination ports by source IP
    src_ports = defaultdict(set)

    for packet in packets:
        if packet["dport"] is not None:
            src_ports[packet["src"]].add(packet["dport"])
        
    
    for ip in src_ports:
        if len(src_ports[ip]) >= PORTSCAN_THRESHOLD:
            find= {
                    "type": "PORT SCAN",
                    "src": ip,
                    "ports_contacted": len(src_ports[ip]),
                    "details": f"{ip} contacted {len(src_ports[ip])} unique ports"
                }
            findings.append(find)
    
    return findings

def detect_arp_spoof(packets):

    findings = []

    mac_addr = defaultdict(set)

    for packet in packets:

        if packet["mac"] is not None:
            mac_addr[packet["src"]].add(packet["mac"])
    
    for ip in mac_addr:
        if len(mac_addr[ip]) > 1:
            find = {
                    "type": "ARP SPOOFING",
                    "src": ip,
                    "macs_detected": list(mac_addr[ip]),
                    "details": f"{ip} is claimed by {len(mac_addr[ip])} different MAC addresses - possible ARP spoofing"
                }
            findings.append(find)
    return findings

def detect_dns_tunneling(packets):

    findings = []

    dns_queries = defaultdict(set)

    for packet in packets:
        if packet["qname"] is not None:
            dns_queries[packet["src"]].add(packet["qname"])
            if len(packet["qname"]) > DNS_LENGTH_THRESHOLD:
                entry = {

                    "type": "DNS tunneling",
                    "src": packet["src"],
                    "query_length": len(packet["qname"]),
                    "details": f"{packet['src']} contains unusual long DNS query {packet['qname']} - possible DNS tunneling."
                }
                findings.append(entry)

    for q in dns_queries:
        if len(dns_queries[q]) > DNSQ_THRESHOLD:
            entry = {

                    "type": "DNS tunneling",
                    "src": q,
                    "number_queries": len(dns_queries[q]),
                    "details": f"{q} performs more than threshold DNS queries - possible DNS tunneling."
                }
            findings.append(entry)
    return findings

def detect_icmp_flood(packets):

    findings = []

    count = defaultdict(int)

    for packet in packets:

        if packet["protocol"] == "ICMP":
            count[packet["src"],packet["dst"]] +=1

    for src,dst in count:   
        if count[src,dst] > ICMP_FLOOD_THRESHOLD:
            entry = {
                "type": "ICMP FLOOD",
                "src": src,
                "dst": dst,
                "packet_count": count[src,dst],
                "details": f"{src} sent {count[src,dst]} ICMP packets to {dst} - possible ICMP flood"
            }
            findings.append(entry)
    return findings

def detect_syn_flood(packets):

    findings = []

    count = defaultdict(int)

    for packet in packets:
        if packet["flags"] == "S":
            count[packet["src"],packet["dst"]] += 1

    for src,dst in count:
        if count[src,dst] > SYN_FLOOD_THRESHOLD:
            entry = {
                "type": "SYN FLOOD",
                "src": src,
                "dst": dst,
                "packet_count": count[src,dst],
                "details": f"{src} sent {count[src,dst]} SYN packets to {dst} - possible SYN flood"
            }
            findings.append(entry)
    return findings
