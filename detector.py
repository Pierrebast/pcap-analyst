from collections import defaultdict

PORTSCAN_THRESHOLD = 15  # number of unique ports to flag

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