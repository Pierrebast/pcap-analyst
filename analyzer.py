import argparse
from parser import parse_pcap
from detector import detect_port_scan, detect_arp_spoof, detect_dns_tunneling
from reporter import generate_report

def main():
    parser = argparse.ArgumentParser(
        description="AI-powered pcap security analyzer"
    )
    parser.add_argument("--file", required=True, help="Path to .pcap file")
    args = parser.parse_args()

    findings = []
    data = parse_pcap(args.file)
    findings.extend(detect_port_scan(data))
    findings.extend(detect_arp_spoof(data))
    findings.extend(detect_dns_tunneling(data))
    report = generate_report(findings,args.file)

    print(report)



if __name__ == "__main__":
    main()