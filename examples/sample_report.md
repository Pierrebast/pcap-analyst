# Network Security Analysis Report

## Executive Summary
Two hosts on the internal network (10.2.28.2 and 10.2.28.88) exhibited suspicious scanning behavior. Host 10.2.28.88 also generated numerous DNS queries that triggered tunneling alerts, though these appear to be **false positives** from legitimate Active Directory operations.

---

## Detailed Findings

### 1. Port Scan from 10.2.28.2
**Severity: HIGH**

**What Happened:**
- Host 10.2.28.2 contacted 379 unique ports, indicating an aggressive network scan
- This is characteristic reconnaissance activity mapping network services

**Attacker Intent:**
- Service discovery and network mapping
- Identifying potential vulnerable services for exploitation
- Preparing for lateral movement or targeted attacks

**Recommended Actions:**
- **IMMEDIATE**: Isolate 10.2.28.2 and investigate for compromise indicators
- Review authentication logs for this host
- Check for malware/backdoors on the system
- Examine what services were targeted
- Review firewall logs for any successful connections

---

### 2. Port Scan from 10.2.28.88
**Severity: MEDIUM**

**What Happened:**
- Host 10.2.28.88 contacted 15 unique ports
- Much smaller scope than 10.2.28.2 but still anomalous

**Attacker Intent:**
- Limited reconnaissance, possibly targeting specific services
- Could be automated tool/script behavior

**Recommended Actions:**
- Investigate the identity and purpose of this host
- Correlate with the DNS activity from the same host
- Check running processes and scheduled tasks

---

### 3. DNS "Tunneling" Alerts from 10.2.28.88
**Severity: LOW (False Positive)**

**What Happened:**
- 48 DNS queries triggered alerts for length and volume
- All queries follow pattern: `_ldap._tcp.Default-First-Site-Name._sites.*`
- Domains include: mshome.net, easyas123.tech, EASYAS123-DC.easyas123.tech

**Analysis:**
These are **legitimate Active Directory DNS SRV record queries**, NOT DNS tunneling:
- `_ldap._tcp` queries are standard for AD domain controller location
- The naming convention matches Microsoft Active Directory Site and Service discovery
- The domains suggest a corporate AD environment (easyas123.tech)
- Long DNS names are normal for AD infrastructure queries

**Recommended Actions:**
- **No immediate action required** for DNS alerts
- Adjust detection thresholds to whitelist legitimate AD DNS patterns
- Verify 10.2.28.88 is an authorized domain member

---

## Priority Response Plan

### Critical (Within 1 Hour):
1. Investigate and isolate **10.2.28.2** - this is the primary threat
2. Pull memory dump and disk forensics from 10.2.28.2
3. Check for outbound C2 communications from 10.2.28.2

### High (Within 4 Hours):
4. Investigate **10.2.28.88** for potential compromise
5. Correlate both hosts - check if they're related to the same incident
6. Review network segmentation - why could these hosts scan so many ports?

### Medium (Within 24 Hours):
7. Tune IDS/detection rules to reduce AD-related false positives
8. Implement network segmentation if not already in place
9. Deploy host-based security monitoring on both systems

---

## Key Indicators of Compromise
- **10.2.28.2**: Aggressive port scanning (379 ports)
- **10.2.28.88**: Moderate port scanning (15 ports)

**Likelihood**: High probability that at least 10.2.28.2 is compromised or being used maliciously.