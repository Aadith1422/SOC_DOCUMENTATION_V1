
# QRadar 101 Challenge – Investigation Report

## a) QRadar 101 Challenge

### i) Challenge Overview and Objectives

The **QRadar 101 Challenge** simulates a real-world security incident involving a compromised financial organization. Multiple systems were affected, and alerts indicated the use of known malicious tools, with suspicion of insider involvement.

The objective of this challenge was to investigate the incident using **IBM QRadar SIEM**, analyze security logs from multiple sources, correlate events, identify attacker behavior, and reconstruct the complete attack timeline.

Key objectives:
- Understand QRadar SIEM architecture and workflows
- Perform log analysis and event correlation
- Identify attacker techniques using MITRE ATT&CK
- Apply structured SOC investigation methodology

---

### ii) Step-by-Step Methodology Followed

1. Reviewed the incident scenario and identified investigation scope.  
2. Identified available log sources (Sysmon, PowerShell, Windows Event Logs, Suricata IDS, Zeek).  
3. Analyzed logs using filters based on event IDs, payloads, IPs, usernames, and timestamps.  
4. Correlated events to identify initial access, persistence, lateral movement, and exfiltration.  
5. Mapped attacker techniques to MITRE ATT&CK (e.g., T1547.001 – Registry Run Keys).  
6. Validated findings by cross-referencing logs and timelines.

---

### iii) Screenshots Showing Progress and Key Investigation Steps

Screenshots from the QRadar 101 walkthrough and reference materials were captured to document:
- Log source configuration
- Event filtering and analysis
- Detection of malicious activity
- MITRE ATT&CK mapping

> Note: Due to enterprise resource requirements, a stable local QRadar deployment was not feasible. Screenshots from the walkthrough were used to document the investigation process.

---

### iv) Summary of Key Findings, Challenges Faced, and Resolutions

**Key Findings:**
- Initial infection via malicious document
- Lateral movement across internal systems
- Persistence via Windows Registry Run Keys
- Data exfiltration using command-line tools

**Challenges Faced:**
- High resource requirements of QRadar Community Edition
- Difficulty maintaining stable local deployment

**Resolutions:**
- Completed investigation using a walkthrough-based approach
- Focused on SOC analysis methodology and threat detection logic

---

## b) Comparison of WebStrike and QRadar 101 Challenges

| Aspect | WebStrike | QRadar 101 |
|------|----------|------------|
| Focus | Network & Web Attacks | SIEM-Based Investigation |
| Data | PCAP, Web Logs | Aggregated Security Logs |
| Tools | Wireshark | IBM QRadar |
| Learning | Attack Execution | Attack Detection |

Together, both challenges provided end-to-end visibility from attack execution to detection and response.

---

## c) Conclusion: SOC Skill Enhancement

These challenges enhanced:
- Incident investigation workflows
- Log correlation and analysis
- Threat detection and MITRE ATT&CK mapping
- SOC analyst decision-making skills

Overall, the tasks provided strong exposure to real-world SOC operations and enterprise SIEM investigations.