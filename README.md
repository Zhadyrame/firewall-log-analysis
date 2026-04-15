# firewall-log-analysis
# Firewall Audit & NAT Analysis (SZK 3310)

## Overview
This project was completed as part of the course "Network Protection and Countermeasures (SZK 3310)".

The purpose of this lab is to analyze firewall traffic logs and identify:
- firewall misconfigurations
- suspicious outbound connections
- NAT (SNAT/DNAT) issues
- possible security threats such as port scanning and data exfiltration

---

## Technologies Used
- Python 3
- pandas
- matplotlib
- reportlab
- scapy (optional)

---

## Project Structure

.
├── main.py
├── firewall_traffic.csv
├── charts/
│ ├── chart1_allow_deny_per_hour.png
│ ├── chart2_top_ports_split_by_action.png
│ └── chart3_heatmap_top_src_vs_ports.png
├── report.pdf
└── README.md


---

## How to Run

1. Clone the repository:

git clone https://github.com/your-username/firewall-analysis.git

cd firewall-analysis


2. Install dependencies:

pip install pandas numpy matplotlib reportlab


3. Run the script:

python main.py


---

## Functionality

### Traffic Analysis
- calculates ALLOW and DENY sessions per hour
- finds top source IP addresses
- identifies most frequently targeted destination ports

### Security Analysis
- detects outbound connections to high-risk ports (4444, 6667, 1080, 9050)
- identifies unusually large data transfers
- highlights potentially compromised internal hosts

### NAT Analysis
- extracts DNAT mappings (external to internal)
- identifies exposed internal services (SSH, RDP, databases)
- checks for possible SNAT or routing issues

---

## Output

The script generates:
- charts saved in the "charts" folder
- a PDF report with findings and evidence

---

## Key Findings

- Internal database exposed through DNAT:
  203.0.113.1:3306 → 10.10.2.50:3306

- Suspicious outbound traffic:
  10.10.3.15 → 91.108.56.130:9050

- Signs of port scanning from external IP

---

## Recommendations

- restrict DNAT rules and allow only trusted sources
- apply default-deny outbound policy
- block non-standard and high-risk ports
- enable logging for all firewall rules
- use MFA for remote access services

---

## Author
Zhadyra Rystemkyzy

---

## References
- Wireshark Documentation
- Scapy Documentation
- NIST SP 800-41
