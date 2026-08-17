# Case Study 01: Network & Endpoint Investigation – [Infection / Attack Name]

## Executive Summary
* **Date of Investigation:** August 2026
* **Investigator:** Atta Kouhzad
* **Threat Classification:** [e.g., Trojan / Malicious DLL Delivery via Phishing]
* **Impacted Assets:** Workstation-01 (`192.168.1.105` / `USER-PC`)
* **Incident Status:** Contained & Remediated

---

## Technical Investigation & Timeline

### Phase 1: Initial Discovery
* **Observation:** Identify the anomaly or initial alert trigger (e.g., suspicious HTTP GET request returning a `.zip` or `.dll` payload).
* **Evidence:** Insert a Wireshark / SIEM screenshot showing the raw packet or log line.

### Phase 2: Threat Analysis & Artifact Extraction
* **Network Analysis:** Wireshark display filters used (`http.request` or `ip.addr == ...`), C2 domains identified, user-agent anomalies.
* **Host/Endpoint Analysis:** Executed process trees, Registry changes, or PowerShell commands.

---

## Indicators of Compromise (IOCs)

| Type | Indicator | Description / Context |
| :--- | :--- | :--- |
| **IP Address** | `192.0.2.45` | Malicious C2 Server |
| **Domain** | `malicious-phish-site.com` | Payload Hosting URL |
| **SHA-256** | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` | Malicious Loader DLL |

---

## Root Cause & Mitigation Recommendations

1. **Short-Term Containment:** Block identified IOCs at the perimeter firewall/proxy and isolate the affected host via EDR.
2. **Long-Term Hardening:** Implement email attachment filtering for compressed/executable extensions and enable Attack Surface Reduction (ASR) rules.
* [Case 01: Emotet Traffic Analysis](Case-01-Emotet-Traffic-Analysis/README.md)
