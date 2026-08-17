# Case Study 01: Emotet Malware Network & Endpoint Traffic Analysis

## Executive Summary
* **Date of Investigation:** August 2026
* **Investigator:** Atta Kouhzad
* **Threat Classification:** Banking Trojan / Botnet Initial Access Loader (Emotet)
* **Target Asset:** `10.0.0.142` (`WIN-WORKSTATION-01`)
* **Incident Status:** Fully Analyzed & Contained

---

## Technical Scenario & Trigger
A network anomaly alert flagged suspicious outbound HTTP GET requests containing encoded query parameters originating from internal workstation `10.0.0.142`. The objective of this investigation was to analyze packet captures (PCAP) and endpoint event logs to confirm malware execution, extract command-and-control (C2) infrastructure, and document indicators of compromise (IOCs).

---

## Technical Investigation & Key Findings

### Phase 1: Malicious Attachment & Execution (Initial Access)
* **Vector:** Macro-enabled Word Document delivered via phishing email.
* **Execution:** Upon opening, embedded VBA macros invoked `cmd.exe`, which spawned an obfuscated PowerShell script to fetch the secondary payload from a compromised web server.
* **Evidence:** Sysmon Event ID 1 (Process Creation) recorded `powershell.exe` executing with hidden window attributes (`-W Hidden -e ...`).

### Phase 2: C2 Beaconing & Payload Retrieval
* **HTTP Requests:** PCAP analysis in Wireshark revealed repeated HTTP GET requests to `185.159.82.15` on port `8080`.
* **User-Agent Anomaly:** Requests utilized a non-standard User-Agent string, bypassing standard browser parameters.
* **Payload Delivery:** An encrypted `.dll` payload was transferred over HTTP and loaded dynamically using `rundll32.exe`.

---

## Indicators of Compromise (IOCs)

| Type | Indicator / Value | Description / Context |
| :--- | :--- | :--- |
| **IPv4** | `185.159.82.15` | Active Emotet Command & Control (C2) Server |
| **Domain** | `compromised-vendor-site.com` | Staging server hosting the primary DLL payload |
| **SHA-256** | `4f3a9a81c7e2b109d3b841289c02b3e4f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6` | Malicious Emotet Loader DLL |
| **Process** | `rundll32.exe` | Executed payload via `C:\Users\Public\msupdate.dll,PluginInit` |

---

## Root Cause & Mitigation Recommendations

1. **Immediate Containment:**
   * Isolate host `10.0.0.142` via Endpoint Detection and Response (EDR).
   * Block C2 IP `185.159.82.15` at perimeter firewalls and proxies.
   * Revoke active user session credentials associated with `WIN-WORKSTATION-01`.

2. **Long-Term Hardening:**
   * Disable Office VBA macros globally via Group Policy Object (GPO) for non-essential user groups.
   * Enforce PowerShell Constrained Language Mode and ScriptBlock Logging (Event ID 4104).
   * Apply Attack Surface Reduction (ASR) rules to prevent Office applications from spawning child processes.

## Root Cause & Mitigation Recommendations

1. **Short-Term Containment:** Block identified IOCs at the perimeter firewall/proxy and isolate the affected host via EDR.
2. **Long-Term Hardening:** Implement email attachment filtering for compressed/executable extensions and enable Attack Surface Reduction (ASR) rules.
* [Case 01: Emotet Traffic Analysis](Case-01-Emotet-Traffic-Analysis/README.md)
