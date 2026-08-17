# Case Study 02: Active Directory Lateral Movement & Privilege Escalation (BOTS)

## Executive Summary
* **Date of Investigation:** August 2026
* **Investigator:** Atta Kouhzad
* **Threat Classification:** Enterprise Lateral Movement & Credential Access (MITRE ATT&CK TA0008 / TA0006)
* **Target Environment:** Enterprise Active Directory Domain (`corp.local`)
* **Incident Status:** Analyzed, Mapped & Mitigated

---

## Technical Scenario & Trigger
During a routine Splunk threat hunting sweep across domain controllers and workstation endpoint logs, multiple high-risk anomalies were flagged: a single domain workstation (`WKSTN-02`) generated abnormal SMB session requests followed immediately by successful logon events using domain administrator privileges (`Event ID 4624`, Logon Type 3). The goal of this investigation was to reconstruct the adversary's lateral movement path, identify compromised accounts, and map all actions to the MITRE ATT&CK framework.

---

## Technical Investigation & Key Findings

### Phase 1: Credential Access & Initial Compromise
* **Vector:** Password spraying and local credential dumping (`LSASS` memory access) on host `WKSTN-02`.
* **Telemetry Analysis:** Splunk SPL queries filtering for `EventCode=4625` revealed a high frequency of failed authentication attempts within a short window, immediately followed by a successful logon (`EventCode=4624`) under user account `svc_backup`.
* **SPL Query Used:**
  ```spl
  index=botsv1 sourcetype="WinEventLog:Security" EventCode=4625 OR EventCode=4624
  | stats count dc(TargetUserName) as unique_users by src_ip, EventCode
  | where count > 10
