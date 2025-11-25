# 🕵️‍♂️ Threat Hunt Report: CF Azuki Import/Export
<img width="300" height="410" alt="Port-of-entry" src="https://github.com/user-attachments/assets/ad79de24-8cf9-4897-8556-ab8e8143930b" />


**Analyst:** Edward Campbell  
**Investigation Date:** 23-November-2025  
**Incident Date:** 19-November-2025  

## 🎯 EXECUTIVE SUMMARY

*Write this LAST - 3-5 sentences summarizing the entire incident*

**What Happened:**

---
## 🖥️ INCIDENT DETAILS
### **Timeline Overview**

- **First Malicious Activity:** 19 November 2025 18:36:18.503997Z
- **Last Observed Activity:** 22 November 2025 00:38:47.8327343Z
- **Total Duration:** 54 hours 2 minutes

### **Attack Overview**

- **Initial Access Method:** Remote Desktop Protocol
- **Compromised Account:** kenji.sato
- **Affected System:** azuki-sl
- **Attacker IP Address:** 88.97.178.12
  
## 🧬 MITRE ATT&CK Mapping (Attack Chain)

| Tactic | Technique ID | Description |
|-------|--------------|-------------|
| **Initial Access (TA0001)** | T1078.003 | The attacker gained access using valid local credentials via RDP. |
| **Execution (TA0002)** | T1059.001 | PowerShell was used to run the malicious script `wupdate.ps1`. |
| **Persistence (TA0003)** | T1053.005 | A Scheduled Task was created to run the malicious payload. |
| **Defense Evasion (TA0005)** | T1564.001 / T1036.008 / T1105 | Attacker used hidden directories, file-type masquerading, and abused `certutil.exe` to download tools. |
| **Discovery (TA0007)** | T1016 | `arp -a` and `ipconfig /all` used to enumerate local network configuration. |
| **Credential Access (TA0006)** | T1003.001 | Mimikatz was used for credential dumping. |
| **Lateral Movement (TA0008)** | T1021.001 | `mstsc.exe /V:<IP>` used to attempt RDP lateral movement. |
| **Collection (TA0009)** | T1560.001 | Data staged into `export-data.zip`. |
| **Command & Control (TA0011)** | T1071.001 | HTTPS (port 443) used for C2 to external IP. |
| **Exfiltration (TA0010)** | T1567 | Discord webhook used for data exfiltration. |
| **Impact (TA0040)** | T1136.001 | Backdoor account `support` created for persistent access. |



---




##  Flag 1 – Identify the source IP address of the Remote Desktop Protocol connection

**Finding**: The IP address `88.97.178.12` gained initial access to the VM `AZUKI-SL` at `2025-11-19T18:36:18.503997Z` via RDP by using valid user credentials. 

**Thoughts**: When creating the query, I filtered for only `Network` and `RemoteInteractive` logon types because these represent an RDP connection. I determined the IP was suspicious because it originates in the UK, which is not normal for business in Japan.

**KQL Query**:
```
DeviceLogonEvents
| where DeviceName == "azuki-sl"
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where ActionType == "LogonSuccess"
| where LogonType has_any ("Network", "RemoteInteractive")
| order by Timestamp desc

```
<img width="1905" height="549" alt="question1" src="https://github.com/user-attachments/assets/094c2159-f40a-427d-ba24-be689a6b74a1" />


---
##  Flag 2 – Identify the user account that was compromised for initial access

**Finding**: The User account `kenji.sato` was used by the attacker.

**Notes**: This evidence can be found when running the query in Flag 1.

---

##  Flag 3 – Identify the command and argument used to enumerate network neighbours

**Finding**: The attacher used the `Arp.exe` and `Ipconfig / all` commands to identify lateral movement opportunities at 2025-11-19T19:04:01.773778Z.

**Thoughts**:  When creating this query, I filtered for the most common commands that reveal local network devices.

**KQL Query**:
```
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where Timestamp between (datetime(2025-11-19T18:36:18.503997Z) .. datetime(2025-11-19T21:36:18.503997Z))
| where ProcessCommandLine has_any ("arp", "net", "nbtstat", "count", "get")
| order by Timestamp desc

```
<img width="1879" height="673" alt="Q3" src="https://github.com/user-attachments/assets/62d2dcec-76af-42e1-afc3-54b398923ee6" />

**Notes:**

---
##  Flag 4 – Identify the PRIMARY staging directory where malware was stored

**Objective**: 

**Finding**:  

**KQL Query**:
```
```

**Notes:**

---

##  Flag 5 – How many file extensions were excluded from Windows Defender scanning

**Objective**: 

**Finding**:  

**KQL Query**:
```
```

**Notes:**
---

##  Flag 6 – What temporary folder path was excluded from Windows Defender scanning

**Objective**: 

**Finding**:  

**KQL Query**:
```
```

**Notes:**

---
##  Flag 7 – Identify the Windows-native binary the attacker abused to download files

**Objective**: 

**Finding**:  

**KQL Query**:
```
```

**Notes:**
---

##  Flag 8 – Identify the name of the scheduled task created for persistence

**Objective**: 

**Finding**:  

**KQL Query**:
```
```

**Notes:**

---
##  Flag 9 – Identify the executable path configured in the scheduled task

**Objective**: 

**Finding**:  

**KQL Query**:
```
```

**Notes:**

---

##  Flag 10 –  Identify the IP address of the command and control server

**Objective**: 

**Finding**:  

**KQL Query**:
```
```

**Notes:**
---
##  Flag 11 – Identify the destination port used for command and control communications

**Objective**: 

**Finding**:  

**KQL Query**:
```
```

**Notes:**

---
##  Flag 12 – Identify the filename of the credential dumping tool

**Objective**: 

**Finding**:  

**KQL Query**:
```
```

**Notes:**
---

##  Flag 13 – Identify the module used to extract logon passwords from memory

**Objective**: 

**Finding**:  

**KQL Query**:
```
```

**Notes:**

---
##  Flag 14 – Identify the compressed archive filename used for data exfiltration

**Objective**: 

**Finding**:  

**KQL Query**:
```
```

**Notes:**

---

##  Flag 15 – Identify the cloud service used to exfiltrate stolen data

**Objective**: 

**Finding**:  

**KQL Query**:
```
```

**Notes:**
---
##  Flag 16 – Identify the first Windows event log cleared by the attacker

**Objective**: 

**Finding**:  

**KQL Query**:
```
```

**Notes:**

---
##  Flag 17 – Identify the backdoor account username created by the attacker

**Objective**: 

**Finding**:  

**KQL Query**:
```
```

**Notes:**
---

##  Flag 18 – Identify the PowerShell script file used to automate the attack chain

**Objective**: 

**Finding**:  

**KQL Query**:
```
```

**Notes:**

---
##  Flag 19 – What IP address was targeted for lateral movement

**Objective**: 

**Finding**:  

**KQL Query**:
```
```

**Notes:**

---

##  Flag 20 – Identify the remote access tool used for lateral movement

**Objective**: 

**Finding**:  

**KQL Query**:
```
```

**Notes:**
---

## **APPENDIX**

### **A. Key Indicators of Compromise (IOCs)**
**B. MITRE ATT&CK Mapping**
**C. Investigation Timeline**
---

**Report Completed By:** Edward Campbell

**Date:** ________________
