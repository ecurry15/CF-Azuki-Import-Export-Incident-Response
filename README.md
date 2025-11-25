# 🕵️‍♂️ Threat Hunt Report: CF Azuki Import/Export

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
  
## 🧬 MITRE ATT&CK Mapping

### **Initial Access (TA0001)**
- **T1078.003** – Valid Accounts  
  The attacker gained access via valid RDP credentials.

### **Execution (TA0002)**
- **T1059.001** – PowerShell  
  Malicious script `wupdate.ps1` executed.

### **Persistence (TA0003)**
- **T1053.005** – Scheduled Task  
  A scheduled task was created to run the malicious payload.

### **Defense Evasion (TA0005)**
- **T1564.001 / T1036.008 / T1105**  
  Hidden directories, file masquerading, and downloading via `certutil.exe`.

### **Discovery (TA0007)**
- **T1016** – System Network Discovery  
  Used `arp -a` and `ipconfig /all`.

### **Credential Access (TA0006)**
- **T1003.001** – LSASS Memory Dumping  
  Mimikatz was executed.

### **Lateral Movement (TA0008)**
- **T1021.001** – Remote Desktop Protocol  
  Attempted RDP movement to target VM.

### **Collection (TA0009)**
- **T1560.001** – Archive Collected Data  
  Data staged into `export-data.zip`.

### **Command & Control (TA0011)**
- **T1071.001** – Web Protocols  
  C2 via HTTPS over port 443.

### **Exfiltration (TA0010)**
- **T1567** – Exfiltration Over Web Services  
  Data exfiltrated via Discord webhook.

### **Impact (TA0040)**
- **T1136.001** – Create Account  
  Backdoor account “support” created.



---




##  Flag 1 – Identify the source IP address of the Remote Desktop Protocol connection

**Objective**: 

**Finding**:  

**KQL Query**:
```
```

**Notes:**

---
##  Flag 2 – Identify the user account that was compromised for initial access

**Objective**: 

**Finding**:  

**KQL Query**:
```
```

**Notes:**
---

##  Flag 3 – Identify the command and argument used to enumerate network neighbours

**Objective**: 

**Finding**:  

**KQL Query**:
```
```

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
