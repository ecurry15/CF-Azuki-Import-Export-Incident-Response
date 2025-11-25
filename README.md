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
  
### **Attack Chain** *(What did the attacker do?)*

## **Initial Access (TA0001):**   
T1078.003 - The attacker gained access using valid local credentials via RDP

## **Execution (TA0002):**  
T1059.001 - PowerShell was used to run the Malicious Script "wupdate.ps1"

## **Persistence (TA0003):**  
T1053.005 - The attacker created a Scheduled Task to run the malicious payload

## **Defense Evasion (TA0005):**  
T1564.001/T1036.008/T1564.001/T1105 - The attacker created a malware staging directory, excluded file extensions and folders from Windows Defender scanning, and abused certutil.exe to download files.

## **Discovery (TA0007):**  
T1016 - the attacher used Arp.exe and Ipconfig / all to perform network reconnaissance

## **Credential Access (TA0006):**  
T1003.001 - The attacker used the credential dumping tool Mimikatz

## **Lateral Movement (TA0008):**  
T1021.001 - The attacker used the mstsc.exe /V:<IP> command to attempt lateral movement.

## **Collection (TA0009):**    
T1560.001 - The attacker created a file "export-data.zip" for data exfiltration

## **Command & Control (TA0011):**    
T1071.001 - Command and Control communications established over port 443

## **Exfiltration (TA0010):**    
T1567 - The website Discord was used to exfiltrate stolen data

## **Impact (TA0040):**    
T1136.001 - The attacker created a backdoor account named "support" for persistence.
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
