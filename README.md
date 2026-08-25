# Official [Cyber Range](http://joshmadakor.tech/cyber-range) Project

<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/Mr-T-Kelly/threat-hunting-scenario-tor/blob/main/threat-hunting-scenario-tor-event-creation.md)

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Tor Browser

##  Scenario

Management suspects that some employees may be using TOR browsers to bypass network security controls because recent network logs show unusual encrypted traffic patterns and connections to known TOR entry nodes. Additionally, there have been anonymous reports of employees discussing ways to access restricted sites during work hours. The goal is to detect any TOR usage and analyze related security incidents to mitigate potential risks. If any use of TOR is found, notify management.

### High-Level TOR-Related IoC Discovery Plan

- **Check `DeviceFileEvents`** for any `tor(.exe)` or `firefox(.exe)` file events.
- **Check `DeviceProcessEvents`** for any signs of installation or usage.
- **Check `DeviceNetworkEvents`** for any signs of outgoing connections over known TOR ports.

---

## Steps Taken

### 1. Searched the `DeviceFileEvents` Table

Searched the DeviceFileEvents table for ANY file that had the string “tor” in it and discovered what looks like the user “vicone” downloaded a tor installer, did something that resulted in many tor-related files being copied to the desktop and the creation of a file called “Tor_shopping_list.txt” on the desktop at 2026-06-02T20:08:20.1616192Z. These events began at:2026-06-02T19:52:03.616004Z.

**Query used to locate events:**

```kql
DeviceFileEvents
| where FileName startswith "tor"
| where DeviceName contains "litefoot"
| where Timestamp >= datetime(2026-06-02T19:52:03.616004Z)
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName
```
<img width="875" height="305" alt="image" src="https://github.com/user-attachments/assets/bc19808a-753d-47d1-bbc9-5105dc2ac1af" />


---

### 2. Searched the `DeviceProcessEvents` Table

Searched for any ProcessCommandLine that contained the string “tor-browser-windows-x86_64-portable-15.0.13.exe”. Based on the logs returned at 2026-06-02T19:54:58.7912258Z, User vicone executed the Tor Browser Portable 15.0.13 installer from their Downloads directory on device litefoot. The installer was launched with the /S silent installation switch, indicating an unattended or automated installation of the Tor Browser software. No evidence from this event alone indicates malicious activity, but the use of anonymity software may warrant additional review depending on organizational policy.

**Query used to locate event:**

```kql

DeviceProcessEvents
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-15.0.13.exe  /S"
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
| where DeviceName contains "litefoot"
```
<img width="923" height="304" alt="image" src="https://github.com/user-attachments/assets/e432c793-a38b-40cc-8f38-ebfa105cb7df" />

---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Searched for any indication that user “vicone” actually opened the tor browser. There was evidence that they did open it at 2026-06-02T19:55:23.3787979Z There were several other instances of firefox.exe (Tor) as well as tor.exe spawned afterward

**Query used to locate events:**

```kql
DeviceProcessEvents
| where ProcessCommandLine has_any("tor.exe","firefox.exe", "tor-browser.exe")
| project  Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
| where DeviceName contains "litefoot"
| order by Timestamp desc
```
<img width="947" height="377" alt="image" src="https://github.com/user-attachments/assets/769c29f7-1c6f-4349-9657-ef0f4786418c" />


---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Searched for any indication the TOR browser was used to establish a connection using any of the known TOR ports. On 2026-06-02T19:55:58.9203658Z, the user vicone on device litefoot successfully established a network connection using tor.exe, the Tor Browser networking component. The process connected from the local Tor Browser installation located on the desktop to the remote IP address 65.21.94.13 over TCP port 9001, which is commonly used by Tor relay nodes. This activity indicates that the Tor software was functioning and communicating with the Tor network following its installation. There were a few other connections.

**Query used to locate events:**

```kql
DeviceNetworkEvents
| where InitiatingProcessFileName in~ ("tor.exe", "firefox.exe")
| where RemotePort in (9001, 9030, 9040, 9050, 9051, 9150)
| where DeviceName contains "litefoot"
| project Timestamp, DeviceName, InitiatingProcessAccountName,ActionType, InitiatingProcessFileName, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFolderPath
| order by Timestamp desc
```
<img width="933" height="181" alt="image" src="https://github.com/user-attachments/assets/b37c7837-d0c3-430e-904c-da3b0f753b1f" />


---

## Chronological Event Timeline 

### 1. Recent File Shortcut 

- **Timestamp:** 3:52:03 PM
- **Event:** Created Windows created a recent-file shortcut:
  This indicates the user accessed a file named TORinst, likely associated with a Tor installation package.
- **Action:** FileCreated File: TORinst.lnk
- **File Path** C:\Users\vicone\AppData\Roaming\Microsoft\Windows\Recent\TORinst.lnk

### 2. Tor Browser Installer Executed
 - **Timestamp:** 3:54:58 PM
 - **Event:** User vicone executed the Tor Browser Portable installer from the Downloads directory: 
C:\Users\vicone\Downloads\tor-browser-windows-x86_64-portable-15.0.13.exe 
The installer was launched with the command: 
tor-browser-windows-x86_64-portable-15.0.13.exe /S 
The /S switch indicates a silent or unattended installation. 
- **Action:** ProcessCreated
- **File Path:** C:\Users\vicone\Downloads\tor-browser-windows-x86_64-portable-15.0.13.exe
  
### 3. Tor Browser Files Installed
- **Timestamp:** 3:55:12 PM
- **Event:** Several Tor-related files were created on the desktop as part of the installation
Files observed include:
- ***- Tor-Launcher.txt***
- ***- Torbutton.txt***
- ***- tor.txt***
- ***- tor.exe***
- These file creation events indicate that the Tor Browser package was successfully extracted and installed.
- **Action:** FileCreated
- **File Path:** C:\Users\vicone\Desktop\Tor Browser\

### 4. Tor Browser Shortcut Created
- **Timestamp:** 3:55:17 PM 
- **Event:** A desktop shortcut was created:
This confirms completion of the installation process and creation of a launch shortcut.
- **Action:** FileCreated
- **File Path:** C:\Users\vicone\Desktop\Tor Browser\Tor Browser.lnk
  
### 5. Tor Browser Launched
- **Timestamp:** 3:55:23 PM
- **Event:** Two instances of firefox.exe were started from the
Tor Browser installation directory. Tor Browser is built on Firefox, so these process creation events indicate the browser
was opened by the user.
- **Action:** ProcessCreated
- **Executable:** firefox.exe

### 6. Browser Support Processes Spawned 
- **Timestamp:** 3:55:25 PM
- **Event:** A Firefox GPU process was launched. 
This is a normal browser component used for graphics rendering. 
- **Action:** ProcessCreated 
- **Executable:** firefox.exe

### 7. Tor Service Started 
- **Timestamp:** 3:55:26 PM
- **Event:** The Tor networking component was launched:
tor.exe 
The command line shows Tor was started using the default Tor Browser configuration files and local SOCKS proxy settings: 
127.0.0.1:9150 
This process is responsible for establishing encrypted connections into the Tor network. 
- **Action:** ProcessCreated 
- **Executable:** tor.exe

### 8. Additional Tor Browser Processes Spawned
- **Timestamp:** 3:55:26 PM – 3:55:27 PM
- **Event:** Multiple Firefox child processes were launched, including:
- ***- Browser tab processes*** 
- ***- Utility processes*** 
- ***- GPU process*** 
- ***- RDD process (media decoding)*** 
- These are normal components of a modern Firefox-based browser and indicate that Tor Browser initialized successfully. 
- **Action:** ProcessCreated 
- **Executable:** firefox.exe

### 9. Successful Connection to Tor Network
- **Timestamp:** 3:55:58 PM 
- **Event:** The Tor process successfully established a network connection. This event confirms that Tor Browser successfully connected to the Tor network and was operational.  
- **Remote IP:** 65.21.94.13 
- **Remote Port:** 9001 
Port 9001 is commonly used by Tor relay nodes. 
 - **Action:** ConnectionSuccess
- **Executable:** tor.exe

### 10. Continued Browser Activity
- **Timestamp:** 3:57 PM – 4:05 PM
- **Event:** Additional Firefox/Tor Browser processes continued to spawn. The timestamps indicate Tor Browser remained open and in use for at least approximately 10 minutes after launch.
Observed activity included: 
- ***- Additional tab processes*** 
- ***- Browser content processes*** 
- ***- User interaction with the browser*** 
 
- **Action:** ProcessCreated 
- **Executable:** firefox.exe

### 11. Tor-Related Text File Created
- **Timestamp:** 4:08:20 PM
- **Event:** A file named: Tor_shopping_list.txt
 was created via a file rename operation. 
A corresponding Windows Recent Items shortcut was also created: 
Tor_shopping_list.lnk 
This indicates the file was likely opened or interacted with by the user shortly after creation. 
- **Action:** File Created
- **File Path:** C:\Users\vicone\Desktop\Tor_shopping_list.txt

### 12. Tor Shopping List Modified
- **Timestamp:** 4:08:45 PM
- **Event:**
The file: Tor_shopping_list.txt 
was modified approximately 25 seconds after creation. 
This indicates user interaction and editing activity. 
- **Action:** FileModified 
- **File:** Tor_shopping_list.txt


---

## Summary

The investigation determined that user vicone downloaded and executed Tor Browser Portable 15.0.13 on device litefoot on June 2, 2026.
The user executed the Tor Browser installer using the /S silent installation switch, resulting in the extraction of Tor Browser files to the Desktop.
Within seconds of installation, the user launched Tor Browser, causing both firefox.exe and tor.exe processes to start. The Tor networking component successfully connected to a remote host over TCP port 9001, confirming that the application established connectivity with the Tor network.
Process creation activity indicates the browser remained active for approximately ten minutes after launch. During this timeframe, a file named Tor_shopping_list.txt was created and subsequently modified on the desktop, suggesting user interaction while Tor Browser was installed and operational.
Overall, the available telemetry confirms the complete sequence of Tor Browser acquisition, installation, execution, successful network connectivity to the Tor network, and subsequent user activity on the system. No evidence within the reviewed logs indicates malicious execution, persistence mechanisms, privilege escalation, or other suspicious activity beyond the installation and use of Tor Browser itself.
---

## Response Taken

TOR usage was confirmed on the endpoint `threat-hunt-lab` by the user `employee`. The device was isolated, and the user's direct manager was notified.

---
