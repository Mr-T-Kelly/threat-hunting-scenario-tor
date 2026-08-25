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

### 1. File Download - TOR Installer

- **Timestamp:** `2024-11-08T22:14:48.6065231Z`
- **Event:** The user "employee" downloaded a file named `tor-browser-windows-x86_64-portable-14.0.1.exe` to the Downloads folder.
- **Action:** File download detected.
- **File Path:** `C:\Users\employee\Downloads\tor-browser-windows-x86_64-portable-14.0.1.exe`

### 2. Process Execution - TOR Browser Installation

- **Timestamp:** `2024-11-08T22:16:47.4484567Z`
- **Event:** The user "employee" executed the file `tor-browser-windows-x86_64-portable-14.0.1.exe` in silent mode, initiating a background installation of the TOR Browser.
- **Action:** Process creation detected.
- **Command:** `tor-browser-windows-x86_64-portable-14.0.1.exe /S`
- **File Path:** `C:\Users\employee\Downloads\tor-browser-windows-x86_64-portable-14.0.1.exe`

### 3. Process Execution - TOR Browser Launch

- **Timestamp:** `2024-11-08T22:17:21.6357935Z`
- **Event:** User "employee" opened the TOR browser. Subsequent processes associated with TOR browser, such as `firefox.exe` and `tor.exe`, were also created, indicating that the browser launched successfully.
- **Action:** Process creation of TOR browser-related executables detected.
- **File Path:** `C:\Users\employee\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe`

### 4. Network Connection - TOR Network

- **Timestamp:** `2024-11-08T22:18:01.1246358Z`
- **Event:** A network connection to IP `176.198.159.33` on port `9001` by user "employee" was established using `tor.exe`, confirming TOR browser network activity.
- **Action:** Connection success.
- **Process:** `tor.exe`
- **File Path:** `c:\users\employee\desktop\tor browser\browser\torbrowser\tor\tor.exe`

### 5. Additional Network Connections - TOR Browser Activity

- **Timestamps:**
  - `2024-11-08T22:18:08Z` - Connected to `194.164.169.85` on port `443`.
  - `2024-11-08T22:18:16Z` - Local connection to `127.0.0.1` on port `9150`.
- **Event:** Additional TOR network connections were established, indicating ongoing activity by user "employee" through the TOR browser.
- **Action:** Multiple successful connections detected.

### 6. File Creation - TOR Shopping List

- **Timestamp:** `2024-11-08T22:27:19.7259964Z`
- **Event:** The user "employee" created a file named `tor-shopping-list.txt` on the desktop, potentially indicating a list or notes related to their TOR browser activities.
- **Action:** File creation detected.
- **File Path:** `C:\Users\employee\Desktop\tor-shopping-list.txt`

---

## Summary

The user "employee" on the "threat-hunt-lab" device initiated and completed the installation of the TOR browser. They proceeded to launch the browser, establish connections within the TOR network, and created various files related to TOR on their desktop, including a file named `tor-shopping-list.txt`. This sequence of activities indicates that the user actively installed, configured, and used the TOR browser, likely for anonymous browsing purposes, with possible documentation in the form of the "shopping list" file.

---

## Response Taken

TOR usage was confirmed on the endpoint `threat-hunt-lab` by the user `employee`. The device was isolated, and the user's direct manager was notified.

---
