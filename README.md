# Official [Cyber Range](http://joshmadakor.tech/cyber-range) Project

<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/ibrahim-negib/threat-hunting-scenario-tor/blob/main/threat-hunting-scenario-tor-event-creation.md)

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

Searched for any file that had the string "tor" in it and discovered what looks like the user "inegib" downloaded a TOR installer, did something that resulted in many TOR-related files being copied to the desktop, and the creation of a file called tor-shopping-list.txt on the desktop at Nov 20, 2025 1:21:39 PM. These events began at Nov 20, 2025 1:05:05 PM. 

**Query used to locate events:**

```kql
DeviceFileEvents  
| where DeviceName == "ibrahim-win11"  
| where FileName contains "tor"  
| order by Timestamp desc  
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName
```
<img width="1808" height="392" alt="Screenshot 2025-11-20 at 2 08 35 PM" src="https://github.com/user-attachments/assets/2616e45e-177b-4cc9-b351-7caaf1a0718d" />

---

### 2. Searched the `DeviceProcessEvents` Table

Searched for any ProcessCommandLine that contained the string "tor-browser". Based on the logs returned, at Nov 20, 2025 1:33:29 PM, an employee on the "ibrahim-win11" device ran the file tor-browser-windows-x86_64-portable-14.0.1.exe from their Downloads folder, using a command that triggered a silent installation.

**Query used to locate event:**

```kql
DeviceProcessEvents  
| where DeviceName == "ibrahim-win11"  
| where ProcessCommandLine contains "tor-browser"  
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
```
<img width="1853" height="276" alt="Screenshot 2025-11-20 at 2 06 07 PM" src="https://github.com/user-attachments/assets/92181530-68ca-40ed-8473-5b1622da2fe3" />

---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Searched for any indication that user "inegib" actually opened the TOR browser. There was evidence that they did open it at Nov 20, 2025 1:06:34 PM. There were several other instances of firefox.exe (TOR) as well as tor.exe spawned afterwards.

**Query used to locate events:**

```kql
DeviceProcessEvents  
| where DeviceName == "ibrahim-win11"  
| where FileName has_any ("tor.exe", "firefox.exe", "tor-browser.exe")  
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine  
| order by Timestamp desc
```
<img width="1830" height="486" alt="Screenshot 2025-11-20 at 2 11 11 PM" src="https://github.com/user-attachments/assets/871abb13-abe3-4d60-b015-5fd35ef7c761" />

---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Searched for any indication the TOR browser was used to establish a connection using any of the known TOR ports. At `Nov 20, 2025 1:09:54 PM`, an employee on the "ibrahim-win11" device successfully established a connection to the remote IP address `162.55.107.247` on port `9001`. The connection was initiated by the process `tor.exe`, located in the folder `c:\users\inegib\desktop\tor browser\browser\torbrowser\tor\tor.exe`. There were a couple of other connections to sites over port `443`.

**Query used to locate events:**

```kql
DeviceNetworkEvents  
| where DeviceName == "ibrahim-win11"  
| where InitiatingProcessAccountName != "system"  
| where InitiatingProcessFileName in ("tor.exe", "firefox.exe")  
| where RemotePort in ("9001", "9030", "9040", "9050", "9051", "9150", "80", "443")  
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName, InitiatingProcessFolderPath  
| order by Timestamp desc
```
<img width="1849" height="418" alt="Screenshot 2025-11-20 at 2 15 04 PM" src="https://github.com/user-attachments/assets/07b210d6-151a-4d5a-b354-73d98e42bc79" />

---

## Chronological Event Timeline 

### 1. File Download - TOR Installer

- **Timestamp:** `Nov 20, 2025 12:32:19 PM`
- **Event:** The user "inegib" downloaded a file named `tor-browser-windows-x86_64-portable-14.0.1.exe` to the Downloads folder.
- **Action:** File download detected.
- **File Path:** `C:\Users\inegib\Downloads\tor-browser-windows-x86_64-portable-14.0.1.exe`

### 2. Process Execution - TOR Browser Installation

- **Timestamp:** `Nov 20, 2025 12:34:46 PM`
- **Event:** The user "inegib" executed the file `tor-browser-windows-x86_64-portable-14.0.1.exe` in silent mode, initiating a background installation of the TOR Browser.
- **Action:** Process creation detected.
- **Command:** `tor-browser-windows-x86_64-portable-14.0.1.exe /S`
- **File Path:** `C:\Users\inegib\Downloads\tor-browser-windows-x86_64-portable-14.0.1.exe`

### 3. Process Execution - TOR Browser Launch

- **Timestamp:** `Nov 20, 2025 12:37:29 PM`
- **Event:** User "inegib" opened the TOR browser. Subsequent processes associated with TOR browser, such as `firefox.exe` and `tor.exe`, were also created, indicating that the browser launched successfully.
- **Action:** Process creation of TOR browser-related executables detected.
- **File Path:** `C:\Users\inegib\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe`

### 4. Network Connection - TOR Network

- **Timestamp:** `Nov 20, 2025 1:09:54 PM`
- **Event:** A network connection to IP `162.55.107.247` on port `9001` by user "inegib" was established using `tor.exe`, confirming TOR browser network activity.
- **Action:** Connection success.
- **Process:** `tor.exe`
- **File Path:** `c:\users\inegib\desktop\tor browser\browser\torbrowser\tor\tor.exe`

### 5. Additional Network Connections - TOR Browser Activity

- **Timestamps:**
  - `Nov 20, 2025 1:09:58 PM` - Connected to `45.157.234.84` on port `443`.
  - `Nov 20, 2025 1:10:36 PM` - Local connection to `127.0.0.1` on port `9150`.
- **Event:** Additional TOR network connections were established, indicating ongoing activity by user "inegib" through the TOR browser.
- **Action:** Multiple successful connections detected.

### 6. File Creation - TOR Shopping List

- **Timestamp:** `Nov 20, 2025 1:18:48 PM`
- **Event:** The user "inegib" created a file named `Tor Shopping list.txt` on the desktop, potentially indicating a list or notes related to their TOR browser activities.
- **Action:** File creation detected.
- **File Path:** `C:\Users\inegib\Desktop\tor-shopping-list.txt`

---

## Summary

The user "inegib" on the "ibrahim-win11" device initiated and completed the installation of the TOR browser. They proceeded to launch the browser, establish connections within the TOR network, and created various files related to TOR on their desktop, including a file named `Tor Shopping list.txt`. This sequence of activities indicates that the user actively installed, configured, and used the TOR browser, likely for anonymous browsing purposes, with possible documentation in the form of the "shopping list" file.

---

## Response Taken

TOR usage was confirmed on the endpoint `ibrahim-win11` by the user `inegib`. The device was isolated, and the user's direct manager was notified.

---# threat-hunting-scenario-tor
