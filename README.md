# threat-hunting-scenario-tor

<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage

## Platforms and Languages Leveraged
- Windows 11 Virtual Machines (Microsoft Azure)
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

Searched for any file that had the string "tor" in it and discovered what looks like the user "a1388wx1" downloaded a TOR installer, did something that resulted in many TOR-related files being copied to the desktop, and the creation of a file called `tor-shopping-list.txt` on the desktop at `2025-11-07T09:35:32.0512157Z`. These events began at `2025-11-07T09:08:15.8780773Z`.

**Query used to locate events:**

```kql
DeviceFileEvents
| where DeviceName == VMname
| where InitiatingProcessAccountName == SusAccount
| where Timestamp >= datetime(2025-11-07T09:08:15.8780773Z)
| where FileName contains "tor"
| order by Timestamp
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account=InitiatingProcessAccountName
```

<img width="1145" height="736" alt="5" src="https://github.com/user-attachments/assets/bbe30627-bf82-4dba-bc10-1ea1a1a96047" />

---

### 2. Searched the `DeviceProcessEvents` Table

Searched `DeviceProcessEvents` for any `ProcessCommandLine` that contained the string "tor-browser-windows-x86_64-portable-15.0.exe". Based on the logs returned, at `2025-11-07T09:16:15.6532194Z`, an employee on the "vm-bartek" device ran the file `tor-browser-windows-x86_64-portable-15.0.exe` from their Downloads folder, using a command that triggered a silent installation.

**Query used to locate event:**

```kql
DeviceProcessEvents
| where DeviceName == VMname
| where Timestamp >= datetime(2025-11-07T09:08:15.8780773Z)
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-15.0.exe"
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, ProcessCommandLine
| order by Timestamp desc
```

<img width="1378" height="66" alt="6" src="https://github.com/user-attachments/assets/47efd583-1854-457d-8af0-36b4c1706d9e" />

---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Searched for any indication that user "a1388wx1" actually opened the TOR browser. There was evidence that they did open it at `2025-11-07T09:09:13.1885499Z`. There were several other instances of `firefox.exe` (TOR) as well as `tor.exe`.

**Query used to locate events:**

```kql
DeviceProcessEvents
| where DeviceName == VMname
| where Timestamp >= datetime(2025-11-07T09:08:15.8780773Z)
| where FileName has_any ("tor.exe", "firefox.exe", "tor-browser.exe")
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
| order by Timestamp desc
```

<img width="1468" height="722" alt="7" src="https://github.com/user-attachments/assets/54878522-0b35-4ba3-846b-e508fac88fac" />

---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Searched for any indication the TOR browser was used to establish a connection using any of the known TOR ports. At `2025-11-07T09:09:21.8489662Z`, an employee on the "vm-bartek" device successfully established a connection to the remote IP address `51.15.89.200` on port `9001`. The connection was initiated by the process `tor.exe`, located in the folder `c:\users\a1388wx1\desktop\tor browser\browser\torbrowser\tor\tor.exe`. There were a couple of other connections to sites over port `443`.

**Query used to locate events:**

```kql
DeviceNetworkEvents
| where DeviceName == VMname
| where Timestamp >= datetime(2025-11-07T09:08:15.8780773Z)
| where RemotePort in ("9001", "9030", "9040", "9050", "9150", "9151", "80", "443")
| where InitiatingProcessAccountName != "system"
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName
| order by Timestamp desc
```

<img width="1386" height="377" alt="8" src="https://github.com/user-attachments/assets/5e2c0850-3f62-42e0-ad06-2a61e40641de" />

---

## Chronological Event Timeline 

### 1. File Download - TOR Installer

- **Timestamp:** `2025-11-07T09:08:15.8780773Z`
- **Event:** The user "a1388wx1" downloaded a file named `tor-browser-windows-x86_64-portable-15.0.exe` to the Downloads folder.
- **Action:** File download detected.
- **File Path:** `C:\Users\a1388wx1\Downloads\tor-browser-windows-x86_64-portable-15.0.exe`

### 2. Process Execution - TOR Browser Installation

- **Timestamp:** `2025-11-07T09:16:15.6532194Z`
- **Event:** The user "a1388wx1" executed the file `tor-browser-windows-x86_64-portable-15.0.exe` in silent mode, initiating a background installation of the TOR Browser.
- **Action:** Process creation detected.
- **Command:** `tor-browser-windows-x86_64-portable-15.0.exe /S`
- **File Path:** `C:\Users\employee\Downloads\tor-browser-windows-x86_64-portable-15.0.exe`

### 3. Process Execution - TOR Browser Launch

- **Timestamp:** `2025-11-07T09:09:13.1885499Z`
- **Event:** User "a1388wx1" opened the TOR browser. Subsequent processes associated with TOR browser, such as `firefox.exe` and `tor.exe`, were also created, indicating that the browser launched successfully.
- **Action:** Process creation of TOR browser-related executables detected.
- **File Path:** `C:\Users\a1388wx1\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe`

### 4. Network Connection - TOR Network

- **Timestamp:** `2025-11-07T09:18:24.1727883Z`
- **Event:** A network connection to IP `51.15.89.200` on port `9001` by user "a1388wx1" was established using `tor.exe`, confirming TOR browser network activity.
- **Action:** Connection success.
- **Process:** `tor.exe`
- **File Path:** `c:\users\a1388wx1\desktop\tor browser\browser\torbrowser\tor\tor.exe`

### 5. Additional Network Connections - TOR Browser Activity

- **Timestamps:**
  - `2025-11-07T09:18:27.5760518Z` - Local connection to `45.14.233.247` on port `443`.
  - `2025-11-07T09:18:27.6008602Z` - Connected to `64.65.0.80` on port `443`.
  - `2025-11-07T09:18:37.3882292Z` - Local connection to `127.0.0.1` on port `9150`.
- **Event:** Additional TOR network connections were established, indicating ongoing activity by user "a1388wx1" through the TOR browser.
- **Action:** Multiple successful connections detected.

### 6. File Creation - TOR Shopping List

- **Timestamp:** `2025-11-07T09:35:32.0512157Z`
- **Event:** The user "a1388wx1" created a file named `tor-shopping-list.txt` on the desktop, potentially indicating a list or notes related to their TOR browser activities.
- **Action:** File creation detected.
- **File Path:** `C:\Users\a1388wx1\Desktop\tor-shopping-list.txt`

---

## Summary

The user "a1388wx1" on the "vm-bartek" device initiated and completed the installation of the TOR browser. They proceeded to launch the browser, establish connections within the TOR network, and created various files related to TOR on their desktop, including a file named `tor-shopping-list.txt`. This sequence of activities indicates that the user actively installed, configured, and used the TOR browser, likely for anonymous browsing purposes, with possible documentation in the form of the "shopping list" file.

---

## Response Taken

TOR usage was confirmed on the endpoint `vm-bartek` by the user `a1388wx1`. The device was isolated, and the user's direct manager was notified.

---
