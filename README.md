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
