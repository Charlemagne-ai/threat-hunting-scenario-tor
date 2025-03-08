<img width="400" src ="https://github.com/user-attachments/assets/c7532c8c-2d8c-48e6-bcdd-dcb80da29a61"/>

# Threat Hunt Report: Unauthorized TOR Usage

**Detection of Unauthorized TOR Browser Installation and Usage on Workstation:** `server-dev-01`


## Background

Recent security logs and employee reports have raised concerns about potential unauthorized access to restricted websites during working hours. Management identified unusual encrypted network traffic patterns, specifically connections to known TOR entry nodes. Additionally, anonymous employee reports have indicated discussions on methods to bypass network security controls using TOR browsers. These combined factors have raised suspicions that employees may be using TOR to circumvent established network access policies.

## Objective

The primary objective of this investigation is to detect and analyze TOR usage within the organization’s network to assess associated security risks. The investigation aims to identify any related security incidents resulting from such activity, particularly those that could expose sensitive organizational data or lead to unauthorized actions. If TOR usage is confirmed, management will be immediately notified, and appropriate mitigation measures will be recommended to prevent further circumvention of network security controls.

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Tor Browser

## High-Level TOR-Related IoC Discovery Plan

- Check `DeviceFileEvents` for occurrences involving `tor.exe` or `firefox.exe`.
- Review `DeviceProcessEvents` for indicators of installation or execution related to TOR.
- Analyze `DeviceNetworkEvents` for signs of outgoing connections utilizing known TOR ports.

--- 

## Steps Taken

### File Event Analysis

Reviewed the `DeviceFileEvents` logs for any file names containing the keyword "tor." Investigation revealed that the user `cdoles.admin` downloaded a TOR installer and subsequently copied several TOR-related files to the desktop. Additionally, a file named `tor-shopping-list.txt` was created on the desktop at `2025-02-26T00:37:29.2096688Z`. The earliest related event was logged at `2025-02-26T00:16:52.4942799Z`.

**Query Executed:**

```sql
DeviceFileEvents
| where DeviceName == "server-dev-01"
| where InitiatingProcessAccountName == "cdoles.admin"
| where FileName contains "tor"
| where Timestamp >= datetime(2025-02-26T00:16:52.4942799Z)
| order by Timestamp desc
| project Timestamp, DeviceName, FileName, FolderPath, ActionType, InitiatingProcessFileName, InitiatingProcessCommandLine, SHA256
```
![tor-download](https://github.com/user-attachments/assets/bd6c508b-038a-4d20-8781-b67bed956adc)

### Process Execution Analysis

Examined the `DeviceProcessEvents` logs for entries containing `tor-browser-windows-x86_64-portable-14.0.6.exe`. At `2025-02-26T00:20:17.8704483Z`, evidence indicated that user `cdoles.admin` executed the TOR Browser installer from the Downloads folder using a silent installation command, suggesting intentional concealment from detection mechanisms.

**Query Executed:**

```sql
DeviceProcessEvents
| where DeviceName == "server-dev-01"
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-14.0.6.exe"
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, ActionType, ProcessCommandLine, SHA256
```
![tor-install](https://github.com/user-attachments/assets/e72b8f93-689b-4167-85f1-a5344ec29e81)


### TOR Browser Launch Verification

Conducted further analysis on `DeviceProcessEvents` to verify the execution of TOR Browser processes by `cdoles.admin`. Confirmed that the TOR Browser was launched at `2025-02-26T00:20:53.4446258Z`. Subsequently, multiple instances of `firefox.exe` (linked to TOR) and `tor.exe` were detected, confirming active TOR Browser usage.

**Query Executed:**

```sql
DeviceProcessEvents
| where DeviceName == "server-dev-01"
| where FileName in ("tor.exe", "firefox.exe", "tor-browser.exe")
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, ActionType, ProcessCommandLine, SHA256
| order by Timestamp desc
```
![tor-process-creation](https://github.com/user-attachments/assets/c2623577-fcac-45a9-9aaf-15298f607083)


### Network Connection Analysis

Analyzed network connection logs (`DeviceNetworkEvents`) for activity involving known TOR ports. At `2025-02-26T00:21:25.1415408Z`, identified a successful connection to a TOR exit node (`IP: 92.51.45.21`) via port `443`. The initiating process was `tor.exe`, executed from the directory `C:\Users\cdoles.admin\Desktop\Tor Browser\Browser\TorBrowser\tor\tor.exe`, conclusively verifying active TOR network communication.

**Query Executed:**

```sql
DeviceNetworkEvents
| where DeviceName == "server-dev-01"
| where InitiatingProcessAccountName == "cdoles.admin"
| where RemotePort in (9001, 9030, 9040, 9050, 9051, 9150)  // Known TOR ports
| where ActionType == "ConnectionSuccess"
| project Timestamp, DeviceName, InitiatingProcessAccountName, RemoteIP, RemotePort, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```
![tor-network-events](https://github.com/user-attachments/assets/51055c7b-1ec8-4f7a-85e2-af65827806ed)


## Chronological Events

1. **File Download – TOR Installer**
    
    - **Timestamp:** `2025-02-25 16:16:52`
    - **Event:** User `cdoles.admin` downloaded `tor-browser-windows-x86_64-portable-14.0.6.exe` to the Downloads folder via `msedge.exe`.
2. **Process Execution – TOR Browser Installation**
    
    - **Timestamp:** `2025-02-25 16:20:17`
    - **Event:** User `cdoles.admin` executed the installer using a silent installation option, indicating deliberate concealment.
    - **Command Line:** `tor-browser-windows-x86_64-portable-14.0.6.exe --silent`
3. **Creation of TOR-related Note File**
    
    - **Timestamp:** `2025-02-25 16:37:29`
    - **Event:** Created the file `tor-shopping-list.txt` using `notepad.exe`, suggesting deliberate planning or preparation for TOR usage.
    - **File Path:** `C:\Users\cdoles.admin\Documents\tor-shopping-list.txt`
4. **Process Execution – Active TOR Browser Usage**
    
    - **Timestamps:** Between `2025-02-25 16:27:40` and `2025-02-25 16:31:00`
    - **Event:** Multiple executions of `firefox.exe` processes associated with the TOR Browser, confirming active TOR browsing sessions.
5. **Network Connection – TOR Network Traffic**
    
    - **Timestamp:** `2025-02-25 19:29:04`
    - **Event:** Established a network connection to IP `92.51.45.21` on port `443` through `tor.exe`, providing direct evidence of TOR network utilization.
    - **Command Line:** `"tor.exe" -f "C:\Users\cdoles.admin\Desktop\Tor Browser\Browser\TorBrowser\tor\tor.exe"`

## Summary

The investigation conclusively confirms that user `cdoles.admin` intentionally downloaded, installed, and utilized the TOR Browser on workstation `server-dev-01`. Multiple executions of associated processes (`firefox.exe`, `tor.exe`) indicate sustained usage. The creation of the file `tor-shopping-list.txt` further suggests intentional planning around TOR use. Additionally, network connection logs confirmed active connections to known TOR nodes, reinforcing evidence of deliberate network security circumvention.

## Response Taken

Following confirmation of TOR usage by user `cdoles.admin` on workstation `server-dev-01`, immediate endpoint isolation was enforced. The incident was promptly reported to the user's direct supervisor for further action.
