
# Threat Hunt Report: Devices Accidentally Exposed to the Internet

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)

## Scenario

During routine maintenance, the security team is tasked with investigating any VMs in the shared services cluster (handling DNS, Domain Services, DHCP, etc.) that have mistakenly been exposed to the public internet. The goal is to identify any misconfigured VMs and check for potential brute-force login attempts/successes from external sources.

---
## Timeline Summary and Findings

Windows-target-1 has been internet facing for several days.
```kql
DeviceInfo
| where DeviceName == "windows-target-1"
| where IsInternetFacing == 1
| order by Timestamp desc
```

Most recent Internet facing time:  2025-08-15T00:07:59.96698Z


Several bad actors have been attempting to log into the target machine
```kql
DeviceLogonEvents
| where DeviceName == "windows-target-1"
| where LogonType has_any("Network", "Interactive", "RemoteInteractive", "Unlock")
| where ActionType == "LogonFailed"
| where isnotempty(RemoteIP)
| summarize Attempts = count() by ActionType, RemoteIP, DeviceName
| order by Attempts
```
<img width="665" height="470" alt="p1" src="https://github.com/user-attachments/assets/78017aa7-b338-416a-b19e-1922b00bfa5c" />


The top 5 most failed login attempt IP addresses have not been able to break into the VM.
```kql
let RemoteIPsInQuestion = dynamic(["59.3.82.127","57.129.140.32", "204.157.179.2", "45.150.128.246", "172.201.61.84"]);
DeviceLogonEvents
| where LogonType has_any("Network", "Interactive", "RemoteInteractive", "Unlock")
| where ActionType == "LogonSuccess"
| where RemoteIP has_any(RemoteIPsInQuestion)
```
<img width="865" height="571" alt="p2" src="https://github.com/user-attachments/assets/c83e1e60-f165-489f-bdf5-bc93ad61844a" />


The only successful remote network logons in the last 30 days where from the "labuser" account (13).
```kql
DeviceLogonEvents
| where DeviceName == "windows-target-1"
| where LogonType == "Network"
| where ActionType == "LogonSuccess"
| summarize count()
```

There were zero (0) failed logons for the "labuser" account, indicating there were no brute force attempts.
```kql
DeviceLogonEvents
| where DeviceName == "windows-target-1"
| where LogonType == "Network"
| where ActionType == "LogonFailed"
| where AccountName  == "labuser"
```
Checked all successful login IP addresses for labuser, did not find any unusual of unexpected locations.
```kql
DeviceLogonEvents
| where DeviceName == "windows-target-1"
| where LogonType == "Network"
| where ActionType == "LogonSuccess"
| where AccountName  == "labuser"
| summarize LoginCOunt = count() by DeviceName, ActionType, AccountName, RemoteIP
```
<img width="860" height="352" alt="p3" src="https://github.com/user-attachments/assets/60caf637-2961-4115-8231-0e65045edc84" />


Though the device was exposed to the internet and clear brute force attempts were made, there is no evidence of successful brute force attacks.

---
## Response Actions:

Hardened the NSG attached to windows-target-1 to allow only RDP traffic from specific endpoints (no public internet access)
Implemented account lockout policy
Implemented MFA

---
Relevant MITRE ATT&CK TTPs:

- T1595.001 – Active Scanning: Scanning IP Blocks  
  Internet-facing system attracted external probing.
- T1046 – Network Service Discovery  
  Likely probing for exposed services (e.g., RDP).
- T1133 – External Remote Services  
  Remote logon attempts via network-facing services.
- T1110 – Brute Force  
  Numerous failed login attempts.
- T1110.001 – Password Guessing  
  Systematic guessing of credentials.
- T1078 – Valid Accounts  
  Attempted use of legitimate credentials.
- T1078.001 – Valid Accounts: Default Accounts  
  Possible targeting of known or default credentials.
