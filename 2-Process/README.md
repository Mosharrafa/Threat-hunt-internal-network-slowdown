# Process Investigation

After identifying abnormal internal network connections from the device `mde-test-03`, the next step was to determine which process generated the traffic.

---

## Step 1 — Review all recent processes

First, I reviewed recent process executions on the device.

```kql
DeviceProcessEvents
| where DeviceName == "mde-test-03"
| project Timestamp, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

### Observation
Large number of PowerShell and Command Prompt executions were observed in a short time window.

This already indicated automated execution instead of normal user interaction.

---

## Step 2 — Filter scripting engines

To focus on execution related processes, I filtered scripting tools.

```kql
DeviceProcessEvents
| where Timestamp > ago(30m)
| where DeviceName == "mde-test-03"
| where FileName in~ ("powershell.exe","pwsh.exe","cmd.exe","wscript.exe","cscript.exe","mshta.exe","python.exe","perl.exe","node.exe")
| project Timestamp, FileName, ProcessCommandLine, InitiatingProcessFileName
| order by Timestamp desc
```

### Observation
Repeated pattern detected:

cmd.exe → powershell.exe

This indicates automated execution chain.

---

## Step 3 — Search suspicious command usage

Next I searched for suspicious execution parameters.

```kql
DeviceProcessEvents
| where Timestamp > ago(30m)
| where DeviceName == "mde-test-03"
| where ProcessCommandLine has_any (
"encodedcommand",
"bypass",
"downloadstring",
"invoke-webrequest",
".ps1",
"http"
)
| project Timestamp, FileName, ProcessCommandLine
| order by Timestamp desc
```

### Observation

The following commands were identified:

powershell.exe -ExecutionPolicy Bypass -File C:\programdata\portscan.ps1  
cmd.exe /c powershell.exe -ExecutionPolicy Bypass -Command Invoke-WebRequest ...

This confirms a script was downloaded and executed.

---

## Step 4 — Check system discovery commands

```kql
DeviceProcessEvents
| where Timestamp > ago(30m)
| where DeviceName == "mde-test-03"
| where FileName in~ (
"certutil.exe","bitsadmin.exe","mshta.exe","rundll32.exe",
"regsvr32.exe","wmic.exe","schtasks.exe","at.exe",
"net.exe","net1.exe","sc.exe","whoami.exe"
)
| project Timestamp, FileName, ProcessCommandLine, InitiatingProcessFileName
| order by Timestamp desc
```

### Observation

Detected commands:

net.exe accounts  
net1.exe accounts

This indicates local account enumeration.

---

## Step 5 — Check execution from suspicious locations

```kql
DeviceProcessEvents
| where Timestamp > ago(30m)
| where DeviceName == "mde-test-03"
| where FolderPath has_any ("Downloads","Temp","AppData","ProgramData")
| project Timestamp, FileName, FolderPath, ProcessCommandLine
| order by Timestamp desc
```

### Observation
Execution detected from:

C:\ProgramData\

This is commonly used for attacker staging files.

---

## Process Investigation Conclusion

The endpoint executed a PowerShell script from ProgramData using execution policy bypass.

The script was launched automatically through cmd.exe and performed account enumeration before generating network connections.

This confirms the network activity originated from an automated reconnaissance script rather than normal user behavior.
