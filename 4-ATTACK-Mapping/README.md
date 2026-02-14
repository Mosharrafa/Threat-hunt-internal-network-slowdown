# MITRE ATT&CK Mapping

This section maps the observed behavior to the MITRE ATT&CK framework to understand the attacker's objective and stage of activity.

---

## Observed Behaviors

During the investigation, the following actions were identified:

• PowerShell execution using execution policy bypass  
• Script download using web request  
• Script execution from ProgramData directory  
• Account enumeration using net.exe  
• Multiple connections to many internal hosts

---

## Technique Mapping

### T1059.001 — Command and Scripting Interpreter: PowerShell
PowerShell was executed with execution policy bypass to run a script.

Evidence:
powershell.exe -ExecutionPolicy Bypass -File C:\programdata\portscan.ps1

---

### T1105 — Ingress Tool Transfer
The script was downloaded from a remote source.

Evidence:
Invoke-WebRequest

---

### T1082 — System Information Discovery
The attacker queried local account information.

Evidence:
net.exe accounts  
net1.exe accounts

---

### T1046 — Network Service Discovery
The script attempted connections to multiple internal hosts.

Evidence:
High volume internal connection attempts

---

### T1070 — Indicator Removal on Host
The script did not remain on disk after execution.

Evidence:
No persistent portscan.ps1 file found

---

## Attack Stage Assessment

The behavior aligns with the **Reconnaissance / Discovery phase** of an attack lifecycle.

No persistence or privilege escalation activity was observed.

---

## Conclusion

The activity simulated an attacker performing internal reconnaissance after gaining initial access to the network.

The attacker attempted to:

1. Discover systems
2. Identify available services
3. Enumerate local accounts
4. Prepare for lateral movement
