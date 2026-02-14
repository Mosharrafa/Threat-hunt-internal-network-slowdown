# Response and Remediation

After confirming automated internal reconnaissance activity from the endpoint, containment and prevention actions were planned.

The goal was to stop the activity immediately and prevent similar behavior in a real environment.

---

## Immediate Containment

### Isolate the Device
The affected device should be isolated from the network to stop further scanning or lateral movement attempts.

Microsoft Defender for Endpoint provides device isolation capability to block all network communication except management traffic.

---

### Terminate Malicious Process
Stop the running PowerShell process responsible for the activity.

This prevents continued execution of the script and stops additional connections.

---

## Investigation Actions

### Collect Forensic Evidence
Before cleanup, collect:

• Running processes  
• PowerShell command history  
• Network connections  
• Security logs  

This ensures the activity can be reviewed later if needed.

---

## Remediation

### Remove Unauthorized Script
Delete the script from the system if still present and clear temporary execution artifacts.

---

### Restrict PowerShell Usage
Implement PowerShell security controls:

• Disable execution policy bypass for standard users  
• Enable PowerShell logging (Script Block Logging & Module Logging)  
• Restrict interactive PowerShell usage where not required  

---

### Network Hardening
Reduce internal reconnaissance risk:

• Block unnecessary internal port access  
• Apply host firewall rules  
• Implement network segmentation

---

### Least Privilege Enforcement
Ensure users do not have local administrative privileges unless required.

This prevents script-based discovery from accessing system information.

---

## Prevention Improvements

To detect this earlier in production:

• Create alert for abnormal internal connection volume  
• Monitor excessive PowerShell execution  
• Alert on execution policy bypass usage  
• Monitor enumeration commands (net.exe, whoami, wmic)

---

## Final Assessment

The activity represents an attacker reconnaissance phase after initial access.

No persistence was established, and early detection allowed containment before lateral movement could occur.
