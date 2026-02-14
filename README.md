
# Internal Network Slowdown Threat Hunt

## Scenario
The IT team reported significant performance degradation on several internal devices within the internal network environment. External attacks were ruled out, suggesting a potential internal security issue.

## Objective
Investigate abnormal internal network traffic and determine the root cause using Microsoft Defender for Endpoint and Microsoft Sentinel.

## Hypothesis
An internal endpoint may be performing automated reconnaissance or port scanning, causing excessive network connections and degraded performance.

## Data Sources
- DeviceNetworkEvents
- DeviceProcessEvents
- DeviceFileEvents

## Investigation Workflow

The investigation followed a structured approach:

1. Detect abnormal network behavior
2. Identify responsible process
3. Validate script execution artifacts
4. Map behavior to MITRE ATT&CK techniques
5. Recommend containment and remediation

---

## Key Finding

An endpoint executed a PowerShell script that performed automated internal network scanning.

The system attempted connections to multiple internal hosts and services in a short time period, matching reconnaissance activity commonly performed by attackers before lateral movement.

---

## Tools Used

- Microsoft Defender for Endpoint (Advanced Hunting)
- KQL Queries
- MITRE ATT&CK Framework

---

## Repository Structure

```
1-Network/        → Network behavior analysis
2-Process/        → Process execution investigation
3-File/           → Script artifact analysis
4-ATTACK-Mapping/ → MITRE technique mapping
5-Response/       → Containment & remediation plan
```

---

## Skills Demonstrated

- Threat hunting methodology
- Log correlation
- Behavioral analysis
- Incident documentation
- Security response planning

---

## Conclusion

The investigation confirmed automated internal reconnaissance activity from a compromised endpoint.

Early detection prevented potential lateral movement and demonstrated the importance of behavioral monitoring in modern endpoint security.


