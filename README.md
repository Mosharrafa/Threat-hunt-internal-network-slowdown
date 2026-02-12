
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

## Investigation Steps
1. Identify abnormal network connections
2. Pivot into process activity
3. Identify executed scripts or commands
4. Confirm malicious behavior
5. Map activity to MITRE ATT&CK

## Tools Used
- Microsoft Defender for Endpoint
- Microsoft Sentinel
- KQL (Kusto Query Language)

## Outcome
The investigation confirmed unauthorized PowerShell-based network scanning activity originating from an internal device.




