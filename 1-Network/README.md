# Network Investigation

## Objective
Investigate the cause of reported internal network performance degradation and identify any abnormal communication patterns within the internal subnet.

---

## Methodology
The investigation began by reviewing recent endpoint network telemetry in Microsoft Defender for Endpoint Advanced Hunting.

Since the issue was isolated to internal devices and external attacks were ruled out, the focus was placed on detecting unusual internal host-to-host communication patterns.

The main goals were:

- Identify devices generating unusually high connection attempts
- Detect communication with multiple internal hosts in a short period
- Determine whether the behavior matches automated reconnaissance activity

---

## Queries Used

### Identify abnormal connection volume per device
```kql
DeviceNetworkEvents
| where Timestamp > ago(30m)
| summarize Connections = count() by DeviceName
| order by Connections desc
```
<img width="1497" height="653" alt="image" src="https://github.com/user-attachments/assets/49210ccf-c392-4d17-96aa-f5923a1ac143" />



### Filter internal-to-internal connection attempts
```kql
DeviceNetworkEvents
| where Timestamp > ago(20m)
| where LocalIP startswith "10."
| where RemoteIP startswith "10."
| where ActionType in ("ConnectionFailed","ConnectionAttempted")
| summarize Attempts=count() by DeviceName
| order by Attempts desc
```
<img width="1512" height="703" alt="image" src="https://github.com/user-attachments/assets/55c643af-1b78-4380-a0ba-bd78d1d381d3" />



### Determine number of unique hosts contacted
```kql
DeviceNetworkEvents
| where Timestamp > ago(20m)
| where DeviceName == "mde-test-03"
| summarize UniqueTargets=dcount(RemoteIP), TotalConnections=count()
```

<img width="1566" height="766" alt="image" src="https://github.com/user-attachments/assets/02606d11-2988-43eb-b373-3be06a3fd036" />


### Identify service discovery behavior (port targeting)
```kql
DeviceNetworkEvents
| where Timestamp > ago(25m)
| where DeviceName == "mde-test-03"
| summarize Attempts=count() by RemotePort
| order by Attempts desc
```
<img width="1303" height="853" alt="image" src="https://github.com/user-attachments/assets/da9de5d5-77d8-408a-8fca-2f92f56d0bfc" />

---

## Findings

### Abnormal Host Activity
A single internal device generated a significantly higher number of outbound connection attempts compared to other endpoints.

**Affected Device:** mde-test-03

### Lateral Host Contact
Within a short time window, the device attempted communication with 21 unique internal hosts.

This behavior is inconsistent with normal workstation usage and suggests automated enumeration rather than user-driven activity.

### Service Enumeration Pattern
The device attempted connections across multiple common service ports including:

- Web services (80, 443, 8080, 8443)
- Remote access (3389)
- File sharing (445)
- Database (3306)
- Remote desktop/VNC (5900)

This pattern strongly indicates network reconnaissance / service discovery scanning rather than legitimate application communication.

---

## Conclusion
Network telemetry analysis indicates that endpoint **mde-test-03** performed automated internal reconnaissance by attempting connections to multiple hosts and service ports within a short period.

The behavior aligns with port scanning activity commonly observed during attacker reconnaissance phases prior to lateral movement.

This activity was generated in a controlled lab environment to simulate a real-world internal threat scenario and validate detection and investigation methodology.
