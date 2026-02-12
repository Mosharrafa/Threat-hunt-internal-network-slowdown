# Network Investigation

The investigation began by reviewing recent network activity to identify abnormal behavior.

## Query Used
```kql
DeviceNetworkEvents
| order by Timestamp desc
| take 50
```

## Observation

A single device generated repeated outbound connection attempts within seconds.

Suspicious Device:
mde-test-03

The device attempted connections to multiple different external IP addresses rapidly, which is not typical user behavior and indicates automated activity.

Behavior Identified

Multiple RemoteIP connections in a short time

Repeated ConnectionAttempt actions

Pattern consistent with automated scanning

Conclusion

The network logs suggested the host was performing automated reconnaissance or port scanning, which could explain the network performance degradation.
