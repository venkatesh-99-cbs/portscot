# SentinelScan Report

**Target:** 127.0.0.1
**Start Time:** 2026-07-04 17:55:40.184313
**End Time:** 2026-07-04 17:55:40.248865

## Summary

- **total_hosts:** 1
- **total_findings:** 1

## Hosts

### 127.0.0.1
- **Status:** unknown
- **Estimated OS:** Linux (Ubuntu/Debian) (90% accuracy)

#### Services

| Port | Protocol | State | Service | Banner |
| --- | --- | --- | --- | --- |
| 22 | tcp | open |  | SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.14 |

#### Findings

- **[INFO] Information Exposure in Banner**
  - *Description:* Service on port 22 exposes version information in its banner: SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.14
  - *Remediation:* Configure the service to hide version information in banners.
