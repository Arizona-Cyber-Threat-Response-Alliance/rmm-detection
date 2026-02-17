# LOLRMM Detection Resources

![LOLRMM Dashboard](splunk/rmm-dashboard.png)

## Overview

This repository serves as a comprehensive collection of resources for monitoring, detecting, and analyzing Remote Monitoring and Management (RMM) tools across enterprise environments. While RMM tools are essential for legitimate IT administration, they are increasingly being leveraged by threat actors as part of "Living Off the Land" (LOL) techniques, making their detection and monitoring crucial for security teams.

All data is compiled and curated from: [https://lolrmm.io](https://lolrmm.io)

## Project Goals

This project aims to be a central hub for security practitioners dealing with RMM tool detection. We are actively expanding to include:
- Multi-SIEM detection rules (Splunk, Sentinel, ELK, etc.)
- API integration scripts for automated response
- Detection engineering guidance and playbooks
- Incident response procedures specific to RMM abuse

## Repository Structure

The project is organized by platform and toolset:

### 🛡️ [Sigma Rules & Community Detections](magicsword_lolrmm/detections/sigma)
Extensive collection of vendor-agnostic detections maintained by the [LOLRMM project](https://lolrmm.io/) from [magicsword-io](https://github.com/magicsword-io/LOLRMM). Huge kudos to their team for building and maintaining this dataset.
- **Sigma Rules**: Over 200 Sigma rules covering process, network, and registry artifacts for many RMM tools.
- **Sigma Process Detection**: [generic_rmm_detection.yml](https://github.com/magicsword-io/LOLRMM/blob/main/detections/sigma/generic_rmm_detection.yml)
- **DNS Detection Rules**: [rmm_domains_dns_queries.yml](https://github.com/magicsword-io/LOLRMM/blob/main/detections/sigma/rmm_domains_dns_queries.yml)
- **Cross-Platform**: Rules can be converted to your preferred SIEM using tools like [sigmac](https://github.com/SigmaOT/sigma).

### 🛡️ [Microsoft Defender for Endpoint](microsoft_defender/README.md)
Detect unauthorized RMM domains in Microsoft Defender for Endpoint and Microsoft Sentinel.
- **KQL Detection**: Query using LOLRMM domain feed with approved-domain filtering.
- **MDE and Sentinel Notes**: Includes field-name differences (`Timestamp` vs `TimeGenerated`).
- **Fast Start**: Copy-ready query and tuning guidance.

### 📊 [Splunk](splunk/README.md)
Comprehensive monitoring for Splunk Enterprise and Enterprise Security.
- **Dashboards**: Visual timeline and distribution of RMM usage.
- **Detections**: Optimized searches for DNS and network traffic.
- **Flexible Data Sources**: Supports Splunk ES, Palo Alto firewalls, or custom indexes.

### 🦅 [CrowdStrike Next-Gen SIEM](crowdstrike/README.md)
Visualizations and lookups for the CrowdStrike Falcon platform.
- **LogScale Dashboards**: Native Next-Gen SIEM dashboard templates.
- **Artifact Lookups**: Automatically updated CSVs for process and domain indicators.

### 🔄 [CrowdStrike IOC Sync](crowdstrike_ioc/README.md)
Advanced Python-based automation for CrowdStrike.
- **Automated Sync**: Synchronizes LOLRMM domain indicators directly to CrowdStrike IOC Management via API.
- **Rollout Control**: Supports staged deployment (assess, report, deploy) to minimize business impact.

## 🤝 Community Contributions

We are **actively looking for community resources** for platforms beyond those currently supported. If you have detection rules, dashboards, or playbooks for:
- Microsoft Sentinel (KQL)
- Elastic / ELK Stack
- Datadog
- Chronicle
- Any other security platform

Please consider contributing! Check out our [Contributing Guidelines](CONTRIBUTING.md) (coming soon) or open an issue/PR to share your work.

## General Considerations

> [!WARNING]  
> RMM tools are frequently used in legitimate IT operations. **Always investigate and verify findings** before taking blocking or remediation actions to avoid disrupting critical business operations. Context is key.

> [!CAUTION]
> These resources identify activity associated with RMM tools based on known indicators. They do **not** automatically distinguish between legitimate and malicious usage without proper tuning and investigation.
