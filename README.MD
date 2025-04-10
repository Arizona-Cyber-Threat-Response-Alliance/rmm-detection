# LOLRMM Splunk Dashboard

![LOLRMM Dashboard](splunk/rmm-dashboard.png)

## Overview

This repository contains Splunk resources for monitoring and detecting Remote Monitoring and Management (RMM) tools in your network environment. RMM tools are commonly used by IT administrators but can also be leveraged by threat actors as part of "Living Off the Land" (LOL) techniques.

> [!NOTE]  
> All data is compiled and curated from: https://lolrmm.io

## Components

- **Dashboard**: Interactive visualization of RMM tool usage across your network
- **Scheduled Search**: Creates and maintains a lookup table of RMM detections
- **Multiple Data Source Options**: Flexibility to use Splunk Enterprise Security, PaloAlto firewalls, or custom data sources

## Files

```
├── splunk/
│   ├── dashboards/
│   │   └── lolrmm_network_dashoard.xml
│   ├── searches/
│   │   └── lolrm_network_report.spl
│   ├── demo.csv
│   └── rmm-dashboard.png
```

## Setup Instructions

### Option 1: Scheduled Search with KV Store (Recommended for Large Enterprises)

> [!TIP]
> This approach is ideal for large enterprises as it reduces query load during dashboard viewing, provides consistent historical data, and enables faster dashboard loading times.

1. Install the search `lolrm_network_report.spl` as a scheduled search
2. Configure the search to run at your preferred interval (e.g., daily)
3. The search will output results to a KV store lookup table named `lolrmm.csv`
4. Import the dashboard XML and select "LOLRMM Network Report" as the data source

### Option 2: Direct PaloAlto Firewall Data

1. Import the dashboard XML
2. Select "PaloAlto Index" as the data source
3. Ensure your PaloAlto logs are being ingested with the sourcetype `pan:traffic`

### Option 3: Splunk Enterprise Security Data Model

1. Import the dashboard XML
2. Select "Splunk ES" as the data source
3. Ensure your Network_Traffic data model is properly populated

> [!IMPORTANT]  
> Custom macros `detect_remote_access_software_usage_traffic_filter` and `remote_access_software_usage_exceptions` must be configured for proper dashboard functionality.

## Dashboard Features

- **Timeline View**: Visualize RMM tool usage over time
- **Application Distribution**: See which RMM tools are most prevalent
- **Geographic Map**: View global distribution of RMM connections
- **Source Analysis**: Identify hosts using RMM tools
- **Filtering Options**: Drill down by tool type, category, time range, and more

## Use Cases

- Identify unauthorized RMM tool usage
- Monitor legitimate RMM tool activity
- Detect potential lateral movement or command and control activity
- Validate security policies around remote access tools

## Requirements

- Splunk Enterprise or Splunk Cloud
- For ES option: Network_Traffic data model
- For PaloAlto option: PaloAlto firewall logs with sourcetype `pan:traffic`

> [!WARNING]  
> RMM tools are frequently used in legitimate IT operations. Always verify findings before taking action to avoid disrupting business operations.

> [!CAUTION]
> This dashboard identifies network traffic patterns associated with RMM tools but does not automatically distinguish between legitimate and malicious usage.
