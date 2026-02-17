# Splunk LOLRMM Detection Resources

This directory contains resources for monitoring, detecting, and analyzing RMM tools within Splunk.

## Contents

- **`dashboards/`**: Contains the XML for the main [LOLRMM Network Dashboard](dashboards/lolrmm_network_dashoard.xml).
- **`searches/`**: Contains SPL files for various detection scenarios, categorized for Splunk Enterprise Security (ES) and non-ES environments.
- **`demo.csv`**: Sample data for testing and demonstration.

## Setup Instructions

Choose one of the following setup options for the Splunk dashboard:

### Option 1: Scheduled Search with KV Store (Recommended for Large Enterprises)

> [!TIP]
> This approach is ideal for large enterprises as it reduces query load during dashboard viewing, provides consistent historical data, and enables faster dashboard loading times.

1. Install the search `searches/es-lolrmm_network_report.spl` as a scheduled search.
2. Configure the search to run at your preferred interval (e.g., daily).
3. The search will output results to a KV store lookup table named `lolrmm.csv`.
4. Import the dashboard XML and select "LOLRMM Network Report" as the data source.

### Option 2: Direct PaloAlto Firewall Data

1. Import the dashboard XML.
2. Select "PaloAlto Index" as the data source.
3. Ensure your PaloAlto logs are being ingested with the sourcetype `pan:traffic`.

### Option 3: Splunk Enterprise Security Data Model

1. Import the dashboard XML.
2. Select "Splunk ES" as the data source.
3. Ensure your `Network_Traffic` data model is properly populated.

## Configuration Requirements

> [!IMPORTANT]  
> Custom macros `detect_remote_access_software_usage_traffic_filter` and `remote_access_software_usage_exceptions` must be configured for proper dashboard functionality.

These macros are essential for filtering legitimate RMM tools specific to your environment and reducing false positives.

## Use Cases

- **Identify unauthorized RMM tool usage**: Detect tools that are not part of your approved administrative stack.
- **Monitor legitimate RMM tool activity**: Gain visibility into where and how your approved tools are being used.
- **Detect lateral movement**: Spot potential C2 activity masquerading as legitimate administration.
- **Validate security policies**: Ensure remote access is only occurring from authorized segments.

## Requirements

- Splunk Enterprise or Splunk Cloud.
- For ES option: `Network_Traffic` data model acceleration.
- For PaloAlto option: PaloAlto firewall logs with sourcetype `pan:traffic`.
