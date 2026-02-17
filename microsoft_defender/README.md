# Detecting Unauthorized RMM Domains in Microsoft Defender

LOLRMM provides a comprehensive list of known RMM domains that can help detect unauthorized RMM tool usage in your environment.

- LOLRMM project: [https://lolrmm.io/](https://lolrmm.io/)
- Source repository: [magicsword-io/LOLRMM](https://github.com/magicsword-io/LOLRMM)
- Domain feed (CSV): [rmm_domains.csv](https://raw.githubusercontent.com/magicsword-io/LOLRMM/main/website/public/api/rmm_domains.csv)

## Microsoft Defender for Endpoint (MDE) KQL Example

Replace the `ApprovedRMM` list with domains approved in your environment.

```kql
// Detecting Unauthorized RMM Instances in Your MDE Environment
let ApprovedRMM = dynamic(["nomachine.com", "ivanti.com", "getgo.com"]); // Your approved RMM domains
let RMMList = externaldata(URI: string, RMMTool: string)
    [h'https://raw.githubusercontent.com/magicsword-io/LOLRMM/main/website/public/api/rmm_domains.csv'];
let RMMUrl = RMMList
| project URIClean = case(
    URI startswith "*.", replace_string(URI, "*.", ""),
    URI startswith "*", replace_string(URI, "*", ""),
    URI !startswith "*" and URI contains "*", replace_regex(URI, @".+?*", ""),
    URI
    );
DeviceNetworkEvents
| where Timestamp > ago(1h)
| where ActionType == @"ConnectionSuccess"
| where RemoteUrl has_any(RMMUrl.URIClean)
| where not (RemoteUrl has_any(ApprovedRMM))
| summarize arg_max(Timestamp, *) by DeviceId
```

## Sentinel Note

If you are using this query in Microsoft Sentinel, replace `Timestamp` with `TimeGenerated` in:
- the `where` time filter clause
- the `summarize arg_max(...)` clause

## Tuning Guidance

- Start with a short time window (for example, `ago(1h)`) and increase as needed.
- Keep your `ApprovedRMM` list current to reduce false positives.
- Validate hits against expected IT tooling and change windows.
