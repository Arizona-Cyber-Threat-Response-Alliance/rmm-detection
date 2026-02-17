# CrowdStrike Manager (LOLRMM IOC Sync)

This directory contains a scoped IOC sync workflow for importing LOLRMM domain indicators into CrowdStrike IOC Management.

## What it does
- Pulls source data from `https://lolrmm.io/api/rmm_tools.json`.
- Uses only `Artifacts.Network[*].Domains`.
- Normalizes and deduplicates domains.
- Applies exclusions from `config.yaml`.
- Syncs project-managed IOCs with idempotent create/update behavior.

## Defaults
- Type: `domain`
- Action: stage-driven (`assess` -> no writes, `report` -> no-detection action, `deploy` -> `detect`)
- Severity: `informational`
- Platforms: `windows`, `mac`, `linux` (when available in tenant)
- Source: `actra_rmm_detection_ioc`
- Tags: `actra`, `rmm_detection`, `feed_lolrmm`
- Retrodetects: opt-in via `--retrodetects`

## Credentials

The tool requires an API client with specific permissions. Create one in the Falcon Console under **Support and resources > API Client and Keys -> OAuth 2 API clients**.

### Required API Scopes

| API Service | Permission | Purpose |
| :--- | :--- | :--- |
| **IOCs (Indicators of Compromise)** | `Read` & `Write` | Manage the domain indicators |
| **Host groups** | `Read` | Resolve group names to IDs for scoped rollout |
| **IOC Management** | `Read` | Check project status and available actions |

### Configuration

The tool supports CLI args or `.env` values:
- `CLIENT_ID`
- `CLIENT_SECRET`
- `BASE_URL` (optional: defaults to `https://api.crowdstrike.com`)

Example `.env` file:
```env
CLIENT_ID=your_id_here
CLIENT_SECRET=your_secret_here
BASE_URL=https://api.crowdstrike.com
```

## Install and run (uv preferred)
```bash
uv pip install crowdstrike-falconpy pyyaml python-dotenv
uv run python cs-sync.py --dry-run --limit 20
uv run python cs-sync.py
```

## Rollout flow
Use assess stage first to measure prevalence and generate whitelist recommendations before writing any IOCs.

```bash
# Stage 1: assess mode (no IOC writes)
uv run python cs-sync.py --stage assess --limit 100

# Stage 2: passive/report mode (create with no-detection action)
uv run python cs-sync.py --stage report

# Stage 3: deploy mode (detect action)
uv run python cs-sync.py --stage deploy
```

**Interactive Safety**: Running `report` or `deploy` modes without `--dry-run` will trigger interactive prompts to confirm execution and scope. To bypass these for automation, use `--confirm-write`.

**Logging and Output**:
- Default log level is `WARNING`.
- The tool always prints a concise `Run Summary` to stdout at the end of execution, including stage/action/scope and key stats.
- Use `--log-level INFO` or `--log-level DEBUG` when you want verbose operational logs.

Use `--summary-json` to capture a machine-readable run summary.
- Summary output includes `summary_schema_version` and `generated_at` for forward compatibility.

Example:

```bash
uv run python cs-sync.py --stage report --dry-run --limit 25 --summary-json run-summary.json
```

Example summary shape:

```json
{
  "summary_schema_version": "1.0",
  "generated_at": "2026-02-16T12:00:00Z",
  "counts": {
    "selected": 25,
    "safe": 24,
    "unsafe": 1,
    "priority_hits": 7
  },
  "source_stats": {
    "tools_total": 293,
    "tools_excluded": 1,
    "raw_domains": 565,
    "normalized_domains": 25,
    "priority_domains": 7,
    "skipped_placeholders": 39,
    "skipped_ipv4": 5,
    "skipped_excluded_domains": 0,
    "deduped": 104
  },
  "sync_plan": {
    "create": 5,
    "update": 2,
    "delete": 0,
    "unchanged": 18
  },
  "prevalence_stats": {
    "status": "skipped"
  },
  "stage": "report",
  "action": "none",
  "dry_run": true
}
```

## Usage Examples

Here are common scenarios for running the tool. All write operations require confirmation (interactive or `--confirm-write`).

### 1. Dry Run (Safe Mode)
See what *would* happen without making any changes. Good for testing configuration or seeing new indicators.
```bash
uv run python cs-sync.py --dry-run
```

Example summary output:

```text
Run Summary
- Stage: report | Action: no_action | Dry run: True
- Scope: host-groups (1)
- Host group IDs: b40f349e9ba545208221968c0f6b5189
- Indicators: selected=10, priority=3, safe=10, unsafe=0
- Source stats: raw_domains=565, normalized_domains=10, deduped=104
- Sync plan: create=0, update=0, unchanged=10, delete=0
```

### 2. Assessment with Prevalence (Default)
Run in `assess` stage to check for existing devices contacting these domains. This does **not** create IOCs; it only queries device activity.
```bash
# Check for prevalence of top 100 indicators
uv run python cs-sync.py --stage assess --limit 100 --prevalence-threshold 10
```

### 3. Targeted Deployment (Testing)
Deploy indicators only to a specific Host Group (e.g., "Test Workstations") to verify behavior before global rollout.
```bash
# Deploy to 'Test Workstations' group with 'detect' action
uv run python cs-sync.py --stage deploy --host-groups "Test Workstations"
```

### 4. Global Deployment (Production)
Force a global deployment to all hosts, ignoring any configured host groups.
```bash
# Deploy globally with 'detect' action
uv run python cs-sync.py --stage deploy --global
```
**Warning**: Global deployment requires typing "GLOBAL" to confirm if running interactively.

### 5. Maintenance & Cleanup
Run occasional maintenance tasks.

```bash
# Prune: Remove managed IOCs that are no longer in the LOLRMM source
uv run python cs-sync.py --prune

# Retrodetects: Update indicators and trigger retro-active detection on past activity
uv run python cs-sync.py --retrodetects

# Remove All: Delete ALL indicators created by this project (Full Uninstall)
uv run python cs-sync.py --remove-all
```

## Utility Commands

Check the current state of the project and source data without making changes:
```bash
uv run python cs-sync.py --project-status
```

Generate a machine-readable JSON summary of a run (useful for automation/logging):
```bash
uv run python cs-sync.py --stage report --dry-run --summary-json run-summary.json
```

## Deployment Scope (Global vs. Test Groups)
By default, the tool applies IOCs **globally** to all hosts in the tenant (`applied_globally=true`).

To restrict deployment to specific **Host Groups** (e.g., for testing or phased rollout):

1.  **Via Config (Recommended for permanence)**:
    Add the `host_groups` key to `config.yaml` (under `rollout`):
    ```yaml
    rollout:
      # Target specific groups (IOCs will NOT be global)
      host_groups:
        - "Purple Team Exercise Hosts"
        - "Test Workstations"
    ```

2.  **Via CLI (Recommended for ad-hoc testing)**:
    Override the config using `--host-groups`:
    ```bash
    # Target a specific test group
    uv run python cs-sync.py --host-groups "Purple Team Exercise Hosts"
    
    # Force global deployment (ignore config)
    uv run python cs-sync.py --global
    ```

**Note**: When Host Groups are specified, the IOC payload sets `applied_globally=false` and attaches the resolved Host Group IDs.

## Configuration (`config.yaml`)

The configuration file is structured into three main sections: `policy`, `rollout`, and `safety`.

```yaml
policy:
  deployment_stage: assess        # assess, report, or deploy
  deploy_action: detect           # action when in deploy stage
  report_action_candidates:       # candidates for report stage (passive)
    - no_action
    - none
  prevalence_threshold: 10        # device count threshold for prevalence reporting

rollout:
  host_groups:                    # Limit scope to these groups
    - Purple Team Exercise Hosts
  priority_platforms:             # Platforms to prioritize in processing
    - ScreenConnect

safety:
  excluded_platforms:             # Platforms (tools) to exclude entirely
    - TeamViewer
  excluded_domains: []            # Specific domains to exclude
```
