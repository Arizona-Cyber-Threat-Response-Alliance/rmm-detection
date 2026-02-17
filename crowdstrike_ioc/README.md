# CrowdStrike Manager (LOLRMM IOC Sync)

This directory contains a scoped IOC sync workflow for importing LOLRMM domain indicators into CrowdStrike IOC Management.

## Quick Start (uv preferred)

1. **Install dependencies**:
   ```bash
   uv pip install crowdstrike-falconpy pyyaml python-dotenv
   ```

2. **Configure credentials**:
   Create a `.env` file with your API keys:
   ```env
   CLIENT_ID=your_id_here
   CLIENT_SECRET=your_secret_here
   BASE_URL=https://api.crowdstrike.com
   ```

3. **Run a dry-run**:
   ```bash
   uv run python cs-sync.py --dry-run --limit 20
   ```

## Rollout Workflow

The tool uses a 3-stage rollout process to ensure safety and visibility.

| Stage | Mode | Write Actions | Typical Use |
| :--- | :--- | :--- | :--- |
| `assess` | Read-only | None | Measure prevalence and check impact before deployment. |
| `report` | Passive | Create with `no_action` | "Soft" rollout to verify visibility without detections. |
| `deploy` | Active | Create/Update with `detect` | Full active detection rollout. |

```bash
# Stage 1: Assessment
uv run python cs-sync.py --stage assess --limit 100

# Stage 2: Passive Report
uv run python cs-sync.py --stage report

# Stage 3: Active Deployment
uv run python cs-sync.py --stage deploy
```

**Note**: Non-dry-run `report` and `deploy` modes require interactive confirmation. Use `--confirm-write` to bypass for automation.

## Credentials & Permissions

Create an API client in the Falcon Console under **Support and resources > API Client and Keys > OAuth 2 API clients**.

| API Service | Permission | Purpose |
| :--- | :--- | :--- |
| **IOCs (Indicators of Compromise)** | `Read` & `Write` | Manage the domain indicators |
| **Host groups** | `Read` | Resolve group names to IDs for scoped rollout |
| **IOC Management** | `Read` | Check project status and available actions |

## Configuration (`config.yaml`)

The configuration is split into `policy`, `rollout`, and `safety`.

```yaml
policy:
  deployment_stage: assess        # assess, report, or deploy
  deploy_action: detect           # action used in 'deploy' stage
  prevalence_threshold: 10        # device count threshold for prevalence warnings

rollout:
  host_groups:                    # Limit scope to these groups
    - "Purple Team Exercise Hosts"
  priority_platforms:             # Platforms to process first
    - "ScreenConnect"

safety:
  excluded_platforms:             # Platforms to exclude entirely
    - "TeamViewer"
  excluded_domains: []            # Specific domains to ignore
```

## Maintenance & Utility

| Command | Description |
| :--- | :--- |
| `--project-status` | Show current managed IOC count and source stats. |
| `--prune` | Remove managed IOCs that are no longer in the LOLRMM source. |
| `--remove-all` | Delete ALL indicators created by this project (Full Uninstall). |
| `--retrodetects` | Trigger retro-active detection on past activity for new/updated IOCs. |
| `--summary-json <path>` | Write a machine-readable JSON summary of the run. |

## Defaults & Meta
- **Source**: `tisu_rmm_detection_ioc`
- **Tags**: `tisu`, `rmm_detection`, `feed_lolrmm`
- **Log Level**: Default is `WARNING`. Use `--log-level INFO` for more detail.
- **Scope**: Applied globally by default unless `host_groups` are configured.
