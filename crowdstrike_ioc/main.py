#!/usr/bin/env python3
"""Synchronize LOLRMM domains into CrowdStrike IOC Management."""

import argparse
import logging
import sys
from pathlib import Path

try:
    from falconpy import IOC  # type: ignore[import-not-found]
except ImportError:  # pragma: no cover
    IOC = None

from config import (
    DEFAULT_CONFIG_PATH,
    load_dotenv,
    load_simple_yaml,
    resolve_env_file_path,
)
from crowdstrike_api import (
    DEFAULT_SEVERITY,
    PROJECT_SOURCE,
    PROJECT_TAGS,
    iter_managed_iocs,
    list_available_actions,
    resolve_action,
    resolve_platforms,
    resolve_host_group_ids,
)
from reconcile import sync
from reporting import (
    DEFAULT_PREVALENCE_STATS,
    DEFAULT_SYNC_PLAN,
    build_summary_payload,
    run_prevalence_report,
    write_json_summary,
)
from source import SOURCE_STATS_KEYS, collect_domains, fetch_lolrmm

LOGGER = logging.getLogger("cs_sync")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Sync LOLRMM domains to CrowdStrike IOC Management"
    )
    parser.add_argument("--client-id", help="CrowdStrike API client ID")
    parser.add_argument("--client-secret", help="CrowdStrike API client secret")
    parser.add_argument("--base-url", help="CrowdStrike cloud base URL (optional)")
    parser.add_argument(
        "--env-file", default=".env", help="Path to .env file (default: .env)"
    )
    parser.add_argument(
        "--config", default=str(DEFAULT_CONFIG_PATH), help="Path to YAML config"
    )
    parser.add_argument(
        "--limit", type=int, default=0, help="Limit processed indicators (0=all)"
    )
    parser.add_argument(
        "--dry-run", action="store_true", help="Show planned changes without writes"
    )
    parser.add_argument(
        "--retrodetects",
        action="store_true",
        help="Submit retrodetects on create/update",
    )
    parser.add_argument(
        "--project-status", action="store_true", help="Show source/API stats and exit"
    )
    parser.add_argument(
        "--prune", action="store_true", help="Delete stale managed IOCs not in source"
    )
    parser.add_argument(
        "--log-level",
        default="WARNING",
        choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
        help="Logging level (default: WARNING)",
    )
    parser.add_argument(
        "--stage",
        choices=["assess", "report", "deploy"],
        help="Rollout stage (assess=read-only, report=passive, deploy=active)",
    )
    parser.add_argument(
        "--prevalence-threshold",
        type=int,
        help="Max device count before skipping/warning",
    )
    parser.add_argument(
        "--prevalence-max",
        type=int,
        default=50,
        help="Max indicators for prevalence report",
    )
    parser.add_argument(
        "--skip-prevalence-report", action="store_true", help="Skip prevalence report"
    )
    parser.add_argument(
        "--summary-json", help="Write machine-readable run summary to JSON"
    )
    parser.add_argument(
        "--host-groups",
        help="Comma-separated list of Host Group names (overrides config)",
    )
    parser.add_argument(
        "--global",
        action="store_true",
        dest="global_scope",
        help="Force global deployment (ignores configured host groups)",
    )
    parser.add_argument(
        "--confirm-write",
        action="store_true",
        help="Required for non-dry-run report/deploy",
    )
    parser.add_argument(
        "--remove-all",
        action="store_true",
        help="Remove ALL indicators created by this project (requires --confirm-write)",
    )
    return parser.parse_args()


def setup_logging(level: str):
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.DEBUG),
        format="%(asctime)s %(levelname)s %(message)s",
    )


def print_run_summary(summary: dict, host_groups: list[str], host_group_ids: list[str]):
    counts = summary.get("counts", {})
    source_stats = summary.get("source_stats", {})
    sync_plan = summary.get("sync_plan", {})
    prevalence_stats = summary.get("prevalence_stats", {})

    scope = "global"
    if host_groups:
        scope = f"host-groups ({len(host_groups)})"

    print("\nRun Summary")
    print(
        "- Stage: {stage} | Action: {action} | Dry run: {dry_run}".format(
            stage=summary.get("stage", "unknown"),
            action=summary.get("action", "unknown"),
            dry_run=summary.get("dry_run", False),
        )
    )
    print(f"- Scope: {scope}")
    if host_group_ids:
        print(f"- Host group IDs: {', '.join(host_group_ids)}")
    print(
        "- Indicators: selected={selected}, priority={priority}, safe={safe}, unsafe={unsafe}".format(
            selected=counts.get("selected", 0),
            priority=counts.get("priority_hits", 0),
            safe=counts.get("safe", 0),
            unsafe=counts.get("unsafe", 0),
        )
    )
    print(
        "- Source stats: raw_domains={raw_domains}, normalized_domains={normalized_domains}, deduped={deduped}".format(
            raw_domains=source_stats.get("raw_domains", 0),
            normalized_domains=source_stats.get("normalized_domains", 0),
            deduped=source_stats.get("deduped", 0),
        )
    )

    if all(k in sync_plan for k in ("create", "update", "delete", "unchanged")):
        print(
            "- Sync plan: create={create}, update={update}, unchanged={unchanged}, delete={delete}".format(
                create=sync_plan.get("create", 0),
                update=sync_plan.get("update", 0),
                unchanged=sync_plan.get("unchanged", 0),
                delete=sync_plan.get("delete", 0),
            )
        )
    elif sync_plan.get("status"):
        print(f"- Sync plan: {sync_plan.get('status')}")

    if (
        isinstance(prevalence_stats, dict)
        and prevalence_stats.get("evaluated") is not None
    ):
        print(
            "- Prevalence: evaluated={evaluated}, high_prevalence_domains={high}".format(
                evaluated=prevalence_stats.get("evaluated", 0),
                high=prevalence_stats.get("high_prevalence_domains", 0),
            )
        )


def main() -> int:
    args = parse_args()
    setup_logging(args.log_level)

    config_path = Path(args.config)
    env_file = resolve_env_file_path(args.env_file)
    env = load_dotenv(env_file)
    config = load_simple_yaml(config_path)

    if not config_path.exists():
        LOGGER.warning("Config file not found: %s", config_path)
        LOGGER.warning(
            "Create it from example-config.yaml (cp example-config.yaml config.yaml)."
        )
        LOGGER.warning("Using built-in defaults for now.")

    stage = (
        (args.stage or str(config.get("policy", {}).get("deployment_stage", "assess")))
        .strip()
        .lower()
    )
    if stage not in {"assess", "report", "deploy"}:
        raise RuntimeError(
            f"Unsupported stage '{stage}'. Use assess, report, or deploy."
        )

    prevalence_threshold = (
        args.prevalence_threshold
        if args.prevalence_threshold is not None
        else int(config.get("policy", {}).get("prevalence_threshold", 25))
    )

    LOGGER.info("Configuration Echo:")
    LOGGER.info("  - Stage: %s", stage)
    LOGGER.info("  - Prevalence Threshold: %s", prevalence_threshold)
    LOGGER.info("  - Limit: %s", args.limit if args.limit > 0 else "All")
    LOGGER.info(
        "  - Priority Platforms: %d configured",
        len(config.get("rollout", {}).get("priority_platforms", [])),
    )
    LOGGER.info(
        "  - Excluded Platforms: %d configured",
        len(config.get("safety", {}).get("excluded_platforms", [])),
    )
    LOGGER.info(
        "  - Excluded Domains: %d configured",
        len(config.get("safety", {}).get("excluded_domains", [])),
    )

    # CLI override for host groups
    host_groups_config = config.get("rollout", {}).get("host_groups", [])
    if args.global_scope:
        host_groups_config = []
        LOGGER.info("  - Host Groups: Cleared via --global (Global Deployment)")
    elif args.host_groups is not None:
        raw_groups = args.host_groups.strip()
        if not raw_groups:
            host_groups_config = []  # Explicit empty string clears host groups (global)
            LOGGER.info("  - Host Groups: Cleared via CLI (Global Deployment)")
        else:
            host_groups_config = [x.strip() for x in raw_groups.split(",") if x.strip()]
            LOGGER.info("  - Host Groups: Overridden via CLI: %s", host_groups_config)
    elif host_groups_config:
        LOGGER.info("  - Host Groups: %s", host_groups_config)
    else:
        LOGGER.info("  - Host Groups: None (Global Deployment)")

    # Safety Checks and Confirmations
    is_write_stage = stage in ("report", "deploy")
    is_global = not host_groups_config

    if is_write_stage and not args.dry_run:
        print(
            f"\n!!! SAFETY WARNING: You are about to run in '{stage.upper()}' mode. !!!"
        )
        if is_global:
            print("!!! SCOPE WARNING: This will apply to ALL hosts (Global Scope). !!!")
            if not args.confirm_write:
                user_input = input("Type 'GLOBAL' to confirm global deployment: ")
                if user_input.strip() != "GLOBAL":
                    LOGGER.error("Global deployment not confirmed. Aborting.")
                    return 1
        else:
            print(f"Scope: {len(host_groups_config)} Host Groups.")
            if not args.confirm_write:
                user_input = input("Type 'yes' to confirm deployment: ")
                if user_input.lower().strip() != "yes":
                    LOGGER.error("Deployment not confirmed. Aborting.")
                    return 1

        # If we passed the interactive check, we treat it as confirmed
        args.confirm_write = True

    if args.dry_run:
        LOGGER.info("  - Mode: DRY-RUN")

    data = fetch_lolrmm()
    desired, stats = collect_domains(data, config=config, limit=args.limit)

    LOGGER.info("Source stats:")
    for key in SOURCE_STATS_KEYS:
        LOGGER.info("- %s: %s", key, stats[key])

    client_id = args.client_id or env.get("CLIENT_ID")
    client_secret = args.client_secret or env.get("CLIENT_SECRET")
    base_url = args.base_url or env.get("BASE_URL")

    if not client_id or not client_secret:
        if args.project_status:
            LOGGER.info("No API credentials provided, source-only status shown.")
            return 0
        LOGGER.error("Missing CrowdStrike API credentials.")
        LOGGER.error(
            "Provide --client-id/--client-secret or set CLIENT_ID/CLIENT_SECRET in .env."
        )
        LOGGER.error("Credentials can be created in Falcon at:")
        LOGGER.error("https://falcon.crowdstrike.com/api-clients-and-keys")
        LOGGER.error("Expected .env keys: CLIENT_ID, CLIENT_SECRET, BASE_URL(optional)")
        if not env:
            LOGGER.error("Resolved env file path: %s (not found or empty)", env_file)
            LOGGER.error(
                "Create .env in this directory or pass --env-file with the correct path."
            )
        return 2

    if IOC is None:
        LOGGER.error(
            "falconpy is not installed. Install it with: uv pip install crowdstrike-falconpy"
        )
        return 2

    kwargs = {"client_id": client_id, "client_secret": client_secret}
    if base_url:
        kwargs["base_url"] = base_url
    client = IOC(**kwargs)

    if args.remove_all:
        LOGGER.info("Remove All mode enabled.")
        LOGGER.info("Fetching all managed indicators...")

        # Use existing filter logic to only find project indicators
        managed_iocs = iter_managed_iocs(client)

        count = len(managed_iocs)
        LOGGER.info(
            "Found %d managed indicators from project '%s'.", count, PROJECT_SOURCE
        )

        if count == 0:
            LOGGER.info("No indicators to remove.")
            return 0

        if args.dry_run:
            LOGGER.info("DRY-RUN: Would remove %d indicators.", count)
            # Show a sample
            for item in managed_iocs[:5]:
                LOGGER.info(
                    "  - Would delete: %s (ID: %s)", item.get("value"), item.get("id")
                )
            if count > 5:
                LOGGER.info("  ... and %d more.", count - 5)
            return 0

        if not args.confirm_write:
            LOGGER.error(
                "To remove all indicators, you must also pass --confirm-write."
            )
            return 1

        LOGGER.info("Removing %d indicators...", count)
        ids_to_delete = [item["id"] for item in managed_iocs if item.get("id")]

        # chunked logic inline to avoid import cycle or extra deps
        chunk_size = 500
        total_batches = (len(ids_to_delete) + chunk_size - 1) // chunk_size

        for i in range(0, len(ids_to_delete), chunk_size):
            batch = ids_to_delete[i : i + chunk_size]
            current_batch = (i // chunk_size) + 1
            LOGGER.info(
                "Deleting batch %d/%d (%d items)",
                current_batch,
                total_batches,
                len(batch),
            )

            response = client.indicator_delete(ids=batch)
            if response["status_code"] not in (200, 201):
                LOGGER.error("Error deleting batch: %s", response)
            else:
                body = response.get("body", {})
                errors = body.get("errors", [])
                if errors:
                    LOGGER.error("Partial errors in batch: %s", errors)

        LOGGER.info("Removal complete.")
        return 0

    # Resolve Host Groups if configured
    host_group_ids = []
    if host_groups_config:
        LOGGER.info("Resolving host group IDs for: %s", host_groups_config)
        host_group_ids = resolve_host_group_ids(
            client_id=client_id,
            client_secret=client_secret,
            base_url=base_url,
            group_names=host_groups_config,
        )
        if not host_group_ids:
            LOGGER.error(
                "Host groups configured but none resolved. Aborting to prevent global rollout safety risk."
            )
            return 1
        LOGGER.info("Resolved %d host group IDs.", len(host_group_ids))

    action = (
        "none"
        if stage == "assess"
        else resolve_action(client, stage=stage, config=config)
    )
    platforms = resolve_platforms(client)
    LOGGER.info("Stage: %s", stage)
    LOGGER.info("Available actions: %s", list_available_actions(client))
    LOGGER.info("Resolved action: %s", action)
    LOGGER.info("Resolved platforms: %s", platforms if platforms else "none")
    LOGGER.info("Configured severity: %s", DEFAULT_SEVERITY)
    LOGGER.info("Configured source: %s", PROJECT_SOURCE)
    LOGGER.info("Configured tags: %s", PROJECT_TAGS)
    if host_group_ids:
        LOGGER.info(
            "Scoped to Host Groups: %s (IDs: %s)", host_groups_config, host_group_ids
        )

    if args.project_status:
        managed_count = len(iter_managed_iocs(client))
        LOGGER.info("Current managed IOC count in tenant: %d", managed_count)
        print(f"Project status: managed IOC count = {managed_count}")
        return 0

    should_run_prevalence = (not args.skip_prevalence_report) and stage == "assess"
    prevalence_stats = dict(DEFAULT_PREVALENCE_STATS)
    sync_plan = dict(DEFAULT_SYNC_PLAN)

    if stage == "assess":
        if should_run_prevalence:
            prevalence_stats = run_prevalence_report(
                client=client,
                desired=desired,
                threshold=prevalence_threshold,
                max_items=args.prevalence_max,
            )
        else:
            LOGGER.info("Assess stage selected and prevalence report skipped.")
    else:
        if not args.dry_run and not args.confirm_write:
            raise RuntimeError(
                "Write stage requires --confirm-write (or run with --dry-run)."
            )
        sync_plan = sync(
            client=client,
            desired=desired,
            dry_run=args.dry_run,
            retrodetects=args.retrodetects,
            prune=args.prune,
            action=action,
            platforms=platforms,
            host_groups=host_group_ids,
        )

    summary_payload = build_summary_payload(
        desired=desired,
        stats=stats,
        stage=stage,
        action=action,
        dry_run=args.dry_run,
        sync_plan=sync_plan,
        prevalence_stats=prevalence_stats,
    )

    if args.summary_json:
        write_json_summary(
            Path(args.summary_json),
            summary_payload,
        )

    print_run_summary(summary_payload, host_groups_config, host_group_ids)
    LOGGER.info("Done.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
