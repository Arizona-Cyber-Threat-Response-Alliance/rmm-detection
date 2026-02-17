import datetime as dt
import json
import logging
from pathlib import Path

from crowdstrike_api import extract_device_count
from source import SOURCE_STATS_KEYS, is_domain_ioc_safe

LOGGER = logging.getLogger(__name__)

SUMMARY_SCHEMA_VERSION = "1.0"
SUMMARY_COUNT_KEYS = ("selected", "safe", "unsafe", "priority_hits")
SUMMARY_SYNC_PLAN_KEYS = ("create", "update", "delete", "unchanged")
DEFAULT_PREVALENCE_STATS = {"status": "skipped"}
DEFAULT_SYNC_PLAN = {"status": "not_applicable"}


def run_prevalence_report(
    client, desired: list, threshold: int, max_items: int
) -> dict:
    filtered = [entry for entry in desired if is_domain_ioc_safe(entry.domain)]
    if max_items and max_items > 0:
        filtered = filtered[:max_items]

    domain_results = []
    tool_max = {}
    for entry in filtered:
        response = client.devices_count(type="domain", value=entry.domain)
        count = extract_device_count(response)
        domain_results.append(
            {"tool": entry.tool, "domain": entry.domain, "count": count}
        )
        current = tool_max.get(entry.tool, 0)
        if count > current:
            tool_max[entry.tool] = count

    high_prevalence = [x for x in domain_results if x["count"] >= threshold]
    high_tools = sorted(tool for tool, count in tool_max.items() if count >= threshold)

    LOGGER.info("Prevalence report:")
    LOGGER.info("- evaluated_indicators: %d", len(domain_results))
    LOGGER.info("- threshold: %d", threshold)
    LOGGER.info("- high_prevalence_domains: %d", len(high_prevalence))
    LOGGER.info("- high_prevalence_tools: %d", len(high_tools))

    if high_tools:
        LOGGER.info(
            "Suggested allowlist review candidates (add to excluded_platforms):"
        )
        for tool in high_tools:
            LOGGER.info("  - %s", tool)

    low_prevalence = sorted(
        [x for x in domain_results if x["count"] < threshold],
        key=lambda x: (x["count"], x["domain"]),
    )

    return {
        "evaluated": len(domain_results),
        "high_prevalence_domains": len(high_prevalence),
        "high_prevalence_tools": high_tools,
        "low_prevalence_sample": low_prevalence[:20],
    }


def write_json_summary(output_path: Path, summary_data: dict):
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(normalize_summary(summary_data), indent=2), encoding="utf-8"
    )
    LOGGER.info("Wrote JSON summary: %s", output_path)


def build_summary_payload(
    desired: list,
    stats: dict,
    stage: str,
    action: str,
    dry_run: bool,
    sync_plan: dict,
    prevalence_stats: dict,
) -> dict:
    safe_count = sum(1 for x in desired if is_domain_ioc_safe(x.domain))
    return normalize_summary(
        {
            "counts": {
                "selected": len(desired),
                "safe": safe_count,
                "unsafe": len(desired) - safe_count,
                "priority_hits": sum(1 for x in desired if x.priority),
            },
            "source_stats": stats,
            "sync_plan": sync_plan,
            "prevalence_stats": prevalence_stats,
            "stage": stage,
            "action": action,
            "dry_run": dry_run,
        }
    )


def normalize_summary(summary_data: dict) -> dict:
    data = summary_data if isinstance(summary_data, dict) else {}

    raw_counts = data.get("counts", {})
    counts = raw_counts if isinstance(raw_counts, dict) else {}
    normalized_counts = {
        key: _safe_int(counts.get(key, 0)) for key in SUMMARY_COUNT_KEYS
    }

    raw_source_stats = data.get("source_stats", {})
    source_stats = raw_source_stats if isinstance(raw_source_stats, dict) else {}
    normalized_source_stats = {
        key: _safe_int(source_stats.get(key, 0)) for key in SOURCE_STATS_KEYS
    }

    raw_sync_plan = data.get("sync_plan", {})
    sync_plan = raw_sync_plan if isinstance(raw_sync_plan, dict) else {}
    normalized_sync_plan = dict(DEFAULT_SYNC_PLAN)
    if all(key in sync_plan for key in SUMMARY_SYNC_PLAN_KEYS):
        normalized_sync_plan = {
            key: _safe_int(sync_plan.get(key, 0)) for key in SUMMARY_SYNC_PLAN_KEYS
        }

    prevalence_stats = data.get("prevalence_stats")
    if not isinstance(prevalence_stats, dict):
        prevalence_stats = dict(DEFAULT_PREVALENCE_STATS)

    stage = str(data.get("stage", "unknown"))
    action = str(data.get("action", "unknown"))
    dry_run = bool(data.get("dry_run", False))

    return {
        "summary_schema_version": SUMMARY_SCHEMA_VERSION,
        "generated_at": dt.datetime.now(dt.UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "counts": normalized_counts,
        "source_stats": normalized_source_stats,
        "sync_plan": normalized_sync_plan,
        "prevalence_stats": prevalence_stats,
        "stage": stage,
        "action": action,
        "dry_run": dry_run,
    }


def _safe_int(value, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default
