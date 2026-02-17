import datetime as dt
import logging
from dataclasses import replace

from crowdstrike_api import iter_managed_iocs, make_indicator
from source import NormalizedEntry

LOGGER = logging.getLogger(__name__)

COMPARE_FIELDS = [
    "action",
    "severity",
    "source",
    "description",
    "applied_globally",
    "tags",
    "platforms",
    "host_groups",
]


def chunked(items: list, size: int) -> list:
    return [items[i : i + size] for i in range(0, len(items), size)]


def _field_diff(payload, existing_item: dict) -> list[str]:
    changes = []
    for field in COMPARE_FIELDS:
        left = getattr(payload, field, None)
        right = existing_item.get(field)
        if isinstance(left, list):
            left = sorted(str(x).lower() for x in left)
            right = sorted(str(x).lower() for x in (right or []))
        if left != right:
            changes.append(field)
    return changes


def sync(
    client,
    desired: list[NormalizedEntry],
    dry_run: bool,
    retrodetects: bool,
    prune: bool,
    action: str,
    platforms: list,
    host_groups: list[str] | None = None,
) -> dict:
    existing = iter_managed_iocs(client)
    existing_by_key = {
        (str(item.get("type", "")).lower(), str(item.get("value", "")).lower()): item
        for item in existing
    }

    desired_payloads = [
        make_indicator(x, action=action, platforms=platforms, host_groups=host_groups)
        for x in desired
    ]
    desired_by_key = {(d.type, d.value.lower()): d for d in desired_payloads}

    to_create = []
    to_update = []
    unchanged = 0
    dry_run_details = {"creates": [], "updates": []}

    for key, payload in desired_by_key.items():
        existing_item = existing_by_key.get(key)
        if not existing_item:
            to_create.append(payload)
            if dry_run and len(dry_run_details["creates"]) < 10:
                dry_run_details["creates"].append(payload.value)
            continue

        changes = _field_diff(payload, existing_item)
        if changes:
            to_update.append(replace(payload, id=existing_item["id"]))
            if dry_run and len(dry_run_details["updates"]) < 10:
                dry_run_details["updates"].append(
                    {"value": payload.value, "fields": changes}
                )
        else:
            unchanged += 1

    to_delete = []
    if prune:
        desired_keys = set(desired_by_key.keys())
        to_delete = [
            item["id"]
            for key, item in existing_by_key.items()
            if key not in desired_keys
        ]

    LOGGER.info("Managed existing IOC count: %d", len(existing))
    LOGGER.info(
        "Plan -> create: %d, update: %d, unchanged: %d, delete: %d",
        len(to_create),
        len(to_update),
        unchanged,
        len(to_delete),
    )

    if dry_run:
        if dry_run_details["creates"]:
            LOGGER.info("Dry run: First 10 planned creates:")
            for val in dry_run_details["creates"]:
                LOGGER.info("  + %s", val)
        if dry_run_details["updates"]:
            LOGGER.info("Dry run: First 10 planned updates:")
            for item in dry_run_details["updates"]:
                LOGGER.info(
                    "  ~ %s (fields: %s)", item["value"], ", ".join(item["fields"])
                )
        return {
            "create": len(to_create),
            "update": len(to_update),
            "delete": len(to_delete),
            "unchanged": unchanged,
        }

    date_text = dt.datetime.utcnow().strftime("%Y-%m-%d")
    comment = f"[autormmdetect] sync_{date_text.replace('-', '')}"

    for batch in chunked(to_create, 200):
        kwargs = {
            "indicators": [x.to_api() for x in batch],
            "comment": comment,
            "ignore_warnings": True,
        }
        if retrodetects:
            kwargs["retrodetects"] = True
        response = client.indicator_create(**kwargs)
        errors = (
            (response.get("body") or {}).get("errors") or response.get("errors") or []
        )
        if errors:
            LOGGER.error("Create batch errors: %s", errors)
            if batch:
                LOGGER.error(
                    "Sample failed payload (first item): %s", batch[0].to_api()
                )
            resources = (response.get("body") or {}).get("resources") or []
            if resources:
                LOGGER.error("Detailed resources response: %s", resources)

    for batch in chunked(to_update, 200):
        kwargs = {
            "indicators": [x.to_api() for x in batch],
            "comment": comment,
            "ignore_warnings": True,
        }
        if retrodetects:
            kwargs["retrodetects"] = True
        response = client.indicator_update(**kwargs)
        errors = (
            (response.get("body") or {}).get("errors") or response.get("errors") or []
        )
        if errors:
            LOGGER.error("Update batch errors: %s", errors)

    if to_delete:
        for batch in chunked(to_delete, 500):
            response = client.indicator_delete(ids=batch)
            errors = (
                (response.get("body") or {}).get("errors")
                or response.get("errors")
                or []
            )
            if errors:
                LOGGER.error("Delete batch errors: %s", errors)

    return {
        "create": len(to_create),
        "update": len(to_update),
        "delete": len(to_delete),
        "unchanged": unchanged,
    }
