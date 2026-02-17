import logging
from dataclasses import dataclass, field

from source import NormalizedEntry

PROJECT_SOURCE = "tisu_rmm_detection_ioc"
PROJECT_TAGS = ["tisu", "rmm_detection", "feed_lolrmm"]
DEFAULT_PLATFORMS = ["windows", "mac", "linux"]
DEFAULT_ACTION = "detect"
DEFAULT_SEVERITY = "informational"

LOGGER = logging.getLogger(__name__)


@dataclass
class IndicatorPayload:
    type: str
    value: str
    action: str
    severity: str
    source: str
    description: str
    applied_globally: bool = True
    tags: list[str] = field(default_factory=list)
    platforms: list[str] = field(default_factory=list)
    host_groups: list[str] = field(default_factory=list)
    id: str | None = None

    def to_api(self) -> dict:
        payload = {
            "type": self.type,
            "value": self.value,
            "action": self.action,
            "severity": self.severity,
            "source": self.source,
            "description": self.description,
            "tags": self.tags,
        }
        if self.platforms:
            payload["platforms"] = self.platforms
        if self.host_groups:
            payload["host_groups"] = self.host_groups
            payload["applied_globally"] = False
        else:
            payload["applied_globally"] = self.applied_globally

        if self.id:
            payload["id"] = self.id
        return payload


def fql_escape(value: str) -> str:
    return value.replace("'", "\\'")


def iter_managed_iocs(client) -> list:
    items = []
    after = None
    while True:
        kwargs = {
            "filter": f"source:'{fql_escape(PROJECT_SOURCE)}'+type:'domain'",
            "limit": 500,
        }
        if after:
            kwargs["after"] = after
        response = client.indicator_combined(**kwargs)
        body = response.get("body") or {}
        resources = body.get("resources") or []
        items.extend(resources)
        after = ((body.get("meta") or {}).get("pagination") or {}).get("after")
        if not after:
            break
    deduped = {}
    for item in items:
        deduped[item.get("id")] = item
    items = list(deduped.values())
    LOGGER.debug("Fetched %d managed indicators", len(items))
    return items


def list_available_actions(client) -> list:
    response = client.action_query(limit=200)
    body = response.get("body") or {}
    resources = body.get("resources") or []
    return sorted({str(x).lower() for x in resources})


def resolve_action(client, stage: str, config: dict) -> str:
    action_names = list_available_actions(client)
    if not action_names:
        raise RuntimeError("No IOC actions returned by API. Cannot continue.")

    # API QUIRK: action_query returns 'none', but indicator_create requires 'no_action'.
    # We patch the available list to ensure no_action is selectable.
    if "none" in action_names and "no_action" not in action_names:
        action_names.append("no_action")

    if stage == "report":
        candidates = [
            str(x).strip().lower()
            for x in config.get("policy", {}).get("report_action_candidates", [])
            if str(x).strip()
        ]
        for candidate in candidates:
            if candidate in action_names:
                return candidate
        raise RuntimeError(
            "Report stage requested, but none of report_action_candidates are available. "
            f"Configured: {candidates}, Available: {action_names}"
        )

    deploy_action = (
        str(config.get("policy", {}).get("deploy_action", DEFAULT_ACTION))
        .strip()
        .lower()
    )
    if deploy_action in action_names:
        return deploy_action

    if DEFAULT_ACTION in action_names:
        LOGGER.warning(
            "Configured deploy_action '%s' unavailable. Using default '%s'.",
            deploy_action,
            DEFAULT_ACTION,
        )
        return DEFAULT_ACTION

    fallback = action_names[0]
    LOGGER.warning("Configured deploy_action unavailable. Using '%s'.", fallback)
    return fallback


def resolve_platforms(client) -> list:
    response = client.platform_query(limit=200)
    body = response.get("body") or {}
    resources = body.get("resources") or []
    available = {str(x).lower() for x in resources}
    chosen = [x for x in DEFAULT_PLATFORMS if x in available]
    if chosen:
        return chosen
    LOGGER.warning("Could not resolve preferred platforms; omitting platforms field.")
    return []


def resolve_host_group_ids(
    client_id: str, client_secret: str, base_url: str | None, group_names: list[str]
) -> list[str]:
    """Resolve Host Group names to IDs using the HostGroups service."""
    if not group_names:
        return []

    try:
        from falconpy import HostGroup
    except ImportError:
        LOGGER.error("falconpy not installed; cannot resolve host groups.")
        return []

    kwargs = {"client_id": client_id, "client_secret": client_secret}
    if base_url:
        kwargs["base_url"] = base_url
    hg_client = HostGroup(**kwargs)

    found_ids: list[str] = []
    found_names: set[str] = set()

    # Resolve each name independently. Use wildcard name query because
    # exact name:'value' filters can return empty results in some tenants.
    for name in group_names:
        fql_filter = f"name:*'{fql_escape(name)}*'"
        resp = hg_client.query_combined_host_groups(filter=fql_filter, limit=100)
        if resp.get("status_code") != 200:
            LOGGER.error("Failed to query host group '%s': %s", name, resp.get("body"))
            continue

        resources = (resp.get("body") or {}).get("resources") or []
        if not resources:
            continue

        normalized = name.strip().lower()
        exact_matches = [
            g
            for g in resources
            if isinstance(g, dict)
            and str(g.get("name") or "").strip().lower() == normalized
        ]

        for group in exact_matches:
            gid = group.get("id")
            if gid:
                found_ids.append(str(gid))
                found_names.add(str(group.get("name") or name))

        # If no exact match but wildcard returned results, accept a single match.
        if not exact_matches and len(resources) == 1 and isinstance(resources[0], dict):
            gid = resources[0].get("id")
            if gid:
                LOGGER.warning(
                    "Host Group '%s' matched by wildcard only; using '%s'.",
                    name,
                    resources[0].get("name"),
                )
                found_ids.append(str(gid))
                found_names.add(name)

    deduped_ids = list(dict.fromkeys(found_ids))

    for name in group_names:
        if name not in found_names:
            LOGGER.warning("Host Group not found: '%s'", name)

    if not deduped_ids:
        LOGGER.warning("No host groups found matching: %s", group_names)

    return deduped_ids


def make_indicator(
    entry: NormalizedEntry,
    action: str,
    platforms: list[str],
    host_groups: list[str] | None = None,
) -> IndicatorPayload:
    tool = entry.tool
    domain = entry.domain
    tools = entry.tools or [tool]
    base_text = (
        entry.description or "Remote monitoring and management domain from LOLRMM"
    )
    tool_text = ", ".join(tools[:6])
    if len(tools) > 6:
        tool_text = f"{tool_text}, +{len(tools) - 6} more"
    description = f"[tisu_rmm] tools={tool_text}; note={base_text}"[:4096]
    return IndicatorPayload(
        type="domain",
        value=domain,
        action=action,
        severity=DEFAULT_SEVERITY,
        source=PROJECT_SOURCE,
        description=description,
        applied_globally=(not host_groups),
        tags=PROJECT_TAGS,
        platforms=platforms,
        host_groups=host_groups or [],
    )


def extract_device_count(response: dict) -> int:
    body = response.get("body") or {}
    resources = body.get("resources") or []

    if isinstance(resources, dict):
        resources = [resources]

    if resources:
        first = resources[0]
        if isinstance(first, int):
            return first
        if isinstance(first, dict):
            for key in ["device_count", "count", "total", "devices_count"]:
                if key in first:
                    try:
                        return int(first[key])
                    except (ValueError, TypeError):
                        return 0
    return 0
