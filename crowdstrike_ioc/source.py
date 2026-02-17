import json
import logging
import re
import urllib.request
from dataclasses import dataclass, field

LOLRMM_URL = "https://lolrmm.io/api/rmm_tools.json"
PLACEHOLDER_VALUES = {"", "user_managed", "unknown", "n/a", "na", "none"}
IPV4_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
DOMAIN_IOC_RE = re.compile(r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")
SOURCE_STATS_KEYS = (
    "tools_total",
    "tools_excluded",
    "raw_domains",
    "normalized_domains",
    "priority_domains",
    "skipped_placeholders",
    "skipped_ipv4",
    "skipped_excluded_domains",
    "deduped",
)

LOGGER = logging.getLogger(__name__)


@dataclass
class NormalizedEntry:
    domain: str
    tool: str
    tools: list[str] = field(default_factory=list)
    description: str = ""
    priority: bool = False


def fetch_lolrmm() -> list:
    LOGGER.debug("Fetching LOLRMM feed: %s", LOLRMM_URL)
    req = urllib.request.Request(LOLRMM_URL, headers={"User-Agent": "Mozilla/5.0"})
    with urllib.request.urlopen(req, timeout=60) as response:
        return json.loads(response.read().decode("utf-8"))


def normalize_domain(value: str) -> str:
    domain = value.strip().lower()
    if not domain:
        return ""
    if "://" in domain:
        domain = domain.split("://", 1)[1]
    domain = domain.split("/", 1)[0].strip()
    if ":" in domain:
        domain = domain.split(":")[0].strip()
    while domain.startswith("*"):
        domain = domain[1:]
    if domain.startswith("."):
        domain = domain[1:]
    if domain.startswith("-"):
        domain = domain.lstrip("-")
    return domain.rstrip(".")


def is_ipv4(value: str) -> bool:
    if not IPV4_RE.match(value):
        return False
    return all(0 <= int(part) <= 255 for part in value.split("."))


def is_domain_ioc_safe(value: str) -> bool:
    # Basic structural check (no wildcards in middle, no spaces)
    if "*" in value or " " in value:
        return False
    # Ensure it looks somewhat like a domain
    return bool(DOMAIN_IOC_RE.match(value))


def collect_domains(
    data: list, config: dict, limit: int = 0
) -> tuple[list[NormalizedEntry], dict]:
    excluded_tools = {
        x.strip().lower()
        for x in config.get("safety", {}).get("excluded_platforms", [])
        if str(x).strip()
    }
    priority_tools = {
        x.strip().lower()
        for x in config.get("rollout", {}).get("priority_platforms", [])
        if str(x).strip()
    }
    excluded_domains = {
        normalize_domain(x)
        for x in config.get("safety", {}).get("excluded_domains", [])
        if str(x).strip()
    }

    stats = {
        "tools_total": len(data),
        "tools_excluded": 0,
        "raw_domains": 0,
        "normalized_domains": 0,
        "priority_domains": 0,
        "skipped_placeholders": 0,
        "skipped_ipv4": 0,
        "skipped_excluded_domains": 0,
        "deduped": 0,
    }

    seen_pairs = set()
    domain_map = {}
    for tool in data:
        tool_name = (tool.get("Name") or "Unknown Tool").strip()
        if tool_name.lower() in excluded_tools:
            stats["tools_excluded"] += 1
            continue

        tool_desc = (tool.get("Description") or "").strip()
        artifacts = tool.get("Artifacts") or {}
        for net in artifacts.get("Network") or []:
            for raw_domain in net.get("Domains") or []:
                if not isinstance(raw_domain, str):
                    continue
                stats["raw_domains"] += 1
                domain = normalize_domain(raw_domain)
                if not domain or domain in PLACEHOLDER_VALUES:
                    stats["skipped_placeholders"] += 1
                    continue
                if is_ipv4(domain):
                    stats["skipped_ipv4"] += 1
                    continue

                # Check for invalid characters or structure
                if not is_domain_ioc_safe(domain):
                    LOGGER.debug("Skipping unsafe/invalid domain format: %s", domain)
                    stats["skipped_placeholders"] += 1
                    continue

                if domain in excluded_domains:
                    stats["skipped_excluded_domains"] += 1
                    continue

                pair_key = (domain, tool_name.lower())
                if pair_key in seen_pairs:
                    stats["deduped"] += 1
                    continue
                seen_pairs.add(pair_key)

                if domain not in domain_map:
                    domain_map[domain] = {"tools": set(), "descriptions": set()}
                domain_map[domain]["tools"].add(tool_name)
                if tool_desc:
                    domain_map[domain]["descriptions"].add(tool_desc)

    ordered_domains = sorted(
        domain_map.keys(),
        key=lambda domain: (
            0
            if any(
                tool.lower() in priority_tools for tool in domain_map[domain]["tools"]
            )
            else 1,
            domain,
        ),
    )

    results = []
    for domain in ordered_domains:
        tools = sorted(domain_map[domain]["tools"], key=lambda x: x.lower())
        descriptions = sorted(
            domain_map[domain]["descriptions"], key=lambda x: x.lower()
        )
        is_priority = any(tool.lower() in priority_tools for tool in tools)
        if is_priority:
            stats["priority_domains"] += 1
        results.append(
            NormalizedEntry(
                domain=domain,
                tool=tools[0] if tools else "Unknown Tool",
                tools=tools,
                description=descriptions[0]
                if descriptions
                else "Remote monitoring and management domain from LOLRMM",
                priority=is_priority,
            )
        )

    if limit and limit > 0:
        results = results[:limit]
    stats["normalized_domains"] = len(results)
    return results, stats
