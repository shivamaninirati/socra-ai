"""Threat Intelligence - modular provider architecture (Task 22).

Providers are ONLY used when configured (API keys from the environment).
When a provider is not configured it reports a real "Provider not configured"
state - the service never pretends an external provider is available, and it
never fabricates reputation results. Provider lookup failures are captured as
errors, not crashes, and API keys are never returned to clients.

Results are split into two honest halves:

1. SOCRA INTERNAL INTELLIGENCE - real occurrences of the indicator in local
   persisted telemetry (events / cases / investigations), bounded to a recent
   window. Substring matches are labeled as such - never implied to be exact
   indicator hits.

2. EXTERNAL THREAT INTELLIGENCE - per-provider results only when the provider
   is configured AND returned real data. Unconfigured providers report
   "Provider not configured"; non-applicable providers (e.g. AbuseIPDB for a
   domain) report "not applicable". Nothing is fabricated.
"""

import ipaddress
import logging
import re
import time
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

# Status values reported to clients (never a fabricated reputation).
STATUS_OK = "ok"
STATUS_ERROR = "error"
STATUS_NOT_CONFIGURED = "not_configured"
STATUS_NOT_APPLICABLE = "not_applicable"

# Indicator types (display strings).
TYPE_IPV4 = "IPv4 Address"
TYPE_IPV6 = "IPv6 Address"
TYPE_DOMAIN = "Domain"
TYPE_URL = "URL"
TYPE_MD5 = "MD5"
TYPE_SHA1 = "SHA-1"
TYPE_SHA256 = "SHA-256"
TYPE_UNKNOWN = "Unknown"

_UNKNOWN_DETAIL = (
    "Not a valid IP address, domain, URL, MD5, SHA-1 or SHA-256 hash. "
    "Check the indicator and try again."
)

_HASH_PATTERNS = (
    (TYPE_MD5, re.compile(r"^[a-fA-F0-9]{32}$")),
    (TYPE_SHA1, re.compile(r"^[a-fA-F0-9]{40}$")),
    (TYPE_SHA256, re.compile(r"^[a-fA-F0-9]{64}$")),
)

_URL_RE = re.compile(r"^(?:https?|ftp)://[^\s/$.?#].[^\s]*$", re.IGNORECASE)

# Maximum hosts to report from local sightings.
_MAX_INTERNAL_EVENTS = 10
_INTERNAL_WINDOW_DAYS = 7


def _looks_like_domain(value: str) -> bool:
    """Best-effort domain validation (no external lookups, no fabrication).

    Accepts hostnames with 2+ dot-separated labels where each label is a valid
    DNS label (1-63 chars, alphanumeric + hyphen, not starting/ending with a
    hyphen) and the final label is 2-24 alphabetic characters. Rejects strings
    that merely contain a dot (e.g. file names, decimal numbers).
    """
    value = (value or "").strip().lower().rstrip(".")
    if len(value) < 4 or len(value) > 253 or ".." in value:
        return False
    # Never accept bare IP-like or numeric strings.
    try:
        ipaddress.ip_address(value)
        return False
    except ValueError:
        pass
    labels = value.split(".")
    if len(labels) < 2:
        return False
    tld = labels[-1]
    if not re.fullmatch(r"[a-z]{2,24}", tld):
        return False
    label_re = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
    return all(label_re.match(label) for label in labels)


def classify_indicator(indicator: str):
    """Strictly validate and classify an indicator value.

    Returns a dict with ``type`` (display type or Unknown), ``valid`` and an
    optional ``detail`` explaining why an input was rejected. Random text is
    NEVER treated as a hash or a domain - only real shapes pass.
    """
    indicator = (indicator or "").strip()
    if not indicator:
        return {"type": TYPE_UNKNOWN, "valid": False, "detail": "Please enter an IP address, domain, URL or hash to analyze."}

    # IP addresses (IPv4 and IPv6) via the standard library.
    try:
        addr = ipaddress.ip_address(indicator)
        return {
            "type": TYPE_IPV4 if addr.version == 4 else TYPE_IPV6,
            "valid": True,
        }
    except ValueError:
        pass

    # URLs (http/https/ftp with a host).
    if _URL_RE.match(indicator):
        try:
            parsed = urlparse(indicator)
            if parsed.hostname:
                return {"type": TYPE_URL, "valid": True}
        except Exception:
            pass
        return {"type": TYPE_UNKNOWN, "valid": False, "detail": _UNKNOWN_DETAIL}

    # Hashes: exact-length hexadecimal strings only.
    for hash_type, pattern in _HASH_PATTERNS:
        if pattern.match(indicator):
            return {"type": hash_type, "valid": True}

    # Domains: real hostname shape (label rules + alphabetic TLD).
    if _looks_like_domain(indicator):
        return {"type": TYPE_DOMAIN, "valid": True}

    return {"type": TYPE_UNKNOWN, "valid": False, "detail": _UNKNOWN_DETAIL}


def _provider_target(ioc_type: str, indicator: str):
    """Map a classified indicator to the enrichment target each provider uses.

    IPs, domains and hashes enrich directly. URLs are enriched through their
    host (a real, labeled lookup of the hostname) because reputation providers
    do not score a full URL string - the response marks ``lookup_scope`` as
    ``host_of_url`` so the analyst knows exactly what was queried.
    """
    if ioc_type in (TYPE_IPV4, TYPE_IPV6):
        return "ip", indicator, None
    if ioc_type == TYPE_DOMAIN:
        return "domain", indicator, None
    if ioc_type in (TYPE_MD5, TYPE_SHA1, TYPE_SHA256):
        return "hash", indicator, None
    if ioc_type == TYPE_URL:
        host = (urlparse(indicator).hostname or "").strip().lower()
        if not host:
            return None, indicator, None
        try:
            addr = ipaddress.ip_address(host)
            family = "ip"
            # Normalize IPv6 without brackets.
            host = str(addr)
        except ValueError:
            family = "domain" if _looks_like_domain(host) else None
        if family:
            return family, host, "host_of_url"
    return None, indicator, None


class BaseProvider:
    """Provider contract: `configured`, `lookup(indicator, ioc_type)`."""

    name = "Base"

    def __init__(self, api_key=""):
        self.api_key = (api_key or "").strip()

    @property
    def configured(self) -> bool:
        return bool(self.api_key)

    def lookup(self, indicator, ioc_type):
        raise NotImplementedError


class VirusTotalProvider(BaseProvider):
    name = "VirusTotal"

    def lookup(self, indicator, ioc_type):
        import httpx

        if ioc_type == "ip":
            endpoint = "ip_addresses"
        elif ioc_type == "domain":
            endpoint = "domains"
        else:
            endpoint = "files"
        url = f"https://www.virustotal.com/api/v3/{endpoint}/{indicator}"
        with httpx.Client(timeout=10.0) as client:
            response = client.get(
                url,
                headers={"x-apikey": self.api_key, "Accept": "application/json"},
            )
            response.raise_for_status()
            attrs = (response.json().get("data") or {}).get("attributes") or {}
            stats = attrs.get("last_analysis_stats") or {}
        malicious = int(stats.get("malicious", 0))
        total = sum(int(stats.get(k, 0)) for k in
                    ("malicious", "suspicious", "harmless", "undetected"))
        confidence = round((malicious / total) * 100) if total else 0
        return {
            "result": {
                "malicious": malicious,
                "suspicious": int(stats.get("suspicious", 0)),
                "harmless": int(stats.get("harmless", 0)),
                "undetected": int(stats.get("undetected", 0)),
                "reputation": attrs.get("reputation"),
            },
            "confidence": confidence,
        }


class AbuseIPDBProvider(BaseProvider):
    name = "AbuseIPDB"

    def lookup(self, indicator, ioc_type):
        import httpx

        if ioc_type != "ip":
            raise ValueError("AbuseIPDB only supports IP address lookups.")
        with httpx.Client(timeout=10.0) as client:
            response = client.get(
                "https://api.abuseipdb.com/api/v2/check",
                params={"ipAddress": indicator, "maxAgeInDays": 90},
                headers={"Key": self.api_key, "Accept": "application/json"},
            )
            response.raise_for_status()
            data = (response.json().get("data") or {})
        return {
            "result": {
                "abuse_score": data.get("abuseConfidenceScore", 0),
                "total_reports": data.get("totalReports", 0),
                "is_whitelisted": data.get("isWhitelisted"),
                "usage_type": data.get("usageType"),
                "country": data.get("countryCode"),
                "domain": data.get("domain"),
            },
            "confidence": int(data.get("abuseConfidenceScore", 0) or 0),
        }


def _active_providers():
    """Providers whose API keys are configured (module stays modular)."""
    from app.core.config import settings

    providers = []
    if settings.VT_API_KEY:
        providers.append(VirusTotalProvider(settings.VT_API_KEY))
    if settings.ABUSEIPDB_API_KEY:
        providers.append(AbuseIPDBProvider(settings.ABUSEIPDB_API_KEY))
    return providers


def _internal_intelligence(indicator: str, ioc_type: str) -> dict:
    """Real local sightings of the indicator in persisted telemetry.

    Every result comes from the SQLite database - never fabricated. A URL is
    searched by its full value and by its host so a sighting of the host is
    still surfaced. Matches are substring occurrences (clearly labeled) over a
    bounded window of recent events.
    """
    from app.storage.sqlite_storage import sqlite_storage

    searches = []
    if ioc_type != TYPE_UNKNOWN and indicator:
        searches.append(indicator)
    if ioc_type == TYPE_URL:
        host = (urlparse(indicator).hostname or "").strip().lower()
        if host and host not in searches:
            searches.append(host)

    if not searches:
        return {
            "window_days": _INTERNAL_WINDOW_DAYS,
            "searched": False,
            "total_sightings": 0,
            "events": [],
            "hosts": [],
            "cases": [],
            "investigations": [],
            "note": "",
        }

    merged_events = {}
    merged_hosts = []
    seen_hosts = set()
    total = 0
    cases = []
    investigations = []
    for value in searches:
        found = sqlite_storage.find_internal_ioc_occurrences(
            value,
            days=_INTERNAL_WINDOW_DAYS,
            event_summary_limit=_MAX_INTERNAL_EVENTS,
            related_limit=5,
        )
        total += found.get("total_sightings", 0)
        for event in found.get("events", []):
            merged_events[event.get("id")] = event
        for host in found.get("hosts", []):
            if host not in seen_hosts:
                seen_hosts.add(host)
                merged_hosts.append(host)
        # Deduplicate related records across searches by identity key.
        for case in found.get("cases", []):
            if not any(c.get("case_id") == case.get("case_id") for c in cases):
                cases.append(case)
        for inv in found.get("investigations", []):
            if not any(i.get("id") == inv.get("id") for i in investigations):
                investigations.append(inv)

    events = sorted(merged_events.values(), key=lambda e: e.get("time") or "", reverse=True)[:_MAX_INTERNAL_EVENTS]

    return {
        "window_days": _INTERNAL_WINDOW_DAYS,
        "searched": True,
        "total_sightings": total,
        "events": events,
        "hosts": merged_hosts,
        "cases": cases,
        "investigations": investigations,
        "note": (
            "Matches are substring occurrences in local telemetry within the "
            "last %d days and may include partial matches."
            % _INTERNAL_WINDOW_DAYS
        ),
    }


class ThreatIntelligenceService:

    def lookup(self, indicator: str) -> dict:
        """Look up an indicator across CONFIGURED providers only.

        Returns a stable shape with the real (validated) indicator type,
        SOCRA-internal sightings and a per-provider status
        (ok / error / not_configured / not_applicable). Result + confidence
        are only present where the provider actually returned data.
        """
        indicator = (indicator or "").strip()
        classification = classify_indicator(indicator)
        ioc_type = classification["type"]
        valid = classification["valid"]

        provider_target = None
        if valid:
            provider_target = _provider_target(ioc_type, indicator)

        # Real internal intelligence from the local database.
        internal = _internal_intelligence(indicator, ioc_type)

        # All known providers are reported; unconfigured ones stay in a real
        # "Provider not configured" state so the UI never guesses.
        providers = {}
        for provider in _active_providers():
            entry = {"provider": provider.name}
            if not provider.configured:
                entry["status"] = STATUS_NOT_CONFIGURED
            elif not valid or provider_target is None:
                entry["status"] = STATUS_NOT_APPLICABLE
                entry["message"] = (
                    "This provider cannot enrich indicators of this type."
                )
            else:
                family, target, scope = provider_target
                if provider.name == "AbuseIPDB" and family != "ip":
                    entry["status"] = STATUS_NOT_APPLICABLE
                    entry["message"] = (
                        "AbuseIPDB only supports IP address lookups; the "
                        "enrichment target for this indicator is not an IP."
                    )
                else:
                    started = time.time()
                    try:
                        data = provider.lookup(target, family)
                        entry["status"] = STATUS_OK
                        entry["lookup_time"] = round(time.time() - started, 3)
                        entry["result"] = data.get("result")
                        entry["confidence"] = data.get("confidence")
                        entry["lookup_target"] = target
                        if scope:
                            entry["lookup_scope"] = scope
                    except Exception as exc:  # API failure -> real error state
                        logger.warning("[ThreatIntel] %s lookup failed: %s", provider.name, exc)
                        entry["status"] = STATUS_ERROR
                        entry["error"] = f"Provider lookup failed ({type(exc).__name__})."
            providers[provider.name.lower()] = entry

        # Always include the full known-provider set (not configured when the
        # API key is absent) so the response shape is stable for clients.
        for name in ("virustotal", "abuseipdb"):
            if name not in providers:
                providers[name] = {"provider": name.title(), "status": STATUS_NOT_CONFIGURED}

        return {
            "indicator": indicator,
            "type": ioc_type,
            "valid": valid,
            "detail": classification.get("detail", ""),
            # Real internal SOCRA intelligence (local sightings).
            "internal": internal,
            # Per-provider details for the UI.
            "providers": providers,
            # Backward-compatible summary fields the existing page reads.
            "virustotal": {
                "status": providers.get("virustotal", {}).get("status", STATUS_NOT_CONFIGURED),
                "malicious": (providers.get("virustotal", {}).get("result") or {}).get("malicious"),
            },
            "abuseipdb": {
                "status": providers.get("abuseipdb", {}).get("status", STATUS_NOT_CONFIGURED),
                "abuse_score": (providers.get("abuseipdb", {}).get("result") or {}).get("abuse_score"),
            },
            # Only real provider data may fill these - otherwise Unknown.
            "geoip": {"country": "Unknown", "city": "Unknown"},
            "whois": {"registrar": "Unknown", "created": "Unknown"},
        }


threat_intelligence_service = ThreatIntelligenceService()
