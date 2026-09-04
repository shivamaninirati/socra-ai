from fastapi import APIRouter, Depends, HTTPException, Query
from datetime import datetime, timedelta
from typing import Optional
from app.auth.dependencies import get_current_user
from app.search.search_engine import search_engine
from app.registry.windows_event_registry import enrich_log_payload
from app.services.filter_cache_service import filter_cache

router = APIRouter(
    prefix="/enterprise",
    tags=["Enterprise Operations"],
    dependencies=[Depends(get_current_user)],
)

# ==========================================================================
# ⚡ NODE 1: FORENSIC TIMELINE TRACER ENGINE
# ==========================================================================
@router.get("/timeline/trace")
def trace_forensic_timeline(host: str = Query(..., description="Target machine hostname")):
    """
    Traces structural process trees and user behavior chronologically 
    across the entire day to build an interactive incident kill chain.
    """
    live_set = search_engine.search(query=host, source="live", limit=100000)
    history_set = search_engine.search(query=host, source="history", limit=100000)
    
    seen = set()
    combined = []
    for item in live_set + history_set:
        fp = item.get("metadata", {}).get("fingerprint")
        if fp not in seen:
            seen.add(fp)
            combined.append(item)

    timeline_tree = []
    for item in combined:
        ev = item.get("event", {})
        det = item.get("detection", {})
        
        if str(ev.get("host", "")).lower() != host.lower():
            continue
            
        raw_id = str(ev.get("event_id", ""))
        enriched = enrich_log_payload(raw_id, det.get("severity", ""), ev.get("command_line", ""))
        
        timeline_tree.append({
            "timestamp": ev.get("time"),
            "event_id": raw_id,
            "user": ev.get("user", "SYSTEM"),
            "process": ev.get("process_name", "N/A"),
            "action": enriched["detection"],
            "severity": enriched["severity"],
            "mitre_id": enriched["mitre_id"],
            "details": {
                "command_line": ev.get("command_line", ""),
                "parent_process": ev.get("parent_process_name", "N/A")
            }
        })
        
    timeline_tree.sort(key=lambda x: x["timestamp"], reverse=True)
    return {"host": host, "total_steps": len(timeline_tree), "timeline": timeline_tree}


# ==========================================================================
# ⚡ NODE 2: INTEL COMPLIANCE REPORT GENERATOR
# ==========================================================================
@router.get("/reports/generate")
def generate_compliance_report(format: str = "json"):
    """
    Compiles full-spectrum SOC operational posture records into executive-ready data frames.
    """
    live_set = search_engine.search(query="", source="live", limit=100000)
    
    critical_incidents = []
    mitre_coverage = {}
    
    for item in live_set:
        ev = item.get("event", {})
        det = item.get("detection", {})
        enriched = enrich_log_payload(str(ev.get("event_id", "")), det.get("severity", ""))
        
        if enriched["severity"] in ["High", "Critical"]:
            critical_incidents.append({
                "time": ev.get("time"),
                "host": ev.get("host"),
                "alert": enriched["detection"],
                "mitre": enriched["mitre_id"]
            })
            
        m_id = enriched["mitre_id"]
        if m_id != "N/A":
            mitre_coverage[m_id] = mitre_coverage.get(m_id, 0) + 1

    return {
        "generated_at": datetime.utcnow().isoformat(),
        "scope": "NIST SP 800-53 / ISO 27001 Audit Context",
        "posture_summary": {
            "total_critical_tracked": len(critical_incidents),
            "unique_mitre_techniques_hit": len(mitre_coverage)
        },
        "mitre_matrix_distribution": mitre_coverage,
        "action_required_log": critical_incidents[:10]
    }


# ==========================================================================
# ⚡ SUGGESTIONS: LIVE AUTOCOMPLETE DATA ENDPOINT
# ==========================================================================
@router.get("/search/suggestions")
def get_search_suggestions(query: str = Query("", description="Partial text to filter suggestions")):
    """
    Returns live autocomplete suggestions from actual event data.
    Groups by: hosts, users, processes, event_ids, mitre_ids, ips, severities.

    Values are served from the incrementally-maintained filter cache instead of
    rescanning the database on every keystroke — the cache is bootstrapped once
    from persisted telemetry and then updated per-event by the collector.
    """
    filter_cache.ensure_bootstrapped()
    data = filter_cache.get_all()
    q = query.lower().strip()

    def pick(entries, cap=20):
        values = [str(e["value"]) for e in entries]
        if q:
            values = [v for v in values if q in v.lower()]
        return sorted(values, key=lambda x: x.lower())[:cap]

    # Alert status suggestions come from the persisted triage lifecycle (the
    # same source the Alerts status dropdown uses), since the telemetry cache
    # only ever observed "New" rows.
    statuses = list(data.get("statuses", []))
    try:
        from app.storage.sqlite_storage import sqlite_storage
        from app.routes.alerts import ALERT_STATUSES
        status_counts = sqlite_storage.get_alert_status_counts()
        statuses = [
            {"value": name, "count": status_counts.get(name, 0)}
            for name in ALERT_STATUSES
        ]
    except Exception:
        pass

    return {
        "hosts": pick(data.get("hosts", [])),
        "users": pick(data.get("users", [])),
        "processes": pick(data.get("processes", [])),
        "event_ids": pick(data.get("event_ids", [])),
        "mitre_ids": pick(data.get("mitre_ids", [])),
        "ips": pick(data.get("ips", [])),
        "pids": pick(data.get("pids", [])),
        "statuses": pick(statuses),
        "severities": pick(data.get("severities", []), cap=50),
    }


# ==========================================================================
# ⚡ NODE 3: THREAT HUNTING MATRIX SIGNATURE MATRIX
# ==========================================================================
@router.get("/hunting/detections")
def hunt_threat_signatures():
    """
    Scans internal enterprise telemetry memory pools against high-signal adversarial weaponization criteria.
    """
    all_logs = search_engine.search(query="", source="live", limit=100000)
    
    hunts = {
        "credential_dumping": [],
        "powershell_bypass": [],
        "persistence_mechanisms": []
    }
    
    for item in all_logs:
        ev = item.get("event", {})
        cmd = str(ev.get("command_line", "")).lower()
        eid = str(ev.get("event_id", ""))
        
        if "mimikatz" in cmd or "lsass" in cmd or "sekurlsa" in cmd:
            hunts["credential_dumping"].append(item)
        elif "powershell" in cmd and ("-enc" in cmd or "bypass" in cmd or "nop" in cmd):
            hunts["powershell_bypass"].append(item)
        elif eid in ["4697", "4698"] or "schtasks" in cmd:
            hunts["persistence_mechanisms"].append(item)
            
    return {
        "status": "Scan Complete",
        "matches": {k: len(v) for k, v in hunts.items()},
        "results": hunts
    }