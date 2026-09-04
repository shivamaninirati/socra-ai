"""Enterprise SIEM Search — API routes.

Provides:
  GET  /search                — Categorized search across all data sources
  GET  /search/suggestions    — Autocomplete suggestions from real data
  GET  /search/history        — User's recent searches
  POST /search/history        — Save a search to history
  DELETE /search/history/{id} — Delete a search history entry
  DELETE /search/history      — Clear all search history
"""

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel
from typing import Optional

from app.auth.dependencies import get_current_user
from app.core.logger import get_module_logger

logger = get_module_logger("routes.search")

# Maximum length for an autocomplete suggestion value
_MAX_SUGGESTION_LEN = 150


def _is_clean_suggestion(value: str) -> bool:
    """Return True if a value is clean enough for autocomplete suggestions.

    Rejects raw XML payloads, event messages, overly long strings,
    and any content that looks like raw telemetry rather than
    structured metadata.
    """
    if not value or not isinstance(value, str):
        return False
    if len(value) > _MAX_SUGGESTION_LEN:
        return False
    # Reject XML tags / angle brackets
    if '<' in value or '>' in value:
        return False
    # Reject multi-line content
    if '\n' in value or '\r' in value:
        return False
    return True

router = APIRouter(
    prefix="/search",
    tags=["Enterprise Search"],
    dependencies=[Depends(get_current_user)],
)


# ──────────────────────────────────────────────────────────────────────
# Categorized search
# ──────────────────────────────────────────────────────────────────────

@router.get("")
def enterprise_search(
    q: str = Query("", description="SEQL query or free-text search"),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    user: dict = Depends(get_current_user),
):
    """Search across events, alerts, hosts, processes, MITRE, cases.

    Returns categorized result counts and paginated event results.
    """
    import time
    start_total = time.time()
    user_id = user.get("user_id") or user.get("sub")
    logger.info(f"Search request started - query: '{q}', page: {page}, page_size: {page_size}, user: {user_id}")
    
    if not q.strip():
        logger.info(f"Empty query, returning empty results - total time: {(time.time() - start_total)*1000:.2f}ms")
        return {
            "query": q,
            "total": 0,
            "events": {"total": 0, "results": []},
            "alerts": {"total": 0, "results": []},
            "hosts": [],
            "processes": [],
            "users": [],
            "event_ids": [],
            "mitre": [],
            "cases": {"total": 0, "results": []},
        }

    from app.storage.sqlite_storage import sqlite_storage

    try:
        result = sqlite_storage.search_all_categorized(
            query=q, user_id=user_id, page=page, page_size=page_size
        )
        total_time = (time.time() - start_total)*1000
        logger.info(f"Search request completed successfully - total time: {total_time:.2f}ms, total results: {result['total']}")
        return {
            "query": q,
            "total": result["total"],
            "events": result["events"],
            "alerts": result["alerts"],
            "hosts": result["hosts"],
            "processes": result["processes"],
            "users": result["users"],
            "event_ids": result["event_ids"],
            "mitre": result["mitre"],
            "cases": result["cases"],
        }
    except Exception as e:
        total_time = (time.time() - start_total)*1000
        logger.error(f"Search failed after {total_time:.2f}ms: %s", e, exc_info=True)
        return {
            "query": q,
            "total": 0,
            "events": {"total": 0, "results": []},
            "alerts": {"total": 0, "results": []},
            "hosts": [],
            "processes": [],
            "users": [],
            "event_ids": [],
            "mitre": [],
            "cases": {"total": 0, "results": []},
            "error": "Search temporarily unavailable.",
        }


# ──────────────────────────────────────────────────────────────────────
# Autocomplete suggestions
# ──────────────────────────────────────────────────────────────────────

@router.get("/suggestions")
def get_search_suggestions(
    q: str = Query("", description="Partial text to filter suggestions"),
    user: dict = Depends(get_current_user),
):
    """Return autocomplete suggestions from real backend data.

    Grouped by: hosts, users, processes, event_ids, mitre_ids, ips,
    severities, and the user's own search history.
    """
    from app.services.filter_cache_service import filter_cache
    from app.storage.sqlite_storage import sqlite_storage

    filter_cache.ensure_bootstrapped()
    data = filter_cache.get_all()
    ql = q.lower().strip()

    # Strip any trailing field prefix (e.g. "host:M" → "M") so the value
    # filter only matches actual data, not the field name itself.
    value_filter = ql
    if ':' in ql:
        value_filter = ql.split(':', 1)[1]

    def pick(entries, cap=20):
        values = [str(e["value"]) for e in entries]
        if value_filter:
            values = [v for v in values if value_filter in v.lower()]
        # Final safety: reject anything that still looks like raw payload
        values = [v for v in values if _is_clean_suggestion(v)]
        return sorted(values, key=lambda x: x.lower())[:cap]

    # User's own search history
    history = []
    try:
        user_id = user.get("user_id") or user.get("sub")
        if user_id:
            history_items = sqlite_storage.get_search_history(user_id, limit=10)
            history = [item["query"] for item in history_items]
            if ql:
                history = [h for h in history if ql in h.lower()]
    except Exception:
        pass

    # Alert statuses
    statuses = list(data.get("statuses", []))
    try:
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
        "history": history,
    }


# ──────────────────────────────────────────────────────────────────────
# Search history (user-isolated)
# ──────────────────────────────────────────────────────────────────────

@router.get("/history")
def get_search_history(user: dict = Depends(get_current_user)):
    """Return the authenticated user's recent searches."""
    from app.storage.sqlite_storage import sqlite_storage

    user_id = user.get("user_id") or user.get("sub")
    if not user_id:
        return {"history": []}

    try:
        history = sqlite_storage.get_search_history(user_id, limit=30)
        return {"history": history}
    except Exception as e:
        logger.error("Failed to load search history: %s", e)
        return {"history": []}


class SaveSearchRequest(BaseModel):
    query: str


@router.post("/history")
def save_search(request: SaveSearchRequest, user: dict = Depends(get_current_user)):
    """Save a search query to the user's history."""
    from app.storage.sqlite_storage import sqlite_storage

    user_id = user.get("user_id") or user.get("sub")
    if not user_id:
        return {"success": False, "error": "Authentication required"}

    query = (request.query or "").strip()
    if not query:
        return {"success": False, "error": "Empty query"}

    try:
        sqlite_storage.add_search_history(user_id, query)
        return {"success": True}
    except Exception as e:
        logger.error("Failed to save search: %s", e)
        return {"success": False, "error": "Failed to save search"}


@router.delete("/history/{history_id}")
def delete_search_history_item(
    history_id: str, user: dict = Depends(get_current_user)
):
    """Delete a single search history entry."""
    from app.storage.sqlite_storage import sqlite_storage

    user_id = user.get("user_id") or user.get("sub")
    if not user_id:
        return {"success": False, "error": "Authentication required"}

    try:
        deleted = sqlite_storage.delete_search_history_item(user_id, history_id)
        return {"success": deleted}
    except Exception as e:
        logger.error("Failed to delete search history: %s", e)
        return {"success": False, "error": "Failed to delete"}


@router.delete("/history")
def clear_search_history(user: dict = Depends(get_current_user)):
    """Clear all search history for the authenticated user."""
    from app.storage.sqlite_storage import sqlite_storage

    user_id = user.get("user_id") or user.get("sub")
    if not user_id:
        return {"success": False, "error": "Authentication required"}

    try:
        sqlite_storage.clear_search_history(user_id)
        return {"success": True}
    except Exception as e:
        logger.error("Failed to clear search history: %s", e)
        return {"success": False, "error": "Failed to clear history"}