import hashlib
import json

from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

from app.search.query_parser import query_parser
from app.storage.sqlite_storage import sqlite_storage
from app.storage.storage_manager import storage_manager


class SearchEngine:

    def search(
        self,
        query: str = "",
        source: str = "live",
        limit: int = 100000
    ):
        """Search matching records without loading the full dataset into memory.

        - history: the SEQL AST is translated to a SQLite WHERE clause and only
          matching rows are read from the database (SQL pushdown).
        - live: the bounded in-memory live store is scanned with the in-memory
          evaluator (it is small and holds the freshest events).
        - all: both sources, deduplicated and merged newest-first.
        """
        parsed = query_parser.parse(query)
        ast = parsed["ast"]
        time_range = parsed["time_range"]

        if source == "history":
            return self._search_history_sql(ast, time_range, limit)
        if source == "live":
            return self._search_live_memory(ast, time_range, limit)

        history = self._search_history_sql(ast, time_range, limit)
        live = self._search_live_memory(ast, time_range, limit)
        return self._merge_all(history, live, limit)

    def search_with_count(
        self,
        query: str = "",
        source: str = "all",
        limit: int = 1000,
    ):
        """Like search(), but also returns the true match count.

        The count comes from SQLite (COUNT over the WHERE clause) while the
        returned rows are bounded by `limit`, so paginated callers get a
        correct total without materializing the whole match set.
        """
        parsed = query_parser.parse(query)
        ast = parsed["ast"]
        time_range = parsed["time_range"]

        if source == "history":
            where, params = self._history_where(ast, time_range)
            result = sqlite_storage.search_events(where, params, limit=limit)
            return result["results"], result["total"]
        if source == "live":
            results = self._search_live_memory(ast, time_range, limit)
            return results, len(results)

        where, params = self._history_where(ast, time_range)
        result = sqlite_storage.search_events(where, params, limit=limit)
        live = self._search_live_memory(ast, time_range, limit)
        merged = self._merge_all(result["results"], live, limit)
        # Live events are also counted in the history store until persisted,
        # so the live overlap is negligible; keep the count approximate.
        return merged, result["total"] + len(live)

    def count_with_filters(self, query: str, filters: dict) -> int:
        """True SQL match count for a keyword query combined with HTTP-style
        field filters (severity / host / mitre / event id / process / PID /
        user / status / time window).

        Used by /logs/windows PATH 1 so the reported total reflects BOTH the
        keyword match AND the field filters — the in-memory filter pass only
        sees a bounded fetch window, so its length is never a reliable total.
        Filter semantics mirror _apply_filters_in_memory in routes/logs.py.
        """
        parsed = query_parser.parse(query)
        where, params = self._history_where(parsed["ast"], parsed["time_range"])
        extra, extra_params = self._field_filters_sql(filters or {})
        if extra:
            where = f"({where}) AND ({extra})"
            params = params + extra_params
        return sqlite_storage.search_events(where, params, limit=1)["total"]

    def _field_filters_sql(self, filters: Dict[str, Any]) -> Tuple[str, List[str]]:
        """Translate HTTP-style field filters into a SQLite WHERE fragment.

        Exact-match semantics (same as the in-memory filter pass): host, event
        id, severity, MITRE, PID and process are equality; status:New covers
        NULL rows (the implicit default); the time window is event_time >=
        cutoff.
        """
        clauses: List[str] = []
        params: List[str] = []

        def eq(col, value):
            clauses.append(f"{col} = ?")
            params.append(value)

        def like_json(expr, value):
            like = self._escape_like(value)
            clauses.append(f"{expr} LIKE '%' || ? || '%' ESCAPE '\\'")
            params.append(like)

        severity = filters.get("severity")
        if severity and severity != "All":
            eq("severity", severity)
        host = filters.get("host")
        if host and host != "All":
            eq("host", host)
        mitre = filters.get("mitre")
        if mitre and mitre != "All":
            if str(mitre).lower() == "unmapped":
                clauses.append("(mitre IS NULL OR mitre IN ('N/A', 'Unknown', 'Unmapped', 'None', 'null'))")
            else:
                eq("mitre", mitre)
        event_id = filters.get("event_id")
        if event_id and event_id != "All":
            eq("event_id", event_id)
        process = filters.get("process")
        if process and process != "All":
            eq("process_name", process)
        process_id = filters.get("process_id")
        if process_id and process_id != "All":
            eq("process_id", process_id)
        user = filters.get("user")
        if user and user != "All":
            like_json("json_extract(raw_json, '$.event.user')", user)
        status = filters.get("status")
        if status and status != "All":
            if status.lower() == "new":
                clauses.append("(status IS NULL OR status = 'New')")
            else:
                eq("status", status)
        time_from = filters.get("time_from")
        if time_from:
            clauses.append("event_time >= ?")
            params.append(time_from)

        return " AND ".join(clauses), params

    # --------------------------------------------------
    # SQL-pushdown path (history)
    # --------------------------------------------------

    def _history_where(
        self, ast: Dict[str, Any], time_range: Optional[str]
    ) -> Tuple[str, List[str]]:
        where, params = self._ast_to_sql(ast)
        if time_range:
            cutoff = query_parser.parse_time(time_range)
            if cutoff:
                where = f"({where}) AND event_time >= ?"
                params = params + [cutoff.isoformat()]
        return where, params

    def _search_history_sql(
        self, ast: Dict[str, Any], time_range: Optional[str], limit: int
    ) -> List[Dict[str, Any]]:
        where, params = self._history_where(ast, time_range)
        result = sqlite_storage.search_events(where, params, limit=limit)
        return result["results"]

    def _ast_to_sql(self, node: Any) -> Tuple[str, List[str]]:
        """Translate a SEQL AST node into a SQLite WHERE fragment + params.

        No-op conditions (unknown fields, status:new, earliest/latest) translate
        to 1=1, mirroring the in-memory evaluator's `return True`.
        """
        if not isinstance(node, dict):
            return "1=1", []
        node_type = node.get("type")
        if node_type == "all":
            return "1=1", []
        if node_type in ("and", "or"):
            left_sql, left_p = self._ast_to_sql(node.get("left", {}))
            right_sql, right_p = self._ast_to_sql(node.get("right", {}))
            op = "AND" if node_type == "and" else "OR"
            return f"({left_sql}) {op} ({right_sql})", left_p + right_p
        if node_type == "not":
            inner_sql, inner_p = self._ast_to_sql(node.get("node", {}))
            return f"NOT ({inner_sql})", inner_p
        if node_type == "condition":
            sql, params = self._condition_to_sql(node)
            if sql is None:
                return "1=1", []
            return sql, params
        return "1=1", []

    def _condition_to_sql(self, condition: Dict[str, Any]) -> Tuple[Optional[str], List[str]]:
        field = condition.get("field", "")
        value = str(condition.get("value", ""))

        # Time fields are applied at the query level; unknown fields are no-ops
        # in the in-memory evaluator, so keep them no-ops here too.
        if field in ("earliest", "latest"):
            return None, None

        # Real persisted alert status (Task 17). NULL rows are the implicit
        # "New" default, so status:new matches both NULL and 'New' — mirroring
        # the in-memory _status_match (which returns True for 'new').
        if field == "status" and value.lower() == "new":
            return "(status IS NULL OR status = 'New')", []
        if field == "status":
            return "status = ? COLLATE NOCASE", [value]

        # Free-text keywords and IOCs: substring over the full stored JSON.
        # SQLite LIKE is case-insensitive for ASCII (matching the in-memory
        # lower() comparison) and avoids a per-row LOWER() over the whole JSON.
        # % and _ are escaped so they stay literal, like the in-memory scan.
        if field in ("_keyword", "ioc"):
            like = self._escape_like(value)
            return f"raw_json LIKE '%' || ? || '%' ESCAPE '\\'", [like]

        # Exact-match columns: equality with COLLATE NOCASE so the dedicated
        # NOCASE indexes are used (millisecond lookups instead of full scans).
        eq_columns = {
            "host": "host", "computer": "host",
            "eventid": "event_id", "event_id": "event_id",
            "severity": "severity", "mitre": "mitre",
            "pid": "process_id", "process_id": "process_id",
            "provider": "provider", "channel": "channel",
            "source": "source", "index": "source",
        }
        if field in eq_columns:
            # 'mitre:Unmapped' matches every row whose stored MITRE value is an
            # unmapped marker (old rows store 'N/A', new rows 'Unmapped').
            if field in ("mitre",) and value.lower() == "unmapped":
                return "(mitre IS NULL OR mitre IN ('N/A', 'Unknown', 'Unmapped', 'None', 'null'))", []
            col = eq_columns[field]
            return f"{col} = ? COLLATE NOCASE", [value]

        # Contains match over the indexed process_name column.
        if field == "process":
            like = self._escape_like(value)
            return f"process_name LIKE '%' || ? || '%' ESCAPE '\\'", [like]

        if field == "user":
            like = self._escape_like(value)
            return (
                "json_extract(raw_json, '$.event.user') LIKE '%' || ? || '%' ESCAPE '\\'",
                [like],
            )

        if field == "domain":
            return "json_extract(raw_json, '$.event.domain') = ? COLLATE NOCASE", [value]

        return None, None

    @staticmethod
    def _escape_like(value: str) -> str:
        """Escape LIKE wildcards so search terms match literally."""
        return (
            value.replace("\\", "\\\\")
            .replace("%", "\\%")
            .replace("_", "\\_")
        )

    # --------------------------------------------------
    # In-memory path (bounded live store)
    # --------------------------------------------------

    def _search_live_memory(
        self, ast: Dict[str, Any], time_range: Optional[str], limit: int
    ) -> List[Dict[str, Any]]:
        events = storage_manager.get_live_events()
        results = [
            item for item in events
            if self._evaluate_ast(ast, item, {})
        ]
        if time_range:
            cutoff = query_parser.parse_time(time_range)
            if cutoff:
                results = [
                    r for r in results
                    if self._event_time_to_datetime(
                        r.get("event", {}).get("time", "")
                    ) and self._event_time_to_datetime(
                        r.get("event", {}).get("time", "")
                    ) >= cutoff
                ]
        return results[:limit]

    def _merge_all(
        self, history: List[Dict[str, Any]], live: List[Dict[str, Any]], limit: int
    ) -> List[Dict[str, Any]]:
        seen = set()
        merged = []
        for item in history + live:
            key = self._dedup_key(item)
            if key in seen:
                continue
            seen.add(key)
            merged.append(item)
        merged.sort(
            key=lambda x: x.get("event", {}).get("time", ""),
            reverse=True,
        )
        return merged[:limit]

    def _dedup_key(self, event: Dict[str, Any]):
        """Stable dedup key shared with the /logs/windows pipeline."""
        fp = event.get("metadata", {}).get("fingerprint")
        if fp:
            return ("fp", fp)
        ev = event.get("event", {}) or {}
        record = ev.get("record_number")
        if record not in (None, ""):
            return ("rec", str(ev.get("host", "")), str(ev.get("channel", "")), str(record), str(ev.get("time", "")))
        try:
            payload = json.dumps(ev, default=str, sort_keys=True)
            return ("hash", hashlib.sha256(payload.encode()).hexdigest())
        except Exception:
            return ("idx", id(event))

    def _evaluate_ast(self, node: Any, item: Dict, tokens: Dict) -> bool:
        if not isinstance(node, dict):
            return True
        node_type = node.get("type")
        if node_type == "all":
            return True
        if node_type == "and":
            return (
                self._evaluate_ast(node.get("left", {}), item, tokens) and
                self._evaluate_ast(node.get("right", {}), item, tokens)
            )
        if node_type == "or":
            return (
                self._evaluate_ast(node.get("left", {}), item, tokens) or
                self._evaluate_ast(node.get("right", {}), item, tokens)
            )
        if node_type == "not":
            return not self._evaluate_ast(node.get("node", {}), item, tokens)
        if node_type == "condition":
            return self._match_condition(node, item)
        return True

    def _match_condition(self, condition: Dict, item: Dict) -> bool:
        field = condition.get("field", "")
        value = condition.get("value", "")
        operator = condition.get("operator", "eq")
        event = item.get("event", {})
        detection = item.get("detection", {})

        if field == "_keyword":
            return self._keyword_match(value, item)
        if field == "ioc":
            return self._ioc_match(value, item)
        if field == "status":
            return self._status_match(value, item)

        field_map = {
            "host": ("event", "host"), "computer": ("event", "host"),
            "user": ("event", "user"),
            "eventid": ("event", "event_id"), "event_id": ("event", "event_id"),
            "process": ("event", "process_name"),
            "pid": ("event", "process_id"), "process_id": ("event", "process_id"),
            "provider": ("event", "provider"), "channel": ("event", "channel"),
            "source": ("event", "source"), "index": ("event", "source"),
            "severity": ("detection", "severity"),
            "mitre": ("detection", "mitre"),
            "domain": ("event", "domain"),
        }

        if field not in field_map:
            return True

        container_key, field_key = field_map[field]
        container = event if container_key == "event" else detection

        if container_key == "detection" and field == "mitre":
            # Canonical detection.mitre is a list of blocks; tolerate a single
            # dict (legacy rows) and a plain string. An event matches when ANY
            # of its mapped technique ids matches the filter.
            mitre_val = container.get("mitre", {})
            ids = []
            if isinstance(mitre_val, list):
                for block in mitre_val:
                    if isinstance(block, dict):
                        ids.append(str(block.get("id", "")))
                    elif block is not None:
                        ids.append(str(block))
            elif isinstance(mitre_val, dict):
                ids.append(str(mitre_val.get("id", "")))
            elif mitre_val is not None:
                ids.append(str(mitre_val))
            ids = [i for i in ids if i and i.lower() not in ("none", "unknown", "n/a")]
            return any(self._compare_value(i, value, operator) for i in ids)

        actual_value = str(container.get(field_key, "")).lower()
        expected_value = str(value).lower() if value else ""
        return self._compare_value(actual_value, expected_value, operator)

    def _compare_value(self, actual: str, expected: str, operator: str) -> bool:
        if operator == "eq":
            return actual == expected
        if operator == "contains":
            return expected in actual
        return True

    def _keyword_match(self, keyword: str, item: Dict) -> bool:
        keyword_lower = keyword.lower()
        event = item.get("event", {})
        for key, value in event.items():
            try:
                if keyword_lower in str(value).lower():
                    return True
            except Exception:
                pass
        detection = item.get("detection", {})
        for key, value in detection.items():
            try:
                if isinstance(value, dict):
                    if keyword_lower in str(value).lower():
                        return True
                elif keyword_lower in str(value).lower():
                    return True
            except Exception:
                pass
        metadata = item.get("metadata", {})
        for key, value in metadata.items():
            try:
                if keyword_lower in str(value).lower():
                    return True
            except Exception:
                pass
        return False

    def _ioc_match(self, ioc: str, item: Dict) -> bool:
        ioc_lower = ioc.lower()
        event = item.get("event", {})
        for key, value in event.items():
            try:
                if ioc_lower in str(value).lower():
                    return True
            except Exception:
                pass
        detection = item.get("detection", {})
        for key, value in detection.items():
            try:
                if ioc_lower in str(value).lower():
                    return True
            except Exception:
                pass
        return False

    def _status_match(self, status: str, item: Dict) -> bool:
        status_lower = status.lower()
        event = item.get("event", {})
        detection = item.get("detection", {})
        actual_status = str(event.get("status", "")).lower()
        if actual_status == status_lower:
            return True
        det_status = str(detection.get("status", "")).lower()
        if det_status == status_lower:
            return True
        if status_lower == "new":
            return True
        return False

    def _event_time_to_datetime(self, time_str: str) -> datetime:
        try:
            return datetime.fromisoformat(
                time_str.replace("Z", "").split(".")[0]
            )
        except Exception:
            return None


search_engine = SearchEngine()
