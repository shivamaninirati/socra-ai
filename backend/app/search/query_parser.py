import re
import shlex
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional


class EnterpriseQueryParser:
    """
    SOCRA Enterprise Query Language (SEQL)

    Full grammar:

    # Field lookups (supports both : and = syntax)
    host:DESKTOP-ABC
    host=DESKTOP-ABC
    user:Administrator
    severity:critical
    eventid:4625
    process:powershell.exe
    mitre:T1059
    ioc:1.1.1.1
    status:open
    provider:Sysmon
    channel:Security

    # Time keywords
    today
    last1h
    last24h
    last7d
    last30d
    yesterday

    # Boolean operators (case-insensitive)
    host:MANI severity:high eventid:4688        <- implicit AND
    host:MANI AND severity:high                  <- explicit AND
    critical OR high                             <- OR
    NOT eventid:4625                             <- NOT
    process:powershell.exe AND mitre:T1059       <- mixed

    # Parenthesized groups
    (severity:critical OR severity:high) AND host:MANI

    # Quoted phrases
    process:"powershell.exe"
    user:"SYSTEM"
    "failed logon"

    # Free text keywords
    powershell
    mimikatz
    """

    VALID_KEYS = {
        "host", "user", "severity", "eventid", "event_id",
        "process", "pid", "process_id", "mitre", "ioc", "status",
        "provider", "channel", "source", "index", "earliest", "latest",
        "computer", "domain"
    }

    TIME_KEYWORDS = {
        "today": ("earliest", "today"),
        "yesterday": ("earliest", "yesterday"),
        "last1h": ("earliest", "-1h"),
        "last4h": ("earliest", "-4h"),
        "last6h": ("earliest", "-6h"),
        "last12h": ("earliest", "-12h"),
        "last24h": ("earliest", "-24h"),
        "last7d": ("earliest", "-7d"),
        "last30d": ("earliest", "-30d"),
    }

    SEVERITY_MAP = {
        "critical": "Critical", "high": "High",
        "medium": "Medium", "low": "Low",
        "informational": "Informational", "info": "Informational",
    }

    def parse(self, query: str) -> Dict[str, Any]:
        if not query or not query.strip():
            return {
                "ast": {"type": "all"},
                "tokens": {},
                "keywords": [],
                "time_range": None,
                "has_boolean": False,
                "raw": ""
            }
        query = query.strip()
        has_boolean = self._has_boolean_operators(query)
        if has_boolean:
            ast = self._parse_expression(query)
            tokens = self._extract_simple_tokens(query)
            keywords = self._extract_keywords_from_ast(ast)
        else:
            tokens, keywords = self._parse_simple(query)
            ast = self._build_simple_ast(tokens, keywords)
        time_range = self._resolve_time_keywords(query, tokens)
        return {
            "ast": ast, "tokens": tokens, "keywords": keywords,
            "time_range": time_range, "has_boolean": has_boolean, "raw": query
        }

    def _has_boolean_operators(self, query: str) -> bool:
        return bool(re.search(r'\b(AND|OR|NOT)\b', query, re.IGNORECASE))

    def _parse_simple(self, query: str) -> tuple:
        tokens = {}
        keywords = []
        field_pattern = r'(\w+):(?:"([^"]*)"|\[([^\]]*)\]|(\S+))'
        cleaned = query
        for match in re.finditer(field_pattern, query):
            key = match.group(1).lower().strip()
            value = (match.group(2) or match.group(3) or match.group(4) or "").strip()
            if key in self.VALID_KEYS or key.startswith("_"):
                if key in ("severity",):
                    value = self.SEVERITY_MAP.get(value.lower(), value)
                tokens[key] = value
                cleaned = cleaned.replace(match.group(0), "", 1)
        eq_pattern = r'(\w+)=(?:"([^"]*)"|\[([^\]]*)\]|(\S+))'
        for match in re.finditer(eq_pattern, query):
            key = match.group(1).lower().strip()
            value = (match.group(2) or match.group(3) or match.group(4) or "").strip()
            if key in self.VALID_KEYS or key.startswith("_"):
                if key in ("severity",):
                    value = self.SEVERITY_MAP.get(value.lower(), value)
                tokens[key] = value
                cleaned = cleaned.replace(match.group(0), "", 1)
        remaining = cleaned.strip()
        if remaining:
            try:
                parts = shlex.split(remaining)
            except ValueError:
                # Fallback: split on whitespace for malformed input (unmatched quotes, etc.)
                parts = remaining.split()
            for part in parts:
                part = part.strip()
                if not part:
                    continue
                if part.lower() in self.TIME_KEYWORDS:
                    continue
                if part.upper() in ("AND", "OR", "NOT"):
                    continue
                keywords.append(part)
        return tokens, keywords

    def _extract_simple_tokens(self, query: str) -> Dict[str, str]:
        tokens = {}
        field_pattern = r'(\w+):(?:"([^"]*)"|\[([^\]]*)\]|(\S+))'
        for match in re.finditer(field_pattern, query):
            key = match.group(1).lower().strip()
            value = (match.group(2) or match.group(3) or match.group(4) or "").strip()
            if key in self.VALID_KEYS or key.startswith("_"):
                if key in ("severity",):
                    value = self.SEVERITY_MAP.get(value.lower(), value)
                tokens[key] = value
        eq_pattern = r'(\w+)=(?:"([^"]*)"|\[([^\]]*)\]|(\S+))'
        for match in re.finditer(eq_pattern, query):
            key = match.group(1).lower().strip()
            value = (match.group(2) or match.group(3) or match.group(4) or "").strip()
            if key in self.VALID_KEYS or key.startswith("_"):
                if key in ("severity",):
                    value = self.SEVERITY_MAP.get(value.lower(), value)
                tokens[key] = value
        return tokens

    def _tokenize(self, query: str) -> List[str]:
        tokens = []
        i = 0
        while i < len(query):
            if query[i] in (' ', '\t'):
                i += 1
                continue
            if query[i] in ('(', ')'):
                tokens.append(query[i])
                i += 1
                continue
            if query[i] in ('"', "'"):
                quote = query[i]
                j = i + 1
                while j < len(query) and query[j] != quote:
                    if query[j] == '\\':
                        j += 1
                    j += 1
                j += 1 if j < len(query) else 0
                tokens.append(query[i:j])
                i = j
                continue
            j = i
            while j < len(query) and query[j] not in (' ', '\t', '(', ')'):
                j += 1
            token = query[i:j]
            if token:
                tokens.append(token)
            i = j
        return tokens

    def _parse_expression(self, query: str, depth: int = 0) -> Dict[str, Any]:
        if depth > 20:
            return {"type": "all"}
        tokens = self._tokenize(query)
        processed = self._process_parentheses(tokens, depth)
        processed = self._process_not(processed)
        processed = self._process_binary_op(processed, "AND", depth)
        processed = self._process_binary_op(processed, "OR", depth)
        if len(processed) == 1:
            node = processed[0]
            if isinstance(node, dict):
                return node
            return self._make_condition_node(str(node))
        if len(processed) == 0:
            return {"type": "all"}
        return {"type": "all"}

    def _process_parentheses(self, tokens: List[str], depth: int) -> List[Any]:
        result = []
        i = 0
        while i < len(tokens):
            token = tokens[i]
            if token == '(':
                j = i + 1
                paren_depth = 1
                while j < len(tokens) and paren_depth > 0:
                    if tokens[j] == '(':
                        paren_depth += 1
                    elif tokens[j] == ')':
                        paren_depth -= 1
                    j += 1
                inner_tokens = tokens[i+1:j-1]
                inner_query = ' '.join(inner_tokens)
                sub_ast = self._parse_expression(inner_query, depth + 1)
                result.append(sub_ast)
                i = j
            else:
                result.append(token)
                i += 1
        return result

    def _process_not(self, tokens: List[Any]) -> List[Any]:
        result = []
        i = 0
        while i < len(tokens):
            token = tokens[i]
            if isinstance(token, str) and token.upper() == "NOT":
                if i + 1 < len(tokens):
                    next_token = tokens[i + 1]
                    if isinstance(next_token, dict):
                        result.append({"type": "not", "node": next_token})
                    else:
                        result.append({
                            "type": "not",
                            "node": self._make_condition_node(str(next_token))
                        })
                    i += 2
                else:
                    i += 1
            else:
                result.append(token)
                i += 1
        return result

    def _process_binary_op(self, tokens: List[Any], op: str, depth: int) -> List[Any]:
        result = []
        i = 0
        while i < len(tokens):
            token = tokens[i]
            if isinstance(token, str) and token.upper() == op:
                left = result.pop() if result else {"type": "all"}
                right = None
                if i + 1 < len(tokens):
                    next_token = tokens[i + 1]
                    if isinstance(next_token, dict):
                        right = next_token
                    else:
                        right = self._make_condition_node(str(next_token))
                    i += 1
                if right is None:
                    result.append(left)
                else:
                    result.append({"type": op.lower(), "left": left, "right": right})
                i += 1
            else:
                if isinstance(token, dict):
                    result.append(token)
                else:
                    result.append(self._make_condition_node(str(token)))
                i += 1
        return result

    def _make_condition_node(self, token: str) -> Dict[str, Any]:
        field_match = re.match(r'^(\w+)[:=](.+)$', token)
        if field_match:
            key = field_match.group(1).lower().strip()
            value = field_match.group(2).strip()
            if len(value) >= 2 and value[0] == value[-1] and value[0] in ('"', "'"):
                value = value[1:-1]
            if key in self.VALID_KEYS:
                if key in ("severity",):
                    value = self.SEVERITY_MAP.get(value.lower(), value)
                # Use contains matching for process and user fields (backward compat)
                operator = "contains" if key in ("process", "user") else "eq"
                return {"type": "condition", "field": key, "value": value, "operator": operator}
        if token.lower() in self.TIME_KEYWORDS:
            field, val = self.TIME_KEYWORDS[token.lower()]
            return {"type": "condition", "field": field, "value": val, "operator": "eq"}
        if len(token) >= 2 and token[0] == token[-1] and token[0] in ('"', "'"):
            token = token[1:-1]
        return {"type": "condition", "field": "_keyword", "value": token, "operator": "contains"}

    def _build_simple_ast(self, tokens: Dict[str, str], keywords: List[str]) -> Dict[str, Any]:
        conditions = []
        for key, value in tokens.items():
            operator = "contains" if key in ("process", "user") else "eq"
            conditions.append({"type": "condition", "field": key, "value": value, "operator": operator})
        for kw in keywords:
            conditions.append({"type": "condition", "field": "_keyword", "value": kw, "operator": "contains"})
        if not conditions:
            return {"type": "all"}
        if len(conditions) == 1:
            return conditions[0]
        node = {"type": "and", "left": conditions[0], "right": conditions[1]}
        for cond in conditions[2:]:
            node = {"type": "and", "left": node, "right": cond}
        return node

    def _extract_keywords_from_ast(self, ast: Dict[str, Any]) -> List[str]:
        keywords = []
        def walk(node):
            if not isinstance(node, dict):
                return
            if node.get("type") == "condition" and node.get("field") == "_keyword":
                keywords.append(node["value"])
            for key in ("left", "right", "node"):
                if key in node:
                    walk(node[key])
        walk(ast)
        return keywords

    def _resolve_time_keywords(self, query: str, tokens: Dict[str, str]) -> Optional[str]:
        if "earliest" in tokens:
            return tokens["earliest"]
        query_lower = query.lower()
        for keyword, (field, value) in self.TIME_KEYWORDS.items():
            if keyword in query_lower.split():
                return value
        return None

    def parse_time(self, value: Optional[str]) -> Optional[datetime]:
        if value is None:
            return None
        if value == "now":
            return datetime.now()
        if value == "today":
            return datetime.now().replace(hour=0, minute=0, second=0, microsecond=0)
        if value == "yesterday":
            return (datetime.now() - timedelta(days=1)).replace(hour=0, minute=0, second=0, microsecond=0)
        match = re.match(r'^(-)?(\d+)([mhd])$', value)
        if not match:
            return None
        is_negative = match.group(1) == "-"
        amount = int(match.group(2))
        unit = match.group(3)
        now = datetime.now()
        if is_negative:
            if unit == "m": return now - timedelta(minutes=amount)
            if unit == "h": return now - timedelta(hours=amount)
            if unit == "d": return now - timedelta(days=amount)
        else:
            if unit == "m": return now + timedelta(minutes=amount)
            if unit == "h": return now + timedelta(hours=amount)
            if unit == "d": return now + timedelta(days=amount)
        return None


query_parser = EnterpriseQueryParser()