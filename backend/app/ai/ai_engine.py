from app.services.ollama_service import OllamaService


class AIEngine:

    def __init__(self):
        self.ollama = OllamaService()

    # ---------------------------------------------------------------
    # Availability
    # ---------------------------------------------------------------

    def health(self):
        """Clear service/model health status (never blocks long)."""
        return self.ollama.health()

    # ---------------------------------------------------------------
    # Real investigation context
    # ---------------------------------------------------------------

    @staticmethod
    def _ioc_lines(ioc):
        """Render real IOCs from the persisted envelope (top-level ioc)."""
        if not isinstance(ioc, dict):
            ioc = {}
        ips = ioc.get("ips") or []
        hashes = ioc.get("hashes") or []
        lines = []
        if ips:
            lines.append("IP Addresses: " + ", ".join(str(x) for x in ips))
        if hashes:
            lines.append("File Hashes: " + ", ".join(str(x) for x in hashes))
        return lines or ["None identified in the provided data."]

    # Cap on how many real related events are placed in the prompt. Every
    # event listed is REAL telemetry; the true total is always stated so the
    # model knows the sample size and can never infer "no other events".
    MAX_RELATED_EVENTS_IN_PROMPT = 15

    @staticmethod
    def _timeline_lines(related_events):
        """Real related-event timeline (chronological), oldest first."""
        entries = sorted(
            related_events or [],
            key=lambda x: str(x.get("time") or ""),
        )
        lines = []
        for entry in entries:
            lines.append(
                f"- {entry.get('time') or '?'} | event_id={entry.get('event_id') or '?'} "
                f"| process={entry.get('process') or '?'} | user={entry.get('user') or '?'} "
                f"| severity={entry.get('severity') or '?'} | detection={entry.get('detection') or '?'}"
            )
        return lines

    @staticmethod
    def _notes_lines(notes):
        if not notes:
            return ["None recorded yet."]
        return [f"- [{n.get('time')}] {n.get('note')}" for n in notes]

    # ---------------------------------------------------------------
    # Investigation
    # ---------------------------------------------------------------

    def investigate(self, event, investigation=None):
        """Analyze a real alert with its real investigation context.

        Args:
            event: the full persisted envelope {event, detection, ioc, metadata}.
            investigation: optional persisted investigation record (Task 5)
                whose notes / related events / process tree / status provide
                real context for the analysis.

        Returns:
            dict: {"success": True, "provider", "model", "analysis"} when
            available; otherwise {"success": False, "available": False,
            "error", "detail"} so the UI can show a useful error instead of
            loading forever.
        """
        # Never call Ollama without knowing it is reachable.
        health = self.health()
        if not health.get("available"):
            return {
                "success": False,
                "available": False,
                "provider": "Ollama",
                "error": health.get("detail") or health.get("error") or "Ollama is unavailable.",
                "detail": health.get("detail") or "Ollama is unavailable.",
            }

        ev = (event or {}).get("event", {}) or {}
        det = (event or {}).get("detection", {}) or {}
        mitre = det.get("mitre", {})
        if not isinstance(mitre, dict):
            mitre = {}
        # IOCs live at the TOP LEVEL of the persisted envelope; legacy
        # detection.ioc is only a fallback for very old rows.
        ioc = (event or {}).get("ioc") or det.get("ioc") or {}

        related = (investigation or {}).get("related_events") or []
        total_related = len(related)
        related = related[: self.MAX_RELATED_EVENTS_IN_PROMPT]
        notes = (investigation or {}).get("notes") or []
        process_tree = (investigation or {}).get("process_tree") or []

        prompt = self._build_prompt(
            event=event,
            ev=ev,
            det=det,
            mitre=mitre,
            ioc=ioc,
            related=related,
            notes=notes,
            process_tree=process_tree,
            investigation=investigation,
            total_related=total_related,
        )

        response = self.ollama.investigate(prompt)

        # Ollama returns a clearly-marked error banner (never telemetry)
        # when generation fails or times out — surface it as an error.
        if "# SOCRA AI Unavailable" in response or "Unable to contact Ollama" in response:
            return {
                "success": False,
                "available": False,
                "provider": "Ollama",
                "error": response,
                "detail": "Ollama could not complete the analysis (unavailable or timed out).",
            }

        return {
            "success": True,
            "available": True,
            "provider": "Ollama",
            "model": self.ollama.model,
            "analysis": response,
        }

    def _build_prompt(
        self,
        event,
        ev,
        det,
        mitre,
        ioc,
        related,
        notes,
        process_tree,
        investigation,
        total_related=0,
    ):
        """Structured prompt: OBSERVED FACTS (real data only) / ANALYSIS /
        RECOMMENDATIONS. The model is explicitly forbidden from inventing
        telemetry — everything it reasons about must come from this block."""
        event_id = ev.get("event_id", "Unknown")
        host = ev.get("host") or ev.get("computer") or "Unknown"
        user = ev.get("user") or "Unknown"
        process = ev.get("process_name") or ev.get("image") or "Unknown"
        command_line = ev.get("command_line") or ""
        parent_process = ev.get("parent_process") or ev.get("parent_image") or ""

        inv_lines = []
        if investigation:
            inv_lines.append(f"- Investigation ID: {investigation.get('id')}")
            inv_lines.append(f"- Status: {investigation.get('status')}")
            inv_lines.append(f"- Risk Score: {investigation.get('risk_score')}")
            inv_lines.append(f"- Confidence: {investigation.get('confidence')}")

        process_tree_lines = []
        if process_tree:
            def _flatten(nodes, depth=0):
                out = []
                for node in nodes or []:
                    name = node.get("name") or "?"
                    pid = node.get("process_id") or ""
                    note = node.get("note") or ""
                    out.append(
                        f"{'  ' * depth}- {name}" + (f" (pid={pid})" if pid else "") +
                        (f" [{note}]" if note else "")
                    )
                    out.extend(_flatten(node.get("children"), depth + 1))
                return out
            process_tree_lines = _flatten(process_tree)

        related_lines = self._timeline_lines(related)
        notes_lines = self._notes_lines(notes)
        ioc_lines = self._ioc_lines(ioc)

        return f"""
You are SOCRA AI, an Enterprise Tier-2 SOC Analyst.

Analyze the security alert below using ONLY the real data provided.
You must NEVER invent telemetry: if an event, process, host, user, IOC,
or timeline entry is not listed here, you must not claim it occurred.
When something is missing, say "not provided in the alert data".

==================================================
OBSERVED FACTS (real data — the only facts you may use)
==================================================

ALERT
- Host: {host}
- User: {user}
- Time: {ev.get('time', 'Unknown')}
- Event ID: {event_id}
- Process: {process}
- Parent Process: {parent_process or 'not provided'}
- Command Line: {command_line or 'not provided'}
- Severity: {det.get('severity', 'Unknown')}
- Detection Rule: {det.get('detection', 'Unknown')}
- Description: {det.get('description', 'not provided')}

MITRE ATT&CK (mapped by the detection engine)
- ID: {mitre.get('id', 'not mapped')}
- Technique: {mitre.get('technique', 'not provided')}
- Tactic: {mitre.get('tactic', 'not provided')}

INDICATORS OF COMPROMISE (extracted from the event)
{chr(10).join('- ' + line for line in ioc_lines)}

INVESTIGATION CONTEXT (persisted record)
{chr(10).join(inv_lines) if inv_lines else '- No persisted investigation record provided.'}

ANALYST NOTES
{chr(10).join(notes_lines)}

RELATED EVENTS ({total_related} found around the alert in real telemetry; listing the first {len(related)} chronologically)
{chr(10).join(related_lines) if related_lines else '- None found in the window.'}

PROCESS TREE (from real parser fields)
{chr(10).join(process_tree_lines) if process_tree_lines else '- Not available.'}

==================================================
ANALYSIS
==================================================

Provide a professional Tier-2 analysis based strictly on the facts above:

1. What happened and why it is (or is not) suspicious.
2. MITRE ATT&CK relevance and attack-chain context.
3. IOC analysis — analyze ONLY the IOCs listed above; if none exist, state "No Indicators of Compromise were identified in the provided data."
4. False-positive assessment.
5. Recommended next investigation steps (threat hunting queries, logs to review).

==================================================
RECOMMENDATIONS
==================================================

Numbered, actionable recommendations for containment and recovery.

==================================================
RESPONSE FORMAT
==================================================

Use EXACTLY these three sections:

# OBSERVED FACTS

Restate only the real facts from the prompt (alert, host, user, event ID,
process, severity, MITRE, IOCs, related-event count). Do not add anything.

# ANALYSIS

Your analysis, referencing only the facts above.

# RECOMMENDATIONS

Numbered actionable recommendations.

Keep the report concise, professional and suitable for enterprise SOC documentation.
""".strip()
