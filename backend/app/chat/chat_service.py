import asyncio

from app.ai.ai_engine import AIEngine
from app.storage.storage_manager import storage_manager


class ChatService:

    def __init__(self):

        self.ai = AIEngine()

    def build_context(self, max_events=5):
        """
        Build a concise context from recent live events.

        Args:
            max_events: Maximum number of events to include (default 5 for faster prompts)
        """
        events = storage_manager.get_events(source="live")
        latest = events[:max_events]

        context = []

        for event in latest:

            ev = event.get("event", {})
            det = event.get("detection", {})
            mitre = det.get("mitre", {})
            if isinstance(mitre, list):
                mitre_label = "; ".join(
                    f"{m.get('id', '')} - {m.get('technique', '')}"
                    for m in mitre
                    if isinstance(m, dict)
                ) or "not mapped"
            else:
                mitre_label = (
                    f"{mitre.get('id', '')} - {mitre.get('technique', '')}"
                    if isinstance(mitre, dict)
                    else "not mapped"
                )

            context.append(
                f"Host: {ev.get('host')} | Time: {ev.get('time')} | Event: {ev.get('event_id')} | "
                f"Process: {ev.get('process_name')} | Severity: {det.get('severity')} | "
                f"Detection: {det.get('detection')} | MITRE: {mitre_label}"
            )

        return "\n".join(context)

    SYSTEM_PROMPT = (
        "You are SOCRA AI, an Enterprise SOC Copilot.\n\n"
        "You help SOC Analysts investigate Windows security events.\n\n"
        "Your responsibilities:\n"
        "- Analyze Windows Event Logs\n"
        "- Explain Windows Event IDs\n"
        "- Map events to MITRE ATT&CK\n"
        "- Explain detections\n"
        "- Recommend investigation steps\n"
        "- Recommend containment actions\n"
        "- Explain Indicators of Compromise\n"
        "- Help analysts during incident response\n"
        "- Summarize security alerts\n"
        "- Use ONLY the provided environment when answering environment-specific questions.\n\n"
        "Rules:\n"
        "1. Never hallucinate Windows Event IDs or invent telemetry.\n"
        "2. Base every statement ONLY on the facts provided.\n"
        "3. When information is missing, say it is not provided.\n"
        "4. Always reference MITRE ATT&CK whenever applicable.\n"
        "5. Keep responses professional and structured.\n"
        "6. Give practical investigation steps.\n"
        "7. Remember the conversation context — refer back to previous questions and answers."
    )

    def ask(self, question, conversation_history=None):
        """Send a question to Ollama, optionally with conversation history.

        Args:
            question: the current user question.
            conversation_history: optional list of previous messages
                [{"role": "user", "content": ...}, {"role": "assistant", "content": ...}]
                from the current conversation. When provided, the AI will
                have full context of the ongoing discussion.
        """
        environment = self.build_context(max_events=5)

        # Build the system message with SOC environment context
        system_content = (
            f"{self.SYSTEM_PROMPT}\n\n"
            f"=========================\n"
            f"LIVE SOC ENVIRONMENT\n"
            f"=========================\n\n"
            f"{environment}"
        )

        # If we have conversation history, use multi-turn chat
        if conversation_history:
            messages = [{"role": "system", "content": system_content}]
            for msg in conversation_history:
                role = msg.get("role", "user")
                content = msg.get("content", "")
                if role in ("user", "assistant") and content:
                    messages.append({"role": role, "content": content})
            messages.append({"role": "user", "content": question})
            return self.ai.ollama.chat_with_history(messages)

        # No history — single-turn prompt (backward compatible)
        prompt = (
            f"{self.SYSTEM_PROMPT}\n\n"
            f"=========================\n"
            f"LIVE SOC ENVIRONMENT\n"
            f"=========================\n\n"
            f"{environment}\n\n"
            f"=========================\n"
            f"QUESTION\n"
            f"=========================\n\n"
            f"{question}\n\n"
            f"=========================\n"
            f"RESPONSE FORMAT\n"
            f"=========================\n\n"
            f"Summary\n\nTechnical Analysis\n\nMITRE ATT…\n\n"
            f"Risk Assessment\n\nRecommended Investigation\n\n"
            f"Recommended Response\n\nConclusion"
        )
        return self.ai.ollama.investigate(prompt)

    async def ask_stream(self, question, conversation_history=None):
        """Stream a response from Ollama for faster perceived latency.

        Args:
            question: the current user question.
            conversation_history: optional list of previous messages.

        Yields:
            str: partial text chunks as they arrive.
        """
        environment = self.build_context(max_events=5)

        system_content = (
            f"{self.SYSTEM_PROMPT}\n\n"
            f"=========================\n"
            f"LIVE SOC ENVIRONMENT\n"
            f"=========================\n\n"
            f"{environment}"
        )

        if conversation_history:
            messages = [{"role": "system", "content": system_content}]
            for msg in conversation_history:
                role = msg.get("role", "user")
                content = msg.get("content", "")
                if role in ("user", "assistant") and content:
                    messages.append({"role": role, "content": content})
            messages.append({"role": "user", "content": question})
            async for chunk in self.ai.ollama.chat_with_history_stream(messages):
                yield chunk
            return

        # No history — single-turn prompt
        prompt = (
            f"{self.SYSTEM_PROMPT}\n\n"
            f"=========================\n"
            f"LIVE SOC ENVIRONMENT\n"
            f"=========================\n\n"
            f"{environment}\n\n"
            f"=========================\n"
            f"QUESTION\n"
            f"=========================\n\n"
            f"{question}\n\n"
            f"=========================\n"
            f"RESPONSE FORMAT\n"
            f"=========================\n\n"
            f"Summary\n\nTechnical Analysis\n\nMITRE ATT…\n\n"
            f"Risk Assessment\n\nRecommended Investigation\n\n"
            f"Recommended Response\n\nConclusion"
        )
        # For single-turn without history, use non-streaming for simplicity
        result = self.ai.ollama.investigate(prompt)
        yield result