import time

import ollama

# Budget for a single LLM generation. Full analyses (num_predict below)
# can take minutes on CPU when the model is cold-loaded; anything beyond
# this hard cap is treated as a timeout so the API never hangs the analyst.
DEFAULT_TIMEOUT_SECONDS = 300

# How long to wait for the availability probe (service/model listing).
AVAILABILITY_TIMEOUT_SECONDS = 5


class OllamaService:

    def __init__(self, model="llama3:latest", host=None, timeout=DEFAULT_TIMEOUT_SECONDS):
        self.model = model
        self.host = host
        self.timeout = timeout

    def _client(self):
        """A client with a hard request timeout — a slow or silent Ollama can
        never make the AI investigation hang indefinitely."""
        kwargs = {"timeout": self.timeout}
        if self.host:
            kwargs["host"] = self.host
        return ollama.Client(**kwargs)

    # ---------------------------------------------------------------
    # Availability / health
    # ---------------------------------------------------------------

    def is_available(self):
        """True when the Ollama service is reachable. Never blocks long:
        the probe uses a short timeout and any exception means unavailable."""
        try:
            client = ollama.Client(
                timeout=AVAILABILITY_TIMEOUT_SECONDS,
                **({"host": self.host} if self.host else {}),
            )
            client.list()
            return True
        except Exception:
            return False

    def health(self):
        """Clear health status for the API: service reachable, configured
        model present, and current latency of the probe."""
        started = time.time()
        try:
            client = ollama.Client(
                timeout=AVAILABILITY_TIMEOUT_SECONDS,
                **({"host": self.host} if self.host else {}),
            )
            response = client.list()
            latency_ms = int((time.time() - started) * 1000)
            models = [m.model for m in (response.get("models") or [])]
            return {
                "success": True,
                "available": True,
                "provider": "Ollama",
                "host": self.host or "http://127.0.0.1:11434",
                "model": self.model,
                "model_installed": self.model in models,
                "models": models,
                "latency_ms": latency_ms,
                "detail": (
                    f"Ollama service is reachable"
                    f"{' and model ' + self.model + ' is installed' if self.model in models else ''}."
                ),
            }
        except Exception as e:
            return {
                "success": False,
                "available": False,
                "provider": "Ollama",
                "host": self.host or "http://127.0.0.1:11434",
                "model": self.model,
                "model_installed": False,
                "models": [],
                "error": str(e),
                "detail": (
                    "Ollama is unavailable. Start the Ollama service "
                    "(typically `ollama serve` on 127.0.0.1:11434) and pull "
                    f"the model: `ollama pull {self.model}`."
                ),
            }

    # ---------------------------------------------------------------
    # Generation
    # ---------------------------------------------------------------

    def investigate(self, prompt):
        """Run a generation against Ollama.

        Returns:
            str: the model's text output, or a clearly-marked error banner
                when the service/model is unavailable or times out — callers
                must treat the banner as an error, never as telemetry.
        """
        try:
            response = self._client().chat(
                model=self.model,
                messages=[
                    {
                        "role": "system",
                        "content": (
                            "You are SOCRA AI, an Enterprise Tier-2 SOC Analyst.\n\n"
                            "Rules:\n"
                            "1. Never hallucinate Windows Event IDs or invent telemetry.\n"
                            "2. Base every statement ONLY on the facts provided in the prompt.\n"
                            "3. When information is missing, say it is not provided — do not guess.\n"
                            "4. Always reference MITRE ATT&CK whenever applicable.\n"
                            "5. Keep responses professional and structured with headings.\n"
                            "6. Give practical investigation steps."
                        ),
                    },
                    {
                        "role": "user",
                        "content": prompt,
                    },
                ],
                options={
                    "temperature": 0.2,
                    "top_p": 0.9,
                    "num_predict": 900,
                },
            )
            return response["message"]["content"]

        except Exception as e:
            return self._error_banner(str(e))

    def chat_with_history(self, messages):
        """Run a multi-turn generation against Ollama with full conversation history.

        Args:
            messages: list of dicts with 'role' and 'content' keys.
                      Must start with a system message, followed by
                      alternating user/assistant messages, ending with
                      the current user question.

        Returns:
            str: the model's text output, or a clearly-marked error banner.
        """
        try:
            response = self._client().chat(
                model=self.model,
                messages=messages,
                options={
                    "temperature": 0.2,
                    "top_p": 0.9,
                    "num_predict": 900,
                },
            )
            return response["message"]["content"]

        except Exception as e:
            return self._error_banner(str(e))

    @staticmethod
    def _error_banner(reason):
        return (
            f"# SOCRA AI Unavailable\n\n"
            f"Unable to contact Ollama within {DEFAULT_TIMEOUT_SECONDS}s.\n\n"
            f"Reason:\n\n{reason}\n\n"
            "Please verify:\n\n"
            "• Ollama is running (`ollama serve`)\n"
            "• The model is installed (`ollama pull llama3:latest`)\n"
            "• The service is responding"
        )
