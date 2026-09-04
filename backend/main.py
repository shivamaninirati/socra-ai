from fastapi import Depends, FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request as StarletteRequest
from starlette.responses import Response as StarletteResponse
from fastapi.openapi.docs import get_swagger_ui_html
from fastapi.openapi.utils import get_openapi

import asyncio
import base64
import hashlib
import re
from contextlib import asynccontextmanager
from pathlib import Path

from app.auth.dependencies import get_current_user, require_admin

from app.core.exceptions import (
    SocraError,
    socra_exception_handler,
    global_exception_handler,
    not_found_handler,
)

from app.services.splunk_service import SplunkService
from app.timeline.timeline_engine import TimelineEngine
from app.reports.report_generator import ReportGenerator
from app.ai.ai_engine import AIEngine

from app.collector.collector_service import collector
from app.collector.single_instance import external_collector_running
from app.services.live_forwarder import live_forwarder_loop

from app.routes.logs import router as logs_router
from app.routes.timeline import router as timeline_router
from app.routes.reports import router as reports_router
from app.routes.ai import router as ai_router
from app.routes.auth import router as auth_router
from app.routes.threat_hunting import router as hunt_router
from app.routes.threat_intelligence import router as threat_router
from app.routes.live_soc import router as live_soc_router
from app.routes.analytics import router as analytics_router
from app.routes.enterprise import router as enterprise_router
from app.routes.cases import router as cases_router
from app.routes.alerts import router as alerts_router
from app.routes.investigations import router as investigations_router
from app.routes.settings import router as settings_router
from app.routes.search import router as search_router
from app.routes.notifications import router as notifications_router

from app.core.config import settings


@asynccontextmanager
async def lifespan(app: FastAPI):

    # Task 14 — persistent standalone collector. If a standalone collector
    # process is already running (Windows service / scheduled task / manual
    # run), do NOT start a second in-process collector. The API instead
    # forwards newly persisted events into the live store + WebSocket
    # pipeline so real-time behavior is preserved without duplicate
    # collection. If none is running, fall back to the in-process collector
    # for local development.
    external_collector = external_collector_running()
    collector_task = None
    forwarder_task = None

    if external_collector:
        print(
            "[Collector] Standalone collector detected - in-process collection "
            "disabled; live events forwarded from SQLite."
        )
        forwarder_task = asyncio.create_task(live_forwarder_loop())
    else:
        print(
            "[Collector] No standalone collector detected - starting in-process "
            "collector (dev fallback). Install a persistent collector with: "
            "python install_collector.py task"
        )
        collector_task = asyncio.create_task(collector.start())

    yield

    if forwarder_task is not None:
        forwarder_task.cancel()

    if collector_task is not None:
        collector.stop()
        collector_task.cancel()


app = FastAPI(
    title="SOCRA AI",
    description="AI-Powered SOC Investigation Platform",
    version="0.1.0",
    lifespan=lifespan,
    docs_url=None,  # Disable default docs to implement custom CSP-aware version
    redoc_url=None,
)

# ══════════════════════════════════════════════════════════
# Self-hosted Swagger UI (CSP-safe /docs)
#
# swagger-ui-dist assets are vendored into static/swagger-ui/ so /docs works
# without cdn.jsdelivr.net or fastapi.tiangolo.com and the global CSP stays
# strict. Only same-origin assets are used, plus a SHA-256 hash of Swagger's
# inline init script (no 'unsafe-inline', no 'unsafe-eval', no external CDNs).
# ══════════════════════════════════════════════════════════

SWAGGER_ASSETS_URL = "/swagger-ui-assets"
SWAGGER_ASSETS_DIR = Path(__file__).resolve().parent / "static" / "swagger-ui"

SWAGGER_JS_URL = f"{SWAGGER_ASSETS_URL}/swagger-ui-bundle.js"
SWAGGER_CSS_URL = f"{SWAGGER_ASSETS_URL}/swagger-ui.css"
SWAGGER_FAVICON_URL = f"{SWAGGER_ASSETS_URL}/favicon-32x32.png"


# Single source of truth for the /docs page and the CSP hash computation so
# the two can never drift apart (the hash must match the served HTML exactly).
def swagger_ui_kwargs() -> dict:
    return {
        "openapi_url": "/openapi.json",
        "title": "SOCRA AI - API Documentation",
        "swagger_js_url": SWAGGER_JS_URL,
        "swagger_css_url": SWAGGER_CSS_URL,
        "swagger_favicon_url": SWAGGER_FAVICON_URL,
    }


# FastAPI's get_swagger_ui_html() emits an inline init script that would be
# blocked by script-src 'self'. Instead of weakening the policy with
# 'unsafe-inline', hash the exact inline script and allow only that hash
# on the /docs page.
_INLINE_SCRIPT_RE = re.compile(r"<script(?![^>]*\bsrc=)[^>]*>(.*?)</script>", re.DOTALL)


def _swagger_inline_script_sources() -> str:
    sources = []
    html = get_swagger_ui_html(**swagger_ui_kwargs()).body.decode("utf-8")
    for match in _INLINE_SCRIPT_RE.finditer(html):
        digest = hashlib.sha256(match.group(1).encode("utf-8")).digest()
        sources.append(f"'sha256-{base64.b64encode(digest).decode('ascii')}'")
    return " ".join(sources)


# Narrowly scoped policy for /docs only: same-origin assets plus the exact
# hashed inline script. The main application CSP below stays unchanged.
SWAGGER_DOCS_CSP = (
    "default-src 'self'; "
    "script-src 'self' " + _swagger_inline_script_sources() + "; "
    "style-src 'self' 'unsafe-inline'; "
    "img-src 'self' data:; "
    "font-src 'self' data:; "
    "connect-src 'self' ws: wss:; "
    "object-src 'none'; "
    "frame-ancestors 'none'; "
    "base-uri 'self'"
)

# CORS origins are environment-driven (CORS_ORIGINS, comma-separated) so a
# production host can be allowed without editing source code. Local dev
# defaults keep the Vite dev server working out of the box. Methods/headers
# are narrowed to what the API actually uses (defense in depth).
app.add_middleware(
    CORSMiddleware,
    allow_origins=[o.strip() for o in settings.CORS_ORIGINS.split(",") if o.strip()],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type"],
)


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Adds basic security headers to every response (CSP, framing, sniffing)."""

    async def dispatch(self, request: StarletteRequest, call_next):
        response: StarletteResponse = await call_next(request)
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault(
            "Referrer-Policy", "strict-origin-when-cross-origin"
        )
        
        # Apply strict CSP for main application, narrow exception for Swagger docs
        if request.url.path.startswith("/docs") or request.url.path == "/openapi.json":
            # Swagger-specific narrow CSP - allows only same-origin assets plus
            # the exact hashed inline init script. No external CDNs, no
            # 'unsafe-inline' for scripts, no 'unsafe-eval'.
            response.headers.setdefault("Content-Security-Policy", SWAGGER_DOCS_CSP)
        else:
            # Main application strict CSP remains unchanged
            response.headers.setdefault(
                "Content-Security-Policy",
                "default-src 'self'; "
                "script-src 'self'; "
                "style-src 'self' 'unsafe-inline'; "
                "img-src 'self' data:; "
                "font-src 'self' data:; "
                "connect-src 'self' ws: wss:; "
                "object-src 'none'; "
                "frame-ancestors 'none'; "
                "base-uri 'self'",
            )
        return response


# Registered after CORS so it wraps every response (outermost middleware).
app.add_middleware(SecurityHeadersMiddleware)

# Self-hosted Swagger UI static assets (vendored swagger-ui-dist). These are
# same-origin resources, so they load fine under the strict main-app CSP.
app.mount(
    SWAGGER_ASSETS_URL,
    StaticFiles(directory=str(SWAGGER_ASSETS_DIR)),
    name="swagger-ui-assets",
)

# ══════════════════════════════════════════════════════════
# Global Exception Handlers
# ══════════════════════════════════════════════════════════

app.add_exception_handler(SocraError, socra_exception_handler)
app.add_exception_handler(Exception, global_exception_handler)
app.add_exception_handler(404, not_found_handler)

splunk = SplunkService()
timeline = TimelineEngine()
report = ReportGenerator()
ai = AIEngine()


@app.get("/")
def home():
    return {
        "message": "Welcome to SOCRA AI 🚀"
    }


@app.get("/health")
def health():
    return {
        "status": "Healthy"
    }


@app.get("/splunk/test", dependencies=[Depends(require_admin)])
def test_splunk():

    try:

        service = splunk.connect()

        return {
            "status": "Connected",
            "username": service.username,
            "version": service.info["version"],
            "server_name": service.info["serverName"]
        }

    except Exception as e:

        return {
            "status": "Failed",
            "error": str(e)
        }


@app.get("/ai/investigate", dependencies=[Depends(get_current_user)])
def ai_investigation():
    """Legacy Splunk-only AI investigation path (Task 26).

    The real AI investigation runs on local telemetry via POST /ai/investigate
    (app/routes/ai.py). This GET endpoint existed for the old Splunk-backed
    pipeline and is kept as an explicit feature flag: it never attempts a
    Splunk connection and never returns raw exceptions.
    """
    return {
        "available": False,
        "detail": "Splunk integration required.",
        "message": (
            "This endpoint served the legacy Splunk-backed AI investigation. "
            "Local telemetry is available via POST /ai/investigate."
        ),
    }


app.include_router(logs_router)
app.include_router(timeline_router)
app.include_router(reports_router)
app.include_router(ai_router)
app.include_router(auth_router)
app.include_router(hunt_router)
app.include_router(threat_router)
app.include_router(enterprise_router)
app.include_router(cases_router)
app.include_router(alerts_router)
app.include_router(investigations_router)
app.include_router(live_soc_router)
app.include_router(analytics_router)
app.include_router(settings_router)
app.include_router(search_router)
app.include_router(notifications_router)


# Custom Swagger UI with CSP-aware implementation (self-hosted assets)
@app.get("/docs", include_in_schema=False)
async def custom_swagger_ui_html():
    return get_swagger_ui_html(**swagger_ui_kwargs())


@app.get("/openapi.json", include_in_schema=False)
async def get_openapi_schema():
    return get_openapi(
        title=app.title,
        version=app.version,
        description=app.description,
        routes=app.routes,
    )


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)