from fastapi import APIRouter, Depends
from pydantic import BaseModel

from app.auth.dependencies import get_current_user
from app.core.logger import get_module_logger
from app.services.threat_intelligence_services import ThreatIntelligenceService

logger = get_module_logger("routes.threat_intelligence")

router = APIRouter(
    prefix="/threat",
    tags=["Threat Intelligence"],
    dependencies=[Depends(get_current_user)]
)

service = ThreatIntelligenceService()


class ThreatRequest(BaseModel):
    indicator: str


@router.post("/intelligence")
def threat_intelligence(request: ThreatRequest):

    try:

        result = service.lookup(request.indicator)

        return {
            "success": True,
            "data": result
        }

    except Exception as e:

        logger.error("Threat intelligence lookup failed: %s", e, exc_info=True)
        return {
            "success": False,
            "error": "Threat intelligence lookup failed."
        }