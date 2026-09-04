import logging

from fastapi import APIRouter, Depends

from app.auth.dependencies import get_current_user
from app.analytics.analytics_engine import analytics_engine

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/analytics",
    tags=["Analytics"],
    dependencies=[Depends(get_current_user)]
)


# ------------------------------------------------------
# Complete Dashboard
# ------------------------------------------------------

@router.get("/dashboard")
def dashboard():
    try:
        logger.debug("[Route Analytics] Dashboard endpoint called")
        result = analytics_engine.dashboard()
        logger.debug("[Route Analytics] Dashboard returned successfully")
        return result
    except Exception as e:
        logger.exception("[Route Analytics] Dashboard failed: %s", e)
        return {
            "summary": {
                "total_events": 0,
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
                "informational": 0,
                "hosts": 0,
                "eps": 0,
            },
            "error": "Dashboard data is temporarily unavailable.",
        }


# ------------------------------------------------------
# Total Events
# ------------------------------------------------------

@router.get("/total-events")
def total_events():

    return {

        "total_events": analytics_engine.total_events()

    }


# ------------------------------------------------------
# Severity Distribution
# ------------------------------------------------------

@router.get("/severity")
def severity():

    return analytics_engine.severity_distribution()


# ------------------------------------------------------
# Top Hosts
# ------------------------------------------------------

@router.get("/top-hosts")
def top_hosts():

    return {

        "hosts": analytics_engine.top_hosts()

    }


# ------------------------------------------------------
# Top Processes
# ------------------------------------------------------

@router.get("/top-processes")
def top_processes():

    return {

        "processes": analytics_engine.top_processes()

    }


# ------------------------------------------------------
# Top Event IDs
# ------------------------------------------------------

@router.get("/top-eventids")
def top_eventids():

    return {

        "event_ids": analytics_engine.top_event_ids()

    }


# ------------------------------------------------------
# MITRE Distribution
# ------------------------------------------------------

@router.get("/mitre")
def mitre():

    return analytics_engine.mitre_distribution()


# ------------------------------------------------------
# Events Per Hour
# ------------------------------------------------------

@router.get("/events-per-hour")
def events_per_hour():

    return analytics_engine.events_per_hour()