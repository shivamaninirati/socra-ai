from typing import Optional

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from app.auth.dependencies import get_current_user
from app.cases.case_manager import CASE_PRIORITIES, CASE_STATUSES, case_manager

router = APIRouter(
    prefix="/cases",
    tags=["Case Management"],
    dependencies=[Depends(get_current_user)]
)


# ---------------------------------------------------------
# Models
# ---------------------------------------------------------

class CreateCaseRequest(BaseModel):
    event: dict
    # Optional link to the persisted investigation record for this alert.
    investigation_id: Optional[str] = None


class UpdateCaseRequest(BaseModel):
    # Generic editable scalar fields (optional - only provided fields change).
    priority: Optional[str] = None
    title: Optional[str] = None


class AssignRequest(BaseModel):
    analyst: str


class StatusRequest(BaseModel):
    status: str


class NoteRequest(BaseModel):
    note: str


def _actor(user: dict) -> str:
    """Human-readable actor name for the case timeline."""
    if not user:
        return "SOC Analyst"
    return str(
        user.get("sub")
        or user.get("username")
        or user.get("user_id")
        or "SOC Analyst"
    )


def _error(message: str):
    return {"success": False, "error": message}


# ---------------------------------------------------------
# Create Case
# ---------------------------------------------------------

@router.post("/create")
def create_case(request: CreateCaseRequest, user: dict = Depends(get_current_user)):

    case = case_manager.create_case(
        request.event,
        investigation_id=request.investigation_id,
        created_by=_actor(user),
    )

    return {

        "success": True,

        "case": case

    }


# ---------------------------------------------------------
# Get All Cases
# ---------------------------------------------------------

@router.get("/")
def get_cases():

    cases = case_manager.get_cases()

    return {

        "success": True,

        "count": len(cases),

        "cases": cases

    }


# ---------------------------------------------------------
# Get Single Case
# ---------------------------------------------------------

@router.get("/{case_id}")
def get_case(case_id: str):

    case = case_manager.get_case(case_id)

    if not case:

        return _error("Case not found")

    return {

        "success": True,

        "case": case

    }


# ---------------------------------------------------------
# Update Case (priority / title)
# ---------------------------------------------------------

@router.put("/{case_id}")
def update_case(
    case_id: str,
    request: UpdateCaseRequest,
    user: dict = Depends(get_current_user),
):

    if request.priority is None and request.title is None:
        return _error("Nothing to update. Provide priority and/or title.")

    try:
        case = case_manager.update_case(
            case_id,
            {"priority": request.priority, "title": request.title},
            changed_by=_actor(user),
        )
    except ValueError as exc:
        return _error(str(exc))

    if not case:
        return _error("Case not found")

    return {

        "success": True,

        "case": case

    }


# ---------------------------------------------------------
# Assign Analyst
# ---------------------------------------------------------

@router.put("/{case_id}/assign")
def assign_case(

    case_id: str,

    request: AssignRequest,

    user: dict = Depends(get_current_user),

):

    analyst = (request.analyst or "").strip()
    if not analyst:
        return _error("Analyst cannot be empty.")

    case = case_manager.assign_case(

        case_id,

        analyst,

        assigned_by=_actor(user),

    )

    if not case:

        return _error("Case not found")

    return {

        "success": True,

        "case": case

    }


# ---------------------------------------------------------
# Update Status
# ---------------------------------------------------------

@router.put("/{case_id}/status")
def update_status(

    case_id: str,

    request: StatusRequest,

    user: dict = Depends(get_current_user),

):

    if request.status not in CASE_STATUSES:
        return _error(
            f"Invalid status. Must be one of: {', '.join(CASE_STATUSES)}"
        )

    case = case_manager.update_status(

        case_id,

        request.status,

        changed_by=_actor(user),

    )

    if not case:

        return _error("Case not found")

    return {

        "success": True,

        "case": case

    }


# ---------------------------------------------------------
# Add Investigation Note
# ---------------------------------------------------------

@router.put("/{case_id}/note")
def add_note(

    case_id: str,

    request: NoteRequest,

    user: dict = Depends(get_current_user),

):

    note = (request.note or "").strip()
    if not note:
        return _error("Note cannot be empty.")

    case = case_manager.add_note(

        case_id,

        note,

        author=_actor(user),

    )

    if not case:

        return _error("Case not found")

    return {

        "success": True,

        "case": case

    }


# ---------------------------------------------------------
# Case priority vocabulary (for UI controls)
# ---------------------------------------------------------

@router.get("/vocabulary/priorities")
def case_priorities():
    return {"priorities": list(CASE_PRIORITIES)}


# ---------------------------------------------------------
# Statistics
# ---------------------------------------------------------

@router.get("/statistics/summary")
def statistics():

    return case_manager.statistics()