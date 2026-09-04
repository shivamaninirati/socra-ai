from typing import Optional

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from app.auth.dependencies import get_current_user
from app.ai.ai_engine import AIEngine
from app.chat.chat_service import ChatService
from app.storage.sqlite_storage import sqlite_storage

router = APIRouter(
    prefix="/ai",
    tags=["AI"],
    dependencies=[Depends(get_current_user)]
)

ai = AIEngine()
chat = ChatService()


class InvestigationRequest(BaseModel):
    event: dict
    investigation_id: Optional[str] = None


class ChatRequest(BaseModel):
    question: str


@router.get("/health")
def ai_health():
    """Clear service/model availability status.

    Checked BEFORE any investigation so the UI can show a useful error
    instead of loading forever when Ollama is down.
    """
    return ai.health()


@router.post("/investigate")
def investigate(request: InvestigationRequest):
    try:
        investigation = None
        if request.investigation_id:
            investigation = sqlite_storage.get_investigation(request.investigation_id)

        analysis = ai.investigate(request.event, investigation=investigation)

        if not analysis.get("success"):
            return analysis

        return {
            "success": True,
            "available": True,
            "provider": analysis.get("provider"),
            "model": analysis.get("model"),
            "analysis": analysis.get("analysis"),
        }

    except Exception as e:
        import logging
        logging.getLogger(__name__).error(
            "AI investigation failed: %s", e, exc_info=True
        )
        return {
            "success": False,
            "available": False,
            "error": "The AI investigation service failed unexpectedly.",
            "detail": "The AI investigation service failed unexpectedly.",
        }


class ChatWithConversationRequest(BaseModel):
    question: str
    conversation_id: str | None = None
    context: dict | None = None


class NewConversationRequest(BaseModel):
    title: str = "New Conversation"
    context: dict = {}


class RenameConversationRequest(BaseModel):
    title: str


class SearchConversationsRequest(BaseModel):
    query: str


@router.post("/chat")
def ai_chat(request: ChatWithConversationRequest, user: dict = Depends(get_current_user)):
    user_id = user.get("sub") or user.get("user_id")
    
    if not request.question.strip():
        return {
            "success": False,
            "error": "Question cannot be empty."
        }

    try:
        # Get or create conversation
        conversation_id = request.conversation_id
        conversation = None
        
        if conversation_id:
            # Verify the conversation belongs to the current user
            conversation = sqlite_storage.get_conversation(conversation_id, user_id)
        
        if not conversation:
            # Create a new conversation if none exists or access was denied
            conversation = sqlite_storage.create_conversation(
                user_id, 
                title="New Conversation",
                context=request.context
            )
            conversation_id = conversation["id"]
        
        # Add user message to conversation
        sqlite_storage.add_message(
            conversation_id,
            "user",
            request.question
        )

        # Flush so user message is persisted before AI response starts
        sqlite_storage.flush(timeout=3.0)

        # Auto-generate title from first user message
        conv_check = sqlite_storage.get_conversation(conversation_id, user_id)
        if conv_check and (not conv_check.get("title") or conv_check.get("title") == "New Conversation"):
            auto_title = request.question[:80].strip()
            if len(request.question) > 80:
                last_space = auto_title.rfind(" ")
                if last_space > 40:
                    auto_title = auto_title[:last_space]
                auto_title += "..."
            sqlite_storage.update_conversation_title(conversation_id, auto_title)
        
        # Fetch conversation history for multi-turn context
        history_messages = sqlite_storage.get_conversation_messages(
            conversation_id, user_id, limit=50
        )
        # Format history for ChatService (exclude the just-added user message
        # since it will be the 'question' parameter)
        conversation_history = []
        for msg in history_messages[:-1]:  # skip the last message (just-added user msg)
            conversation_history.append({
                "role": msg["role"],
                "content": msg["content"]
            })

        # Get AI response with conversation history for context
        answer = chat.ask(request.question, conversation_history=conversation_history)

        # Ollama returns a clearly-marked error banner (never an answer)
        # when the service/model is unavailable or the request times out.
        if "# SOCRA AI Unavailable" in answer or "Unable to contact Ollama" in answer:
            sqlite_storage.add_message(
                conversation_id,
                "assistant",
                answer,
                status="failed"
            )
            sqlite_storage.flush(timeout=3.0)
            return {
                "success": False,
                "available": False,
                "provider": "Ollama",
                "error": answer,
                "detail": "Ollama could not answer the question (unavailable or timed out).",
                "conversation_id": conversation_id
            }
        
        # Add AI response to conversation
        sqlite_storage.add_message(
            conversation_id,
            "assistant",
            answer,
            status="completed"
        )
        
        # Flush the write queue so the frontend immediately sees persisted messages
        sqlite_storage.flush(timeout=3.0)
        
        return {
            "success": True,
            "answer": answer,
            "conversation_id": conversation_id
        }

    except Exception as e:
        import logging
        logging.getLogger(__name__).error(
            "AI chat failed: %s", e, exc_info=True
        )
        return {
            "success": False,
            "error": "The chat service failed unexpectedly.",
            "detail": str(e)
        }


@router.get("/conversations")
def get_conversations(user: dict = Depends(get_current_user)):
    """Get all chat conversations for the current user."""
    user_id = user.get("sub") or user.get("user_id")
    try:
        conversations = sqlite_storage.get_user_conversations_with_count(user_id)
        return {
            "success": True,
            "conversations": conversations
        }
    except Exception as e:
        import logging
        logging.getLogger(__name__).error("Failed to get conversations: %s", e, exc_info=True)
        return {
            "success": False,
            "error": "Failed to load conversations."
        }


@router.get("/conversations/{conversation_id}")
def get_conversation(conversation_id: str, user: dict = Depends(get_current_user)):
    """Get a specific conversation and its messages."""
    user_id = user.get("sub") or user.get("user_id")
    try:
        # Verify ownership and get conversation
        conversation = sqlite_storage.get_conversation_with_count(conversation_id, user_id)
        if not conversation:
            return {
                "success": False,
                "error": "Conversation not found or access denied."
            }
        
        # Get messages
        messages = sqlite_storage.get_conversation_messages(conversation_id, user_id)
        
        # Format messages for frontend
        formatted_messages = []
        for msg in messages:
            formatted_messages.append({
                "role": msg["role"],
                "content": msg["content"],
                "time": msg["timestamp"],
                "status": msg.get("status", "completed")
            })
        
        return {
            "success": True,
            "conversation": conversation,
            "messages": formatted_messages
        }
    except Exception as e:
        import logging
        logging.getLogger(__name__).error("Failed to get conversation: %s", e, exc_info=True)
        return {
            "success": False,
            "error": "Failed to load conversation."
        }


@router.post("/conversations/new")
def create_new_conversation(request: NewConversationRequest = None, user: dict = Depends(get_current_user)):
    """Create a new empty conversation."""
    user_id = user.get("sub") or user.get("user_id")
    try:
        title = request.title if request else "New Conversation"
        context = request.context if request else {}
        conversation = sqlite_storage.create_conversation(user_id, title, context)
        return {
            "success": True,
            "conversation": conversation
        }
    except Exception as e:
        import logging
        logging.getLogger(__name__).error("Failed to create conversation: %s", e, exc_info=True)
        return {
            "success": False,
            "error": "Failed to create new conversation."
        }


@router.post("/conversations/{conversation_id}/clear")
def clear_conversation(conversation_id: str, user: dict = Depends(get_current_user)):
    """Clear all messages from a conversation."""
    user_id = user.get("sub") or user.get("user_id")
    try:
        success = sqlite_storage.clear_conversation(conversation_id, user_id)
        if success:
            return {
                "success": True
            }
        return {
            "success": False,
            "error": "Failed to clear conversation or access denied."
        }
    except Exception as e:
        import logging
        logging.getLogger(__name__).error("Failed to clear conversation: %s", e, exc_info=True)
        return {
            "success": False,
            "error": "Failed to clear conversation."
        }


@router.delete("/conversations/{conversation_id}")
def delete_conversation(conversation_id: str, user: dict = Depends(get_current_user)):
    """Delete a conversation and all its messages."""
    user_id = user.get("sub") or user.get("user_id")
    try:
        success = sqlite_storage.delete_conversation(conversation_id, user_id)
        if success:
            return {
                "success": True
            }
        return {
            "success": False,
            "error": "Failed to delete conversation or access denied."
        }
    except Exception as e:
        import logging
        logging.getLogger(__name__).error("Failed to delete conversation: %s", e, exc_info=True)
        return {
            "success": False,
            "error": "Failed to delete conversation."
        }


@router.patch("/conversations/{conversation_id}")
def rename_conversation(conversation_id: str, request: RenameConversationRequest, user: dict = Depends(get_current_user)):
    """Rename a conversation."""
    user_id = user.get("sub") or user.get("user_id")
    try:
        if not request.title.strip():
            return {"success": False, "error": "Title cannot be empty."}
        success = sqlite_storage.rename_conversation(conversation_id, user_id, request.title.strip())
        if success:
            return {"success": True}
        return {"success": False, "error": "Failed to rename conversation or access denied."}
    except Exception as e:
        import logging
        logging.getLogger(__name__).error("Failed to rename conversation: %s", e)
        return {"success": False, "error": "Failed to rename conversation."}


@router.post("/conversations/search")
def search_conversations(request: SearchConversationsRequest, user: dict = Depends(get_current_user)):
    """Search conversations by title or message content."""
    user_id = user.get("sub") or user.get("user_id")
    try:
        conversations = sqlite_storage.search_conversations(user_id, request.query)
        return {"success": True, "conversations": conversations}
    except Exception as e:
        import logging
        logging.getLogger(__name__).error("Failed to search conversations: %s", e)
        return {"success": False, "error": "Failed to search conversations."}


@router.delete("/conversations")
def delete_all_conversations(user: dict = Depends(get_current_user)):
    """Delete all conversations for the current user."""
    user_id = user.get("sub") or user.get("user_id")
    try:
        sqlite_storage.flush(timeout=3.0)
        success = sqlite_storage.delete_all_conversations(user_id)
        sqlite_storage.flush(timeout=3.0)
        if success:
            return {"success": True}
        return {"success": False, "error": "Failed to delete conversations."}
    except Exception as e:
        import logging
        logging.getLogger(__name__).error("Failed to delete all conversations: %s", e)
        return {"success": False, "error": "Failed to delete all conversations."}
