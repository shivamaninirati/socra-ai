from app.chat.chat_service import ChatService

chat = ChatService()

response = chat.ask(
    "Explain Windows Event ID 4688."
)

print(response)