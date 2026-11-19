"""
Lab 11 — Helper Utilities
"""
from core.config import get_llm_provider, PROVIDER_OPENROUTER  # noqa: F401
from core.openai_runtime import OpenAIRunner, OpenAISession


async def chat_with_agent(agent, runner, user_message: str, session_id=None, *, user_id="student"):
    """Send a message to the agent and get the response.

    Works with OpenAIRunner (OpenAI Red / OpenRouter Blue) and Google ADK (Gemini Red).
    """
    provider = getattr(runner, "provider", None)
    if isinstance(runner, OpenAIRunner) or provider in ("openrouter", "openai"):
        session_key = getattr(session_id, "id", session_id)
        session = session_id if isinstance(session_id, OpenAISession) else (
            runner.sessions.get(session_key) if session_key else None
        )
        if session_key and session is None:
            raise ValueError("Unknown chat session")
        if session is None:
            session = OpenAISession(user_id=user_id)
        text = await runner.chat(agent, user_message, user_id=user_id, session=session)
        runner.sessions[session.id] = session
        while len(runner.sessions) > 100:
            runner.sessions.pop(next(iter(runner.sessions)))
        return text, session

    from google.genai import types

    app_name = runner.app_name

    session = None
    if session_id is not None:
        session_id = getattr(session_id, "id", session_id)
        try:
            session = await runner.session_service.get_session(
                app_name=app_name, user_id=user_id, session_id=session_id
            )
        except (ValueError, KeyError):
            pass

    if session is None:
        try:
            session = await runner.session_service.create_session(
                app_name=app_name, user_id=user_id
            )
        except Exception:
            session = await runner.session_service.create_session(
                app_name=app_name, user_id=user_id
            )

    content = types.Content(
        role="user",
        parts=[types.Part.from_text(text=user_message)],
    )

    final_response = ""
    async for event in runner.run_async(
        user_id=user_id, session_id=session.id, new_message=content
    ):
        if hasattr(event, "content") and event.content and event.content.parts:
            for part in event.content.parts:
                if hasattr(part, "text") and part.text:
                    final_response += part.text

    return final_response, session
