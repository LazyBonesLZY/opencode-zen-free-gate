"""Model catalog + outbound protocol routing — mirrors oc-fwd src/catalog."""
import re

# Outbound protocols mirror oc-fwd docs/conversion.md
_RESPONSES = re.compile(r"^(gpt-5|grok-|muse-)", re.I)
_MESSAGES = re.compile(r"^(claude-|qwen3)", re.I)
_GEMINI = re.compile(r"^gemini-", re.I)


def resolve_outbound_protocol(model: str, overrides: dict = None) -> str:
    overrides = overrides or {}
    if model in overrides:
        return overrides[model]
    m = model.lower()
    if _RESPONSES.match(m):
        return "responses"
    if _MESSAGES.match(m):
        return "messages"
    if _GEMINI.match(m):
        return "gemini"
    return "chat"


def outbound_path(model: str, overrides: dict = None) -> str:
    proto = resolve_outbound_protocol(model, overrides)
    return {
        "responses": "/v1/responses",
        "messages": "/v1/messages",
        "gemini": f"/v1/models/{model}:generateContent",
        "chat": "/v1/chat/completions",
    }[proto]


def apply_model_map(model: str, model_map: dict) -> str:
    return model_map.get(model, model)
