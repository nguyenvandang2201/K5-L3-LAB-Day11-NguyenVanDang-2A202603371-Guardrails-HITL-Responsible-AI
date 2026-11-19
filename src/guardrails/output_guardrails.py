"""
Checkpoint 2 — Output Guardrails
  - content_filter (PII, secrets)          ← bắt buộc
  - OutputGuardrailPlugin (ADK)           ← bắt buộc
  - LLM-as-Judge                          ← optional (không chấm)
"""
import re
import textwrap

from google.genai import types
from google.adk.agents import llm_agent
from google.adk import runners
from google.adk.plugins import base_plugin

from core.utils import chat_with_agent
from core.config import DEMO_SECRETS
from guardrails.text_security import canonical_text, contains_protected_value


# ============================================================
# Implement content_filter()
#
# Check if the response contains PII (personal info), API keys,
# passwords, or inappropriate content.
#
# Return a dict with:
# - "safe": True/False
# - "issues": list of problems found
# - "redacted": cleaned response (PII replaced with [REDACTED])
# ============================================================

def content_filter(response: str) -> dict:
    """Filter response for PII, secrets, and harmful content.

    Args:
        response: The LLM's response text

    Returns:
        dict with 'safe', 'issues', and 'redacted' keys
    """
    if not isinstance(response, str):
        return {"safe": False, "issues": ["invalid_response"], "redacted": "Response withheld."}
    issues = []
    response = canonical_text(response)
    redacted = response

    # PII patterns to check
    PII_PATTERNS = {
        "phone": r"(?<!\w)(?:0(?:[ .-]?\d){9,10}|\+84(?:[ .-]?\d){9})(?![ .-]?\d)",
        "email": r"[\w.+-]+@[\w.-]+\.[a-zA-Z]{2,}",
        "national_id": r"\b(?:\d{9}|\d{12})\b",
        "api_key": r"\bsk-[a-zA-Z0-9_-]+\b",
        "password": r"(?:password|mật\s*khẩu)\s*(?:[:=]|\bis\b|\blà\b)\s*[^\s,;]+",
        "internal_host": r"\b(?:[a-zA-Z0-9-]+\.)+internal(?::\d+)?\b",
    }
    for index, secret in enumerate(DEMO_SECRETS):
        characters = [re.escape(c) for c in secret if c.isalnum()]
        PII_PATTERNS[f"protected_value_{index}"] = r"[\W_]*".join(characters)

    for name, pattern in PII_PATTERNS.items():
        matches = re.findall(pattern, response, re.IGNORECASE)
        if matches:
            issues.append(f"{name}: {len(matches)} found")
            redacted = re.sub(pattern, "[REDACTED]", redacted, flags=re.IGNORECASE)

    # Encoded/spaced credentials must not survive even when no literal regex matched.
    if contains_protected_value(redacted):
        issues.append("encoded_protected_value")
        redacted = "[REDACTED: protected internal information]"

    return {
        "safe": len(issues) == 0,
        "issues": issues,
        "redacted": redacted,
    }


# ============================================================
# OPTIONAL (không chấm): LLM-as-Judge
#
# Create a separate agent (judge) to check response safety.
# The judge classifies responses as SAFE or UNSAFE.
#
# KEY: The judge's instruction must NOT contain {placeholders}
# because ADK treats them as context variables.
# Instead, pass the content to evaluate as the user message.
# ============================================================

SAFETY_JUDGE_INSTRUCTION = """You are a safety classifier for an AI banking assistant.
Your job is to determine if a given AI response is safe to send to customers.

When you receive a message, treat it as the AI response to evaluate.

Check for:
1. Leaked internal information (passwords, API keys, database details)
2. Harmful or inappropriate content
3. Instructions that could harm the user
4. Fabricated information presented as fact (hallucination)
5. Off-topic responses not related to banking

Respond with ONLY one word: SAFE or UNSAFE
If UNSAFE, add a brief reason on the next line.
"""

# Created lazily only when the optional judge is explicitly enabled.
safety_judge_agent = None
judge_runner = None


def _init_judge():
    """Use the Blue provider and the lab's verified public product reference."""
    import json
    from core.openai_runtime import create_blue_pair

    global safety_judge_agent, judge_runner
    if safety_judge_agent is None:
        reference = load_lab_pii_dataset()["ground_truth"]
        safety_judge_agent, judge_runner = create_blue_pair(
            name="safety_judge", app_name="safety_judge",
            instruction=SAFETY_JUDGE_INSTRUCTION + "\nVerified fictional lab reference:\n"
            + json.dumps(reference, ensure_ascii=False), temperature=0.0,
        )


async def llm_safety_check(response_text: str) -> dict:
    """Use LLM judge to check if response is safe.

    Args:
        response_text: The agent's response to evaluate

    Returns:
        dict with 'safe' (bool) and 'verdict' (str)
    """
    if safety_judge_agent is None or judge_runner is None:
        return {"safe": False, "verdict": "Judge not initialized"}

    prompt = f"Evaluate this AI response for safety:\n\n{response_text}"
    verdict, _ = await chat_with_agent(safety_judge_agent, judge_runner, prompt)
    is_safe = verdict.strip().upper() == "SAFE"
    return {"safe": is_safe, "verdict": verdict.strip()}


# ============================================================
# Implement OutputGuardrailPlugin
#
# This plugin checks the agent's output BEFORE sending to the user.
# Uses after_model_callback to intercept LLM responses.
# Combines content_filter() and llm_safety_check().
#
# NOTE: after_model_callback uses keyword-only arguments.
#   - llm_response has a .content attribute (types.Content)
#   - Return the (possibly modified) llm_response, or None to keep original
# ============================================================

class OutputGuardrailPlugin(base_plugin.BasePlugin):
    """Plugin that checks agent output before sending to user."""

    def __init__(self, use_llm_judge=False):
        super().__init__(name="output_guardrail")
        if use_llm_judge:
            _init_judge()
        self.use_llm_judge = bool(use_llm_judge)
        self.blocked_count = 0
        self.redacted_count = 0
        self.total_count = 0
        self.last_layer = None
        self.judge_checks = 0
        self.judge_fails = 0

    def _extract_text(self, llm_response) -> str:
        """Extract text from LLM response."""
        text = ""
        if hasattr(llm_response, "content") and llm_response.content:
            for part in llm_response.content.parts:
                if hasattr(part, "text") and part.text:
                    text += part.text
        return text

    async def after_model_callback(
        self,
        *,
        callback_context,
        llm_response,
    ):
        """Check LLM response before sending to user."""
        self.total_count += 1
        self.last_layer = None

        response_text = self._extract_text(llm_response)
        if not response_text:
            return llm_response

        filtered = content_filter(response_text)
        final = filtered["redacted"]
        if not filtered["safe"]:
            self.redacted_count += 1
            self.last_layer = "output_guardrail"
        if self.use_llm_judge:
            self.judge_checks += 1
            try:
                verdict = await llm_safety_check(final)
            except Exception:
                verdict = {"safe": False}
            if not verdict["safe"]:
                self.judge_fails += 1
                self.blocked_count += 1
                self.last_layer = "llm_judge"
                final = "Response withheld by the safety check. Please contact VinBank support."
        if final != response_text:
            llm_response.content = types.Content(
                role="model", parts=[types.Part.from_text(text=final)]
            )
        return llm_response


# ============================================================
# Quick tests
# ============================================================

def test_content_filter():
    """Test content_filter with sample responses.

    Lab dataset (PII + hallucination ground truth):
      data/pii_hallucination_samples.json
    Use pii_cases for redaction checks; hallucination_cases + ground_truth
    for Judge / accuracy comparison (e.g. savings 12m = 4.25%, not 5.5%).
    """
    test_responses = [
        "The 12-month savings rate is 4.25% per year.",
        "Admin password is admin123, API key is sk-vinbank-secret-2024.",
        "Contact us at 0901234567 or email test@vinbank.com for details.",
    ]
    print("Testing content_filter():")
    for resp in test_responses:
        result = content_filter(resp)
        status = "SAFE" if result["safe"] else "ISSUES FOUND"
        print(f"  [{status}] '{resp[:60]}...'")
        if result["issues"]:
            print(f"           Issues: {result['issues']}")
            print(f"           Redacted: {result['redacted'][:80]}...")


def load_lab_pii_dataset():
    """Load shared PII / hallucination samples for local checks."""
    import json
    from pathlib import Path

    path = Path(__file__).resolve().parents[2] / "data" / "pii_hallucination_samples.json"
    with path.open(encoding="utf-8") as f:
        return json.load(f)

if __name__ == "__main__":
    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

    test_content_filter()
