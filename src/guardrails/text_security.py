"""Small deterministic text helpers shared by the student's Blue guardrails."""
from __future__ import annotations

import base64
import binascii
import codecs
import re
import unicodedata

from core.config import DEMO_SECRETS


def canonical_text(text: str) -> str:
    """Normalize compatibility characters and remove invisible control characters."""
    text = unicodedata.normalize("NFKC", text)
    return "".join(c for c in text if unicodedata.category(c) != "Cf")


def policy_text(text: str) -> str:
    """Use an accent-insensitive view for English/Vietnamese policy matching."""
    text = canonical_text(text).casefold().replace("đ", "d")
    text = "".join(c for c in unicodedata.normalize("NFD", text)
                   if unicodedata.category(c) != "Mn")
    return re.sub(r"\s+", " ", text).strip()


def contains_protected_value(text: str) -> bool:
    """Recognize lab values, including common encodings and inserted separators."""
    text = canonical_text(text)
    views = [text, text[::-1], codecs.decode(text, "rot_13")]
    for token in re.findall(r"[A-Za-z0-9+/_-]{8,}={0,2}", text):
        try:
            decoded = base64.urlsafe_b64decode(token + "=" * (-len(token) % 4))
            views.append(decoded.decode("utf-8", errors="ignore"))
        except (binascii.Error, ValueError):
            continue
    for token in re.findall(r"\b(?:[0-9a-fA-F]{2}[ :-]?){6,}\b", text):
        try:
            views.append(bytes.fromhex(re.sub(r"[ :-]", "", token)).decode("utf-8", errors="ignore"))
        except ValueError:
            continue
    needles = [re.sub(r"[^a-z0-9]", "", s.casefold()) for s in DEMO_SECRETS]
    return any(needle and needle in re.sub(r"[^a-z0-9]", "", view.casefold())
               for view in views for needle in needles)
