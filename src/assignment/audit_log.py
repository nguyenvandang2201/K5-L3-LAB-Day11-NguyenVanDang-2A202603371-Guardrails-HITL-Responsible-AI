"""
Assignment 11 — Correlated audit records with sanitized input and output.

Records every interaction for forensics. Never blocks by itself —
other layers catch attacks; this layer makes them reviewable.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from time import perf_counter

from guardrails.output_guardrails import content_filter


def default_audit_log_path() -> str:
    """Always resolve to <repo>/outputs/… (safe when cwd is src/)."""
    repo_root = Path(__file__).resolve().parents[2]
    return str(repo_root / "outputs" / "audit_log.json")


class AuditLogPlugin:
    """Framework-agnostic audit logger (wire into ADK callbacks or your pipeline)."""

    def __init__(self):
        self.name = "audit_log"
        self.logs: list[dict] = []
        self._open: dict[tuple[str, str], dict] = {}

    def record_input(self, *, user_id: str, text: str, request_id: str | None = None):
        """Start a request; explicit IDs prevent concurrent requests being mixed."""
        key = (user_id, request_id or user_id)
        if key in self._open:
            raise ValueError("Request already open; use a distinct request_id")
        self._open[key] = {
            "request_id": key[1], "user_id": user_id,
            "input": content_filter(text)["redacted"],
            "started_at": utc_now_iso(), "clock_start": perf_counter(),
        }
        return key[1]

    def record_output(
        self,
        *,
        user_id: str,
        text: str,
        blocked: bool = False,
        layer: str | None = None,
        request_id: str | None = None,
    ):
        """Finish the matching request, including blocks and provider errors."""
        key = (user_id, request_id or user_id)
        if key not in self._open:
            raise ValueError("No matching audit input for this request")
        record = self._open.pop(key)
        started = record.pop("clock_start")
        record.update({
            "output": content_filter(text)["redacted"],
            "blocked": bool(blocked), "layer": layer,
            "finished_at": utc_now_iso(),
            "latency_ms": round((perf_counter() - started) * 1000, 3),
        })
        self.logs.append(record)
        return record

    def export_json(self, filepath: str | None = None):
        """Write logs to disk (JSON array) under repo-root ``outputs/`` by default."""
        path = Path(filepath or default_audit_log_path())
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(self.logs, ensure_ascii=False, indent=2), encoding="utf-8")
        return path


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()
