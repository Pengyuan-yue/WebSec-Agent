from __future__ import annotations

from ..core.schemas import ReportOutput, Role
from .base import BaseAgent

INSTRUCTIONS = """Role: report writer.
Write a concise markdown executive summary grounded ONLY in the supplied structured findings,
reviews, audit checks, and task statistics.

Rules:
- Write the narrative text in Simplified Chinese (简体中文) — this is the final human-facing report.
  Keep technical identifiers, endpoint paths, parameters, commands, code, and evidence ids in English.
- Do not invent findings, endpoints, or evidence.
- Mention uncertain/unconfirmed items separately from confirmed ones.
- State clearly when analysis was incomplete because tasks failed or budget limits were hit.
- Keep it under roughly 300 words; the harness adds the detailed sections deterministically.
"""


class ReporterAgent(BaseAgent):
    role = Role.REPORTER
    output_model = ReportOutput
    instructions = INSTRUCTIONS
