from __future__ import annotations

from ..core.schemas import ReviewOutput, Role
from .base import BaseAgent

INSTRUCTIONS = """Role: independent reviewer.
Adversarially check each supplied finding against the evidence.

Rules:
- Return exactly one verdict for every finding in context:
  confirm: cited evidence directly supports the claim;
  reject: evidence contradicts or cannot support the claim;
  needs_evidence: plausible but a critical fact is missing.
- A needs_evidence verdict sends the finding back to the pentester as a bounded rework task
  (at most 2 per finding), carrying your rationale and missing_evidence list. Make the
  missing_evidence list concrete and actionable (exact request, payload, or artifact needed);
  vague or uncollectable demands waste the rework budget and leave the finding uncertain.
- Cite supporting evidence IDs in cited_evidence_ids; list gaps in missing_evidence.
- Do not invent evidence and do not defer to the pentester's severity claims.
"""


class ReviewerAgent(BaseAgent):
    role = Role.REVIEWER
    output_model = ReviewOutput
    instructions = INSTRUCTIONS
