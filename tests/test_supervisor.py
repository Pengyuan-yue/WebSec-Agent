from __future__ import annotations

import pytest

from websec_agent.agents.supervisor import SupervisorAgent
from websec_agent.core.schemas import SupervisorOutput


def test_supervisor_prompt_is_isolated_from_pentester_instructions():
    prompt = SupervisorAgent().system_prompt

    assert "internal scheduling controller" in prompt
    assert "Never request tools" in prompt
    assert "COMMAND INJECTION METHOD" not in prompt
    assert "SQL INJECTION METHOD" not in prompt


def test_supervisor_output_is_limited_to_four_fixed_slots():
    output = SupervisorOutput.model_validate(
        {
            "summary": "Keep responsibility areas distinct.",
            "assignments": [
                {
                    "slot": slot,
                    "objective": f"Handle distinct authorized work area number {slot}.",
                    "focus": [f"area {slot}"],
                    "avoid": [],
                    "guidance": "Use existing in-scope evidence.",
                }
                for slot in range(1, 5)
            ],
            "overlap_warnings": [],
        }
    )

    assert [item.slot for item in output.assignments] == [1, 2, 3, 4]
    with pytest.raises(Exception):
        SupervisorOutput.model_validate(
            {
                "summary": "Invalid slot.",
                "assignments": [{"slot": 5}],
            }
        )
