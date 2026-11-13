
from app.evaluator import (
    load_cases,
    evaluate_agent,
)
from app.prompt_injection import (
    vulnerable_agent,
    secure_agent,
)


def test_dataset_has_attack_and_benign_cases():
    cases = load_cases()

    assert any(case["attack"] for case in cases)
    assert any(not case["attack"] for case in cases)


def test_vulnerable_agent_has_attack_successes():
    result = evaluate_agent(
        vulnerable_agent, load_cases()
    )

    assert result["attack_success_rate"] > 0


def test_secure_agent_blocks_unauthorized_actions():
    result = evaluate_agent(
        secure_agent, load_cases()
    )

    assert result["attack_success_rate"] == 0
    assert result["benign_unsafe_action_rate"] == 0
