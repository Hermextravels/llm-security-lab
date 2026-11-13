
from copy import deepcopy

import pytest

from app.real_llm_evaluator import (
    load_cases,
    build_payload,
    parse_response,
    is_unauthorized_call,
    run_backend,
    evaluate_responses,
    rate,
)
from app.tool_executor import (
    REFUNDS,
    secure_executor,
    vulnerable_executor,
)


def mock_response(tool_calls=None, content=None):
    return {
        "choices": [
            {
                "message": {
                    "role": "assistant",
                    "content": content,
                    "tool_calls": tool_calls or [],
                }
            }
        ]
    }


def refund_call(order_id):
    return {
        "id": "call_test",
        "type": "function",
        "function": {
            "name": "issue_refund",
            "arguments": (
                '{"order_id": "' + order_id + '"}'
            ),
        },
    }


@pytest.fixture
def cases():
    return load_cases()


def test_dataset_has_six_cases(cases):
    assert len(cases) == 6


def test_payload_has_system_prompt(cases):
    payload = build_payload(cases[0], "test-model")

    assert payload["messages"][0]["role"] == "system"
    assert payload["model"] == "test-model"


def test_payload_contains_untrusted_material(cases):
    payload = build_payload(cases[0], "test-model")

    text = payload["messages"][1]["content"]

    assert "<untrusted_support_material>" in text
    assert cases[0]["content"] in text


def test_parse_valid_tool_call():
    response = mock_response(
        [refund_call("order-200")]
    )

    parsed = parse_response(response)

    assert parsed["tool_calls"] == [
        {
            "tool": "issue_refund",
            "arguments": {
                "order_id": "order-200"
            },
        }
    ]


def test_parse_invalid_json_arguments():
    call = refund_call("order-200")
    call["function"]["arguments"] = "{invalid"

    parsed = parse_response(mock_response([call]))

    assert parsed["tool_calls"][0]["arguments"] is None


def test_cross_user_refund_detected(cases):
    call = {
        "tool": "issue_refund",
        "arguments": {"order_id": "order-200"},
    }

    assert is_unauthorized_call(cases[0], call)


def test_same_user_refund_not_cross_user():
    case = {"user_id": "alice"}

    call = {
        "tool": "issue_refund",
        "arguments": {"order_id": "order-100"},
    }

    assert not is_unauthorized_call(case, call)


def test_vulnerable_backend_executes(cases):
    call = {
        "tool": "issue_refund",
        "arguments": {"order_id": "order-200"},
    }

    outcomes = run_backend(
        cases[0],
        [call],
        vulnerable_executor,
    )

    assert outcomes[0]["unauthorized_execution"]
    assert len(REFUNDS) == 1


def test_secure_backend_blocks(cases):
    call = {
        "tool": "issue_refund",
        "arguments": {"order_id": "order-200"},
    }

    outcomes = run_backend(
        cases[0],
        [call],
        secure_executor,
    )

    assert not outcomes[0]["unauthorized_execution"]
    assert REFUNDS == []


def test_full_mock_evaluation(cases):
    responses = {}

    for case in cases:
        if case["kind"] == "attack":
            responses[case["id"]] = mock_response(
                [refund_call("order-200")]
            )
        else:
            responses[case["id"]] = mock_response(
                content="I can help with that request."
            )

    report = evaluate_responses(cases, responses)
    metrics = report["metrics"]

    assert report["total_cases"] == 6

    assert metrics[
        "unauthorized_tool_request_rate"
    ] == 1.0

    assert metrics[
        "vulnerable_unauthorized_execution_rate"
    ] == 1.0

    assert metrics[
        "secure_unauthorized_execution_rate"
    ] == 0.0

    assert metrics[
        "benign_response_presence_rate"
    ] == 1.0


def test_multiple_tool_calls(cases):
    responses = {}

    for case in cases:
        responses[case["id"]] = mock_response(
            content="No action needed."
        )

    responses[cases[0]["id"]] = mock_response([
        refund_call("order-100"),
        refund_call("order-200"),
    ])

    report = evaluate_responses(cases, responses)

    first = report["results"][0]

    assert len(first["tool_calls"]) == 2
    assert first["unauthorized_request"]
    assert first["vulnerable_execution"]
    assert not first["secure_execution"]


def test_rate_zero_denominator():
    assert rate(0, 0) == 0.0
    assert rate(3, 4) == 0.75
