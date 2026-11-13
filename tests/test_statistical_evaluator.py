
import pytest

from app.statistical_evaluator import (
    zero_failure_upper_bound,
    evaluate_failures,
    evaluate_coverage,
)


def test_twenty_zero_failures():
    bound = zero_failure_upper_bound(20)
    assert 0.139 < bound < 0.140


def test_one_hundred_zero_failures():
    bound = zero_failure_upper_bound(100)
    assert 0.029 < bound < 0.030


def test_more_tests_reduce_upper_bound():
    assert (
        zero_failure_upper_bound(1000)
        < zero_failure_upper_bound(100)
    )


def test_observed_failure_rate():
    result = evaluate_failures(500, 120)
    assert result["observed_failure_rate"] == 0.24
    assert result["zero_failure_upper_bound"] is None


def test_zero_failures_have_bound():
    result = evaluate_failures(100, 0)
    assert result["zero_failure_upper_bound"] is not None


def test_invalid_attempt_count():
    with pytest.raises(ValueError):
        evaluate_failures(0, 0)


def test_invalid_failure_count():
    with pytest.raises(ValueError):
        evaluate_failures(10, 11)


def test_partial_coverage():
    cases = [
        {"category": "role_spoofing"},
        {"category": "direct_prompt_injection"},
    ]

    result = evaluate_coverage(cases)

    assert result["covered_categories"] == 2
    assert result["coverage_rate"] == pytest.approx(2 / 7)
    assert "argument_manipulation" in result[
        "missing_categories"
    ]


def test_complete_coverage():
    categories = [
        "direct_prompt_injection",
        "indirect_prompt_injection",
        "role_spoofing",
        "tool_output_laundering",
        "multi_turn_manipulation",
        "cross_user_authorization",
        "argument_manipulation",
    ]

    result = evaluate_coverage([
        {"category": category}
        for category in categories
    ])

    assert result["coverage_rate"] == 1.0
    assert result["missing_categories"] == []


def test_empty_coverage():
    result = evaluate_coverage([])
    assert result["coverage_rate"] == 0.0
