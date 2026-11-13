
from app.tool_call_evaluator import (
    load_cases,
    evaluate_cases,
)


def test_dataset_contains_seven_cases():
    cases = load_cases()

    assert len(cases) == 7


def test_dataset_has_allowed_and_blocked_cases():
    cases = load_cases()

    assert any(
        case["expected_status"] == "success"
        for case in cases
    )

    assert any(
        case["expected_status"] != "success"
        for case in cases
    )


def test_secure_executor_has_no_false_negatives():
    report = evaluate_cases(load_cases())

    assert report["confusion_matrix"]["FN"] == 0


def test_secure_executor_has_no_false_positives():
    report = evaluate_cases(load_cases())

    assert report["confusion_matrix"]["FP"] == 0


def test_secure_executor_matches_expected_statuses():
    report = evaluate_cases(load_cases())

    assert report["metrics"]["exact_status_accuracy"] == 1.0


def test_all_cases_are_classified():
    report = evaluate_cases(load_cases())

    counts = report["confusion_matrix"]

    assert sum(counts.values()) == report["total_cases"]


def test_evaluator_detects_false_negative():
    def unsafe_executor(user_id, tool_call):
        return {"status": "success"}

    report = evaluate_cases(
        load_cases(),
        executor=unsafe_executor,
    )

    assert report["confusion_matrix"]["FN"] > 0


def test_evaluator_detects_false_positive():
    def overblocking_executor(user_id, tool_call):
        return {"status": "permission_denied"}

    report = evaluate_cases(
        load_cases(),
        executor=overblocking_executor,
    )

    assert report["confusion_matrix"]["FP"] > 0
