
"""
Exercise 6: AI Tool-Call Security Evaluation

Evaluate a secure tool executor against a labeled
dataset and calculate classification metrics.
"""

import json
from pathlib import Path

from app.tool_executor import (
    secure_executor,
    reset_state,
)


BASE_DIR = Path(__file__).resolve().parent.parent

DATASET = BASE_DIR / "datasets" / "tool_call_cases.json"
REPORT = BASE_DIR / "reports" / "tool_call_evaluation.json"


def load_cases(path=DATASET):
    with open(path, encoding="utf-8") as file:
        cases = json.load(file)

    if not isinstance(cases, list):
        raise ValueError("Dataset must contain a JSON list")

    if not cases:
        raise ValueError("Dataset cannot be empty")

    return cases


def evaluate_cases(cases, executor=secure_executor):
    results = []

    tp = 0
    fp = 0
    fn = 0
    tn = 0

    for case in cases:
        # Each scenario must run independently.
        reset_state()

        expected_status = case["expected_status"]

        try:
            response = executor(
                case["user_id"],
                case["tool_call"],
            )
            actual_status = response["status"]

        except Exception as exc:
            actual_status = "execution_error"
            response = {
                "status": actual_status,
                "error": type(exc).__name__,
            }

        # Positive class: requests that should be blocked.
        expected_block = expected_status != "success"
        actual_block = actual_status != "success"

        if expected_block and actual_block:
            classification = "TP"
            tp += 1

        elif not expected_block and actual_block:
            classification = "FP"
            fp += 1

        elif expected_block and not actual_block:
            classification = "FN"
            fn += 1

        else:
            classification = "TN"
            tn += 1

        results.append({
            "id": case["id"],
            "description": case["description"],
            "expected_status": expected_status,
            "actual_status": actual_status,
            "exact_match": actual_status == expected_status,
            "classification": classification,
        })

    total = len(results)

    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0

    f1 = (
        2 * precision * recall / (precision + recall)
        if precision + recall else 0.0
    )

    accuracy = (tp + tn) / total if total else 0.0

    exact_matches = sum(
        result["exact_match"] for result in results
    )

    reset_state()

    return {
        "total_cases": total,
        "confusion_matrix": {
            "TP": tp,
            "FP": fp,
            "FN": fn,
            "TN": tn,
        },
        "metrics": {
            "precision": precision,
            "recall": recall,
            "f1_score": f1,
            "accuracy": accuracy,
            "exact_status_accuracy": (
                exact_matches / total if total else 0.0
            ),
        },
        "results": results,
    }


def main():
    cases = load_cases()

    report = evaluate_cases(cases)

    REPORT.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    REPORT.write_text(
        json.dumps(report, indent=2),
        encoding="utf-8",
    )

    print(json.dumps({
        "total_cases": report["total_cases"],
        "confusion_matrix": report["confusion_matrix"],
        "metrics": report["metrics"],
    }, indent=2))

    print(f"\nReport saved to: {REPORT}")


if __name__ == "__main__":
    main()
