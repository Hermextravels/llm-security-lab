
"""Exercise 12: Security evaluation statistics."""

import math
from collections import Counter


REQUIRED_CATEGORIES = {
    "direct_prompt_injection",
    "indirect_prompt_injection",
    "role_spoofing",
    "tool_output_laundering",
    "multi_turn_manipulation",
    "cross_user_authorization",
    "argument_manipulation",
}


def zero_failure_upper_bound(attempts, confidence=0.95):
    """Exact one-sided binomial upper bound for 0 failures."""
    if not isinstance(attempts, int) or attempts <= 0:
        raise ValueError("attempts must be a positive integer")

    if not 0 < confidence < 1:
        raise ValueError("confidence must be between 0 and 1")

    return -math.expm1(
        math.log1p(-confidence) / attempts
    )


def evaluate_failures(attempts, failures, confidence=0.95):
    if not isinstance(attempts, int) or attempts <= 0:
        raise ValueError("attempts must be positive")

    if (
        not isinstance(failures, int)
        or not 0 <= failures <= attempts
    ):
        raise ValueError("Invalid failure count")

    return {
        "attempts": attempts,
        "failures": failures,
        "observed_failure_rate": failures / attempts,
        "zero_failure_upper_bound": (
            zero_failure_upper_bound(attempts, confidence)
            if failures == 0 else None
        ),
        "confidence": confidence,
        "statistical_assumptions": (
            "Independent, identically distributed trials"
        ),
    }


def evaluate_coverage(cases):
    if not isinstance(cases, list):
        raise ValueError("cases must be a list")

    counts = Counter()

    for case in cases:
        if not isinstance(case, dict):
            raise ValueError("Each case must be an object")

        category = case.get("category")

        if not isinstance(category, str):
            raise ValueError("Invalid category")

        counts[category] += 1

    covered = REQUIRED_CATEGORIES & counts.keys()
    missing = REQUIRED_CATEGORIES - covered

    return {
        "required_categories": len(REQUIRED_CATEGORIES),
        "covered_categories": len(covered),
        "coverage_rate": (
            len(covered) / len(REQUIRED_CATEGORIES)
        ),
        "missing_categories": sorted(missing),
        "category_counts": dict(counts),
    }
