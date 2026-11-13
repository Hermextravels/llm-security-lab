
"""
Exercise 7: Source-to-Sink Security Scanner

An educational AST-based static analyzer.

Detects:
- Selected attacker-controlled tool-call sources
- REFUNDS.append(...) as a sensitive sink
- Missing recognizable ownership guards
- Possible authorization bypasses

Limitations:
- Not a full taint-analysis engine
- Does not prove exploitability
- Does not validate runtime authentication
- Does not analyze imported functions
"""

import ast
import json
import sys
from pathlib import Path


SINK_OBJECT = "REFUNDS"
SINK_METHOD = "append"


def is_refund_sink(node):
    """Identify REFUNDS.append(...) calls."""
    return (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == SINK_METHOD
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id == SINK_OBJECT
    )


def is_tool_call_source(node):
    """
    Recognize direct access to tool_call arguments.

    This is a syntactic source heuristic, not
    a complete data-flow analysis.
    """
    return (
        isinstance(node, ast.Subscript)
        and isinstance(node.value, ast.Name)
        and node.value.id == "tool_call"
    )


def has_tool_call_reference(function):
    return any(
        is_tool_call_source(node)
        for node in ast.walk(function)
    )


def is_ownership_comparison(node):
    """
    Recognize comparisons involving:
    - user_id
    - customer or owner

    This only identifies a potential guard.
    """
    if not isinstance(node, ast.Compare):
        return False

    names = {
        child.id
        for child in ast.walk(node)
        if isinstance(child, ast.Name)
    }

    strings = {
        child.value
        for child in ast.walk(node)
        if isinstance(child, ast.Constant)
        and isinstance(child.value, str)
    }

    return (
        "user_id" in names
        and bool({"customer", "owner"} & strings)
        and any(
            isinstance(op, (ast.Eq, ast.NotEq))
            for op in node.ops
        )
    )


def is_denial_statement(node):
    """Recognize a return or exception as a denial."""
    return isinstance(node, (ast.Return, ast.Raise))


def has_denial_guard(function, sink):
    """
    Recognize a narrow ownership-check pattern:

        if order["customer"] != user_id:
            return ...

        REFUNDS.append(...)

    The guard must precede the sink in the
    same statement block.

    This does not prove the guard is correct.
    """
    for node in ast.walk(function):
        if not isinstance(node, (ast.Module, ast.FunctionDef, ast.If)):
            continue

        body = getattr(node, "body", [])

        if not isinstance(body, list):
            continue

        for index, statement in enumerate(body):
            if not isinstance(statement, ast.If):
                continue

            if not is_ownership_comparison(statement.test):
                continue

            if not any(
                is_denial_statement(child)
                for child in statement.body
            ):
                continue

            # Only count the guard if the sink occurs
            # in a later statement of this same block.
            for later in body[index + 1:]:
                if any(
                    child is sink
                    for child in ast.walk(later)
                ):
                    return True

    return False


def analyze_function(function, filename):
    findings = []

    # Avoid attributing nested function sinks
    # to their enclosing function.
    nodes = []

    def collect(node):
        nodes.append(node)

        for child in ast.iter_child_nodes(node):
            if isinstance(
                child,
                (ast.FunctionDef, ast.AsyncFunctionDef)
            ):
                continue

            collect(child)

    collect(function)

    sinks = [
        node for node in nodes
        if is_refund_sink(node)
    ]

    if not sinks:
        return findings

    source_detected = has_tool_call_reference(function)

    for sink in sinks:
        ownership_guard = has_denial_guard(
            function,
            sink,
        )

        if ownership_guard:
            classification = "REVIEW"
            severity = "INFO"
            description = (
                "Refund sink has a recognizable "
                "ownership guard. Manual review "
                "is still required."
            )
        else:
            classification = "POTENTIAL_VULNERABILITY"
            severity = "HIGH"
            description = (
                "Refund sink lacks a recognizable "
                "ownership guard."
            )

        findings.append({
            "file": str(filename),
            "function": function.name,
            "line": sink.lineno,
            "source_detected": source_detected,
            "source": (
                "tool_call"
                if source_detected
                else "unknown"
            ),
            "sink": "REFUNDS.append",
            "ownership_guard_detected": ownership_guard,
            "classification": classification,
            "severity": severity,
            "description": description,
        })

    return findings


def scan_source(source_code, filename="<memory>"):
    """Scan Python source without executing it."""
    tree = ast.parse(source_code, filename=filename)

    findings = []

    for node in ast.walk(tree):
        if isinstance(
            node,
            (ast.FunctionDef, ast.AsyncFunctionDef)
        ):
            findings.extend(
                analyze_function(node, filename)
            )

    return findings


def scan_file(path):
    path = Path(path)

    source = path.read_text(encoding="utf-8")

    return scan_source(
        source,
        filename=str(path),
    )


def main():
    if len(sys.argv) < 2:
        print(
            "Usage: python -m app.source_sink_scanner "
            "<python_file>"
        )
        return 2

    path = Path(sys.argv[1])

    if not path.is_file():
        print(f"File not found: {path}")
        return 2

    try:
        findings = scan_file(path)
    except (SyntaxError, OSError) as exc:
        print(f"Scan failed: {exc}")
        return 2

    print(json.dumps({
        "file": str(path),
        "total_findings": len(findings),
        "findings": findings,
    }, indent=2))

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
