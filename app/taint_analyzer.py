
"""
Exercise 8: Educational Interprocedural Taint Analyzer.

Tracks selected untrusted inputs through:
- Variable assignments
- Dictionary/subscript access
- Calls to functions in the same module
- REFUNDS.append(...) sensitive sinks

Recognizes one narrow ownership-denial guard pattern.

This is not a production-grade taint analyzer.
It does not prove authorization correctness.
"""

import ast
import json
import sys
from pathlib import Path


SOURCE_PARAMETERS = {
    "ticket",
    "tool_call",
    "request",
    "user_input",
}

MAX_CALL_DEPTH = 12


def expression_tainted(node, tainted):
    """Check whether an expression uses a tainted variable."""
    if isinstance(node, ast.Name):
        return node.id in tainted

    return any(
        expression_tainted(child, tainted)
        for child in ast.iter_child_nodes(node)
    )


def is_refund_sink(node):
    return (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "append"
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id == "REFUNDS"
    )


def is_ownership_denial(test):
    """
    Recognize:
        order["customer"] != user_id
        order["owner"] != user_id

    This is a syntactic heuristic.
    """
    if not isinstance(test, ast.Compare):
        return False

    if len(test.ops) != 1:
        return False

    if not isinstance(test.ops[0], ast.NotEq):
        return False

    expressions = [test.left, *test.comparators]

    has_user = any(
        isinstance(expr, ast.Name)
        and expr.id == "user_id"
        for expr in expressions
    )

    has_owner = any(
        isinstance(expr, ast.Subscript)
        and isinstance(expr.slice, ast.Constant)
        and expr.slice.value in {"customer", "owner"}
        for expr in expressions
    )

    return has_user and has_owner


def is_terminal_denial(body):
    """
    Recognize a denial that ends the branch.

    An unconditional final return or raise is required.
    """
    return bool(body) and isinstance(
        body[-1],
        (ast.Return, ast.Raise),
    )


class TaintAnalyzer:
    def __init__(self, source):
        self.tree = ast.parse(source)
        self.functions = {
            node.name: node
            for node in self.tree.body
            if isinstance(
                node,
                (ast.FunctionDef, ast.AsyncFunctionDef),
            )
        }
        self.findings = []
        self.seen = set()

    def record_finding(
        self,
        function_name,
        node,
        tainted,
        guarded,
        call_path,
    ):
        key = (
            function_name,
            node.lineno,
            tainted,
            guarded,
            tuple(call_path),
        )

        if key in self.seen:
            return

        self.seen.add(key)

        if not tainted:
            classification = "UNTAINTED_SINK"
            severity = "INFO"
        elif guarded:
            classification = "GUARDED_TAINTED_SINK"
            severity = "REVIEW"
        else:
            classification = "TAINTED_SINK"
            severity = "HIGH"

        self.findings.append({
            "function": function_name,
            "line": node.lineno,
            "sink": "REFUNDS.append",
            "tainted": tainted,
            "ownership_guard_detected": guarded,
            "classification": classification,
            "severity": severity,
            "call_path": list(call_path),
        })

    def analyze_function(
        self,
        name,
        initial_taint=None,
        guarded=False,
        call_path=None,
    ):
        if name not in self.functions:
            return

        if initial_taint is None:
            initial_taint = set()

        if call_path is None:
            call_path = []

        if name in call_path:
            return

        if len(call_path) >= MAX_CALL_DEPTH:
            return

        function = self.functions[name]

        tainted = set(initial_taint)

        # Entry-point parameters are treated as sources.
        if not call_path:
            for arg in function.args.args:
                if arg.arg in SOURCE_PARAMETERS:
                    tainted.add(arg.arg)

        current_path = [*call_path, name]

        self.analyze_block(
            function.body,
            tainted,
            guarded,
            name,
            current_path,
        )

    def analyze_block(
        self,
        statements,
        tainted,
        guarded,
        function_name,
        call_path,
    ):
        current_guard = guarded

        for statement in statements:
            if isinstance(statement, ast.Assign):
                value_tainted = expression_tainted(
                    statement.value,
                    tainted,
                )

                for target in statement.targets:
                    if isinstance(target, ast.Name):
                        if value_tainted:
                            tainted.add(target.id)
                        else:
                            tainted.discard(target.id)

                self.inspect_calls(
                    statement.value,
                    tainted,
                    current_guard,
                    function_name,
                    call_path,
                )

            elif isinstance(statement, ast.AnnAssign):
                value_tainted = (
                    statement.value is not None
                    and expression_tainted(
                        statement.value,
                        tainted,
                    )
                )

                if isinstance(statement.target, ast.Name):
                    if value_tainted:
                        tainted.add(statement.target.id)
                    else:
                        tainted.discard(statement.target.id)

                if statement.value is not None:
                    self.inspect_calls(
                        statement.value,
                        tainted,
                        current_guard,
                        function_name,
                        call_path,
                    )

            elif isinstance(statement, ast.Expr):
                self.inspect_calls(
                    statement.value,
                    tainted,
                    current_guard,
                    function_name,
                    call_path,
                )

            elif isinstance(statement, ast.If):
                # Analyze the branch independently.
                self.analyze_block(
                    statement.body,
                    set(tainted),
                    current_guard,
                    function_name,
                    call_path,
                )

                if statement.orelse:
                    self.analyze_block(
                        statement.orelse,
                        set(tainted),
                        current_guard,
                        function_name,
                        call_path,
                    )

                # A recognized denial branch establishes
                # a guard for subsequent statements.
                if (
                    not statement.orelse
                    and is_ownership_denial(statement.test)
                    and is_terminal_denial(statement.body)
                ):
                    current_guard = True

            elif isinstance(statement, ast.Return):
                if statement.value is not None:
                    self.inspect_calls(
                        statement.value,
                        tainted,
                        current_guard,
                        function_name,
                        call_path,
                    )

            # Loops, exceptions, comprehensions, dynamic
            # dispatch and complex control flow are not
            # modeled by this educational implementation.

    def inspect_calls(
        self,
        expression,
        tainted,
        guarded,
        function_name,
        call_path,
    ):
        for node in ast.walk(expression):
            if not isinstance(node, ast.Call):
                continue

            if is_refund_sink(node):
                sink_tainted = any(
                    expression_tainted(arg, tainted)
                    for arg in node.args
                )

                self.record_finding(
                    function_name,
                    node,
                    sink_tainted,
                    guarded,
                    call_path,
                )

            elif (
                isinstance(node.func, ast.Name)
                and node.func.id in self.functions
            ):
                callee = self.functions[node.func.id]
                parameters = [
                    arg.arg
                    for arg in callee.args.args
                ]

                propagated = set()

                for parameter, argument in zip(
                    parameters,
                    node.args,
                ):
                    if expression_tainted(
                        argument,
                        tainted,
                    ):
                        propagated.add(parameter)

                self.analyze_function(
                    node.func.id,
                    initial_taint=propagated,
                    guarded=guarded,
                    call_path=call_path,
                )

    def run(self):
        for name in self.functions:
            self.analyze_function(name)

        return sorted(
            self.findings,
            key=lambda finding: (
                finding["line"],
                finding["function"],
                finding["classification"],
            ),
        )


def analyze_source(source):
    return TaintAnalyzer(source).run()


def analyze_file(path):
    source = Path(path).read_text(
        encoding="utf-8"
    )
    return analyze_source(source)


def main():
    if len(sys.argv) != 2:
        print(
            "Usage: python -m app.taint_analyzer "
            "<python_file>"
        )
        return 2

    path = Path(sys.argv[1])

    if not path.is_file():
        print(f"File not found: {path}")
        return 2

    try:
        findings = analyze_file(path)
    except (SyntaxError, OSError) as exc:
        print(f"Analysis failed: {exc}")
        return 2

    print(json.dumps({
        "file": str(path),
        "total_findings": len(findings),
        "findings": findings,
    }, indent=2))

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
