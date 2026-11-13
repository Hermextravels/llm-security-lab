
import pytest

from app.taint_analyzer import analyze_source


DIRECT_VULNERABILITY = '''
def process_ticket(ticket):
    order_id = ticket["requested_order"]
    REFUNDS.append(order_id)
'''


INTERPROCEDURAL_VULNERABILITY = '''
def process_ticket(ticket):
    order_id = ticket["requested_order"]
    execute_refund(order_id)

def execute_refund(order_id):
    REFUNDS.append(order_id)
'''


GUARDED_REFUND = '''
def process_ticket(ticket, user_id):
    order_id = ticket["requested_order"]
    order = ORDERS[order_id]

    if order["customer"] != user_id:
        return {"status": "permission_denied"}

    REFUNDS.append(order_id)
'''


INEFFECTIVE_GUARD = '''
def process_ticket(ticket, user_id):
    order_id = ticket["requested_order"]
    order = ORDERS[order_id]

    if order["customer"] != user_id:
        pass

    REFUNDS.append(order_id)
'''


UNTAINTED_REFUND = '''
def system_refund():
    order_id = "order-100"
    REFUNDS.append(order_id)
'''


TAINT_REASSIGNMENT = '''
def process_ticket(ticket):
    order_id = ticket["requested_order"]
    order_id = "order-100"
    REFUNDS.append(order_id)
'''


THREE_FUNCTION_CHAIN = '''
def process_ticket(ticket):
    order_id = ticket["requested_order"]
    intermediate(order_id)

def intermediate(value):
    execute_refund(value)

def execute_refund(order_id):
    REFUNDS.append(order_id)
'''


NO_SINK = '''
def process_ticket(ticket):
    order_id = ticket["requested_order"]
    return {"order_id": order_id}
'''


def find_tainted_sinks(findings):
    return [
        finding
        for finding in findings
        if finding["classification"] == "TAINTED_SINK"
    ]


def test_detects_direct_taint():
    findings = analyze_source(DIRECT_VULNERABILITY)

    assert find_tainted_sinks(findings)


def test_detects_interprocedural_taint():
    findings = analyze_source(
        INTERPROCEDURAL_VULNERABILITY
    )

    assert any(
        finding["classification"] == "TAINTED_SINK"
        and finding["call_path"] == [
            "process_ticket",
            "execute_refund",
        ]
        for finding in findings
    )


def test_recognizes_guarded_taint():
    findings = analyze_source(GUARDED_REFUND)

    assert any(
        finding["classification"]
        == "GUARDED_TAINTED_SINK"
        for finding in findings
    )


def test_ineffective_guard_is_not_accepted():
    findings = analyze_source(INEFFECTIVE_GUARD)

    assert find_tainted_sinks(findings)


def test_untainted_sink_is_informational():
    findings = analyze_source(UNTAINTED_REFUND)

    assert any(
        finding["classification"] == "UNTAINTED_SINK"
        for finding in findings
    )


def test_reassignment_clears_taint():
    findings = analyze_source(TAINT_REASSIGNMENT)

    assert not find_tainted_sinks(findings)


def test_tracks_three_function_chain():
    findings = analyze_source(THREE_FUNCTION_CHAIN)

    assert any(
        finding["call_path"] == [
            "process_ticket",
            "intermediate",
            "execute_refund",
        ]
        and finding["classification"] == "TAINTED_SINK"
        for finding in findings
    )


def test_no_sink_returns_no_findings():
    findings = analyze_source(NO_SINK)

    assert findings == []


def test_invalid_python_raises_error():
    with pytest.raises(SyntaxError):
        analyze_source("def broken(")


def test_finding_contains_line_and_severity():
    findings = analyze_source(DIRECT_VULNERABILITY)

    finding = find_tainted_sinks(findings)[0]

    assert finding["line"] > 0
    assert finding["severity"] == "HIGH"
    assert finding["sink"] == "REFUNDS.append"
