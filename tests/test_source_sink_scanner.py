
import pytest

from app.source_sink_scanner import scan_source


VULNERABLE_CODE = '''
def process_tool_call(user_id, tool_call):
    order_id = tool_call["arguments"]["order_id"]
    order = ORDERS[order_id]

    REFUNDS.append({
        "order_id": order_id,
        "amount": order["amount"]
    })

    return {"status": "success"}
'''


SECURE_CODE = '''
def process_tool_call(user_id, tool_call):
    order_id = tool_call["arguments"]["order_id"]
    order = ORDERS[order_id]

    if order["customer"] != user_id:
        return {"status": "permission_denied"}

    REFUNDS.append({
        "order_id": order_id,
        "amount": order["amount"]
    })

    return {"status": "success"}
'''


NO_SINK_CODE = '''
def summarize_ticket(user_id, tool_call):
    return {
        "summary": "Ticket received"
    }
'''


MISSING_GUARD_CODE = '''
def issue_refund(user_id, tool_call):
    order_id = tool_call["arguments"]["order_id"]

    REFUNDS.append({
        "order_id": order_id
    })
'''


FALSE_POSITIVE_EXAMPLE = '''
def admin_refund(user_id, tool_call):
    # Imagine an independent authorization
    # decorator protects this endpoint.
    REFUNDS.append({
        "order_id": "order-100"
    })
'''


FALSE_NEGATIVE_EXAMPLE = '''
def issue_refund(user_id, tool_call):
    order_id = tool_call["arguments"]["order_id"]
    order = ORDERS[order_id]

    if order["customer"] != user_id:
        pass

    REFUNDS.append({
        "order_id": order_id
    })
'''


def test_detects_vulnerable_refund():
    findings = scan_source(VULNERABLE_CODE)

    assert len(findings) == 1

    finding = findings[0]

    assert finding["classification"] == (
        "POTENTIAL_VULNERABILITY"
    )
    assert finding["severity"] == "HIGH"


def test_identifies_untrusted_source():
    findings = scan_source(VULNERABLE_CODE)

    assert findings[0]["source_detected"] is True
    assert findings[0]["source"] == "tool_call"


def test_identifies_sensitive_sink():
    findings = scan_source(VULNERABLE_CODE)

    assert findings[0]["sink"] == "REFUNDS.append"


def test_recognizes_ownership_guard():
    findings = scan_source(SECURE_CODE)

    assert len(findings) == 1
    assert findings[0]["ownership_guard_detected"] is True
    assert findings[0]["classification"] == "REVIEW"


def test_no_sink_produces_no_findings():
    findings = scan_source(NO_SINK_CODE)

    assert findings == []


def test_missing_guard_is_flagged():
    findings = scan_source(MISSING_GUARD_CODE)

    assert findings[0]["classification"] == (
        "POTENTIAL_VULNERABILITY"
    )


def test_finding_has_line_number():
    findings = scan_source(VULNERABLE_CODE)

    assert findings[0]["line"] > 0


def test_finding_identifies_function():
    findings = scan_source(VULNERABLE_CODE)

    assert findings[0]["function"] == (
        "process_tool_call"
    )


def test_scanner_does_not_execute_code():
    code = '''
raise RuntimeError("Must not execute")

def unsafe(user_id, tool_call):
    REFUNDS.append({"order_id": "order-200"})
'''

    findings = scan_source(code)

    assert len(findings) == 1


def test_possible_false_positive():
    """
    The scanner cannot inspect authorization
    performed by an external decorator.
    """
    findings = scan_source(FALSE_POSITIVE_EXAMPLE)

    assert findings[0]["classification"] == (
        "POTENTIAL_VULNERABILITY"
    )


def test_possible_false_negative():
    """
    A weak or ineffective ownership check
    must not be treated as secure.
    """
    findings = scan_source(FALSE_NEGATIVE_EXAMPLE)

    assert findings[0]["classification"] == (
        "POTENTIAL_VULNERABILITY"
    )


def test_invalid_python_raises_syntax_error():
    with pytest.raises(SyntaxError):
        scan_source("def broken(")
