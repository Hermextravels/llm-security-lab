
"""
Exercise 5: AI Tool-Calling Security

All orders, refunds, and approvals are fictional.
This module does not process real payments.
"""

from copy import deepcopy


ORDERS = {
    "order-100": {
        "customer": "alice",
        "amount": 50,
    },
    "order-200": {
        "customer": "bob",
        "amount": 200,
    },
}

# Trusted server-side approval records.
# The LLM cannot modify these through tool arguments.
APPROVALS = {
    "order-100": {
        "approved": True,
        "approved_for": "alice",
    },
    "order-200": {
        "approved": False,
        "approved_for": "bob",
    },
}

REFUNDS = []
AUDIT_LOG = []


def reset_state():
    """Reset mutable state between test scenarios."""
    REFUNDS.clear()
    AUDIT_LOG.clear()


def vulnerable_executor(user_id, tool_call):
    """
    VULNERABLE:
    Executes model-requested refunds without authorization.
    """
    tool_name = tool_call.get("tool")
    arguments = tool_call.get("arguments", {})

    if tool_name != "issue_refund":
        return {"status": "unsupported_tool"}

    order_id = arguments.get("order_id")
    order = ORDERS.get(order_id)

    if order is None:
        return {"status": "order_not_found"}

    refund = {
        "order_id": order_id,
        "amount": order["amount"],
        "requested_by": user_id,
    }

    REFUNDS.append(refund)

    AUDIT_LOG.append({
        "user_id": user_id,
        "tool": tool_name,
        "order_id": order_id,
        "decision": "executed_without_authorization",
    })

    return {
        "status": "success",
        "refund": deepcopy(refund),
    }


def secure_executor(user_id, tool_call):
    """
    SECURE:
    Validates tool arguments, ownership,
    and trusted server-side approval.
    """
    if not isinstance(tool_call, dict):
        return {"status": "invalid_tool_call"}

    tool_name = tool_call.get("tool")
    arguments = tool_call.get("arguments")

    if tool_name != "issue_refund":
        return {"status": "unsupported_tool"}

    if not isinstance(arguments, dict):
        return {"status": "invalid_arguments"}

    # Strict allowlist prevents the LLM from
    # injecting approval or identity claims.
    if set(arguments) != {"order_id"}:
        return {"status": "invalid_arguments"}

    order_id = arguments["order_id"]

    if not isinstance(order_id, str):
        return {"status": "invalid_arguments"}

    order = ORDERS.get(order_id)

    if order is None:
        return {"status": "order_not_found"}

    # Identity is supplied by trusted application code,
    # not by the LLM's tool arguments.
    if order["customer"] != user_id:
        AUDIT_LOG.append({
            "user_id": user_id,
            "tool": tool_name,
            "order_id": order_id,
            "decision": "denied_ownership",
        })

        return {"status": "permission_denied"}

    # Approval is checked against server-side records.
    approval = APPROVALS.get(order_id)

    if (
        approval is None
        or approval["approved"] is not True
        or approval["approved_for"] != user_id
    ):
        AUDIT_LOG.append({
            "user_id": user_id,
            "tool": tool_name,
            "order_id": order_id,
            "decision": "denied_approval",
        })

        return {"status": "approval_required"}

    refund = {
        "order_id": order_id,
        "amount": order["amount"],
        "requested_by": user_id,
    }

    REFUNDS.append(refund)

    AUDIT_LOG.append({
        "user_id": user_id,
        "tool": tool_name,
        "order_id": order_id,
        "decision": "authorized_execution",
    })

    return {
        "status": "success",
        "refund": deepcopy(refund),
    }


def simulate_model_tool_call(ticket_text):
    """
    Offline simulation of a model's tool-call output.

    This is deterministic and does not invoke an LLM.
    """
    text = ticket_text.lower()

    if "refund" in text:
        return {
            "tool": "issue_refund",
            "arguments": {
                "order_id": "order-200",
            },
        }

    return {
        "tool": "summarize_ticket",
        "arguments": {},
    }
