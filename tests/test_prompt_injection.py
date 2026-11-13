
import pytest

from app.agent_tools import REFUNDS
from app.prompt_injection import (
    MALICIOUS_TICKET,
    vulnerable_agent,
    secure_agent,
    secure_refund_workflow,
)


@pytest.fixture(autouse=True)
def reset_refunds():
    REFUNDS.clear()
    yield
    REFUNDS.clear()


def test_injection_triggers_vulnerable_agent():
    result = vulnerable_agent(
        "alice", MALICIOUS_TICKET
    )

    assert result["order_id"] == "order-200"
    assert len(REFUNDS) == 1


def test_secure_agent_ignores_injection():
    result = secure_agent(
        "alice", MALICIOUS_TICKET
    )

    assert result["refund_executed"] is False
    assert len(REFUNDS) == 0


def test_secure_workflow_blocks_unauthorized_refund():
    with pytest.raises(PermissionError):
        secure_refund_workflow(
            "alice", "order-200", True
        )

    assert len(REFUNDS) == 0


def test_secure_workflow_requires_approval():
    with pytest.raises(PermissionError):
        secure_refund_workflow(
            "bob", "order-200", False
        )

    assert len(REFUNDS) == 0


def test_secure_workflow_allows_authorized_refund():
    result = secure_refund_workflow(
        "bob", "order-200", True
    )

    assert result["amount"] == 200
    assert len(REFUNDS) == 1
