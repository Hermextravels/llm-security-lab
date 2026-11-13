
import pytest

from app.agent_tools import (
    REFUNDS,
    view_ticket,
    issue_refund_vulnerable,
    issue_refund_fixed,
    issue_refund_hard_negative,
)


@pytest.fixture(autouse=True)
def reset_refunds():
    REFUNDS.clear()
    yield
    REFUNDS.clear()


def test_ticket_authorized():
    result = view_ticket("alice", "order-100")
    assert result["customer"] == "alice"


def test_ticket_unauthorized():
    with pytest.raises(PermissionError):
        view_ticket("alice", "order-200")


def test_vulnerable_unauthorized_refund():
    result = issue_refund_vulnerable(
        "alice", "order-200"
    )

    assert result["amount"] == 200
    assert len(REFUNDS) == 1


def test_fixed_blocks_other_users_order():
    with pytest.raises(PermissionError):
        issue_refund_fixed(
            "alice", "order-200", approved=True
        )

    assert len(REFUNDS) == 0


def test_fixed_requires_approval():
    with pytest.raises(PermissionError):
        issue_refund_fixed(
            "alice", "order-100", approved=False
        )

    assert len(REFUNDS) == 0


def test_fixed_allows_authorized_refund():
    result = issue_refund_fixed(
        "alice", "order-100", approved=True
    )

    assert result["amount"] == 50
    assert len(REFUNDS) == 1


def test_hard_negative_blocks_unauthorized():
    with pytest.raises(PermissionError):
        issue_refund_hard_negative(
            "alice", "order-200", approved=True
        )

    assert len(REFUNDS) == 0


def test_hard_negative_allows_authorized():
    result = issue_refund_hard_negative(
        "bob", "order-200", approved=True
    )

    assert result["amount"] == 200
    assert len(REFUNDS) == 1
