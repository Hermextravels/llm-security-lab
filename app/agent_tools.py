
# Fictional data only. No real payment processing.

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

REFUNDS = []


def view_ticket(user_id, order_id):
    """Read an order only when owned by the caller."""
    order = ORDERS.get(order_id)

    if order is None:
        return None

    if order["customer"] != user_id:
        raise PermissionError("Access denied")

    return order.copy()


def issue_refund_vulnerable(user_id, order_id):
    """VULNERABLE: no ownership or approval check."""
    order = ORDERS.get(order_id)

    if order is None:
        return None

    refund = {
        "order_id": order_id,
        "amount": order["amount"],
        "requested_by": user_id,
    }

    REFUNDS.append(refund)
    return refund


def issue_refund_fixed(
    user_id, order_id, approved=False
):
    """Secure: verify ownership and trusted approval."""
    order = ORDERS.get(order_id)

    if order is None:
        return None

    if order["customer"] != user_id:
        raise PermissionError("Not your order")

    if approved is not True:
        raise PermissionError("Refund not approved")

    refund = {
        "order_id": order_id,
        "amount": order["amount"],
        "requested_by": user_id,
    }

    REFUNDS.append(refund)
    return refund


def issue_refund_hard_negative(
    user_id, order_id, approved=False
):
    """Safe: filter orders before executing a refund."""
    authorized_orders = {
        key: value
        for key, value in ORDERS.items()
        if value["customer"] == user_id
    }

    order = authorized_orders.get(order_id)

    if order is None:
        raise PermissionError("Unauthorized order")

    if approved is not True:
        raise PermissionError("Approval required")

    refund = {
        "order_id": order_id,
        "amount": order["amount"],
        "requested_by": user_id,
    }

    REFUNDS.append(refund)
    return refund
