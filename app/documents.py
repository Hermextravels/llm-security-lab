
DOCUMENTS = {
    "doc-001": {
        "owner": "alice",
        "content": "Alice's private financial report",
    },
    "doc-002": {
        "owner": "bob",
        "content": "Bob's confidential customer records",
    },
}


def get_document_vulnerable(user_id: str, document_id: str):
    """Vulnerable: ignores the requesting user's identity."""
    document = DOCUMENTS.get(document_id)

    if document is None:
        return None

    return document["content"]


def get_document_fixed(user_id: str, document_id: str):
    """Secure: checks ownership before returning content."""
    document = DOCUMENTS.get(document_id)

    if document is None:
        return None

    if document["owner"] != user_id:
        raise PermissionError("Access denied")

    return document["content"]


def get_document_hard_negative(user_id: str, document_id: str):
    """Safe example: applies authorization before retrieval."""
    permitted = {
        doc_id: document
        for doc_id, document in DOCUMENTS.items()
        if document["owner"] == user_id
    }

    document = permitted.get(document_id)

    if document is None:
        return None

    return document["content"]
