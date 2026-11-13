
import pytest

from app.documents import (
    get_document_vulnerable,
    get_document_fixed,
    get_document_hard_negative,
)


def test_vulnerable_information_disclosure():
    result = get_document_vulnerable("alice", "doc-002")

    assert result == "Bob's confidential customer records"


def test_fixed_blocks_unauthorized_access():
    with pytest.raises(PermissionError):
        get_document_fixed("alice", "doc-002")


def test_fixed_allows_authorized_access():
    result = get_document_fixed("bob", "doc-002")

    assert result == "Bob's confidential customer records"


def test_hard_negative_blocks_unauthorized_access():
    result = get_document_hard_negative("alice", "doc-002")

    assert result is None


def test_hard_negative_allows_authorized_access():
    result = get_document_hard_negative("bob", "doc-002")

    assert result == "Bob's confidential customer records"
