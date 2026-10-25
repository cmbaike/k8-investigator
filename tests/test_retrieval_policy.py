from unittest.mock import patch

from app.rag import retrieve_evidence


def test_retrieve_evidence_reranks_candidates():
    candidates = [
        {
            "content": f"candidate {i}",
            "similarity": 0.5,
        }
        for i in range(12)
    ]

    reranked = candidates[:4]

    with (
        patch(
            "app.rag.retrieve",
            return_value=candidates,
        ) as retrieve_mock,
        patch(
            "app.rag.rerank",
            return_value=reranked,
        ) as rerank_mock,
    ):
        result = retrieve_evidence("test question")

    retrieve_mock.assert_called_once_with(
        "test question",
        limit=12,
    )

    rerank_mock.assert_called_once_with(
        "test question",
        candidates,
        limit=4,
    )

    assert result == reranked
