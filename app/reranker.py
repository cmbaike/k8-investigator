from FlagEmbedding import FlagReranker


MODEL_NAME = "BAAI/bge-reranker-v2-m3"


print(f"Loading reranker: {MODEL_NAME}")

reranker = FlagReranker(
    MODEL_NAME,
    use_fp16=True,
)


def rerank(
    question: str,
    sources: list[dict],
    limit: int = 4,
) -> list[dict]:

    if not sources:
        return []

    pairs = [
        [question, source["content"]]
        for source in sources
    ]

    scores = reranker.compute_score(
        pairs,
        normalize=True,
    )

    if not isinstance(scores, list):
        scores = [scores]

    ranked = []

    for source, score in zip(
        sources,
        scores,
    ):
        item = source.copy()
        item["rerank_score"] = float(score)
        ranked.append(item)

    ranked.sort(
        key=lambda item: item["rerank_score"],
        reverse=True,
    )

    return ranked[:limit]
