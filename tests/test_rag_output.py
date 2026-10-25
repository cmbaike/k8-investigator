from app.rag import strip_think_blocks


def test_strip_think_blocks():
    text = (
        "<think>\n"
        "internal reasoning that must not be exposed\n"
        "</think>\n\n"
        "The supported answer. [SOURCE: runbook#page-1-chunk-0]"
    )

    assert strip_think_blocks(text) == (
        "The supported answer. "
        "[SOURCE: runbook#page-1-chunk-0]"
    )


def test_preserves_answer_without_think_block():
    text = "Grounded answer. [SOURCE: runbook#page-1-chunk-0]"

    assert strip_think_blocks(text) == text
