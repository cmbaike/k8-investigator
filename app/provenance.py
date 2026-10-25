def source_label(source: dict) -> str:
    if source["page_number"] is not None:
        return (
            f"{source['filename']}"
            f"#page-{source['page_number']}"
            f"-chunk-{source['chunk_index']}"
        )

    return (
        f"{source['filename']}"
        f"#chunk-{source['chunk_index']}"
    )
