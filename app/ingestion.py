import hashlib
import os
import re
from pathlib import Path

import psycopg
import torch
from pgvector.psycopg import register_vector
from pypdf import PdfReader
from sentence_transformers import SentenceTransformer
from dotenv import load_dotenv


load_dotenv()

DATABASE_URL = os.environ["DATABASE_URL"]

EMBEDDING_MODEL = os.getenv(
    "EMBEDDING_MODEL",
    "BAAI/bge-small-en-v1.5",
)

device = "cuda" if torch.cuda.is_available() else "cpu"

embedding_model = SentenceTransformer(
    EMBEDDING_MODEL,
    device=device,
)

HEADING_RE = re.compile(
    r"^(?:\d+\.)+\s+.+$|^\d+\.\s+.+$"
)


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def split_sections(text: str) -> list[str]:
    """
    Split extracted text into logical sections while keeping
    headings attached to the text that follows them.
    """

    lines = [
        line.strip()
        for line in text.splitlines()
    ]

    sections = []
    current = []

    for line in lines:

        if not line:
            if current:
                current.append("")
            continue

        if HEADING_RE.match(line) and current:
            section = "\n".join(current).strip()

            if section:
                sections.append(section)

            current = [line]

        else:
            current.append(line)

    if current:
        section = "\n".join(current).strip()

        if section:
            sections.append(section)

    return sections

def chunk_text(
    text: str,
    max_chars: int = 1400,
) -> list[str]:

    sections = split_sections(text)

    chunks = []

    for section in sections:

        if len(section) <= max_chars:
            chunks.append(section)
            continue

        paragraphs = [
            p.strip()
            for p in section.split("\n\n")
            if p.strip()
        ]

        current = ""

        for paragraph in paragraphs:

            candidate = (
                f"{current}\n\n{paragraph}".strip()
                if current
                else paragraph
            )

            if (
                len(candidate) <= max_chars
            ):
                current = candidate
                continue

            if current:
                chunks.append(current)

            if len(paragraph) <= max_chars:
                current = paragraph
                continue

            # Last-resort split for unusually large paragraphs.
            sentences = re.split(
                r"(?<=[.!?])\s+",
                paragraph,
            )

            current = ""

            for sentence in sentences:

                candidate = (
                    f"{current} {sentence}".strip()
                    if current
                    else sentence
                )

                if len(candidate) <= max_chars:
                    current = candidate
                else:
                    if current:
                        chunks.append(current)

                    current = sentence

        if current:
            chunks.append(current)

    return [
        chunk
        for chunk in chunks
        if chunk.strip()
    ]
    
def clean_extracted_text(text: str) -> str:

    text = re.sub(
        r"Private AI Platform Lab\s*-\s*"
        r"DevOps Production Operations Runbook v1\.0",
        "",
        text,
        flags=re.IGNORECASE,
    )

    text = re.sub(
        r"\bPage\s+\d+\b",
        "",
        text,
        flags=re.IGNORECASE,
    )

    text = re.sub(
        r"[ \t]+",
        " ",
        text,
    )

    text = re.sub(
        r"\n{3,}",
        "\n\n",
        text,
    )

    return text.strip()    


def extract_pages(
    filename: str,
    data: bytes,
) -> list[tuple[int | None, str]]:

    suffix = Path(filename).suffix.lower()

    if suffix in {".txt", ".md"}:
        text = data.decode("utf-8")
        return [(None, text)]

    if suffix == ".pdf":
        from io import BytesIO

        reader = PdfReader(BytesIO(data))

        pages = []

        for page_number, page in enumerate(reader.pages, start=1):
            text = page.extract_text() or ""

            if text.strip():
                pages.append(
                    (page_number, text)
                )

        return pages

    raise ValueError(
        f"Unsupported file type: {suffix}"
    )


def ingest_document(
    filename: str,
    content_type: str,
    data: bytes,
) -> dict:

    file_hash = sha256_bytes(data)

    with psycopg.connect(DATABASE_URL) as conn:
        register_vector(conn)

        with conn.cursor() as cur:

            cur.execute(
                """
                SELECT id, filename
                FROM documents
                WHERE sha256 = %s
                """,
                (file_hash,),
            )

            duplicate = cur.fetchone()

            if duplicate:
                return {
                    "status": "duplicate",
                    "document_id": duplicate[0],
                    "filename": duplicate[1],
                    "sha256": file_hash,
                }

    pages = extract_pages(filename, data)

    chunk_records = []

    chunk_index = 0

    for page_number, text in pages:
        text = clean_extracted_text(text)
        for chunk in chunk_text(text):
            chunk_records.append(
                {
                    "chunk_index": chunk_index,
                    "page_number": page_number,
                    "content": chunk,
                }
            )

            chunk_index += 1

    if not chunk_records:
        raise ValueError(
            "No extractable text found in document."
        )

    texts = [
        record["content"]
        for record in chunk_records
    ]

    embeddings = embedding_model.encode(
        texts,
        normalize_embeddings=True,
        show_progress_bar=False,
    )

    with psycopg.connect(DATABASE_URL) as conn:
        register_vector(conn)

        with conn.cursor() as cur:

            cur.execute(
                """
                INSERT INTO documents (
                    filename,
                    sha256,
                    content_type,
                    size_bytes
                )
                VALUES (%s, %s, %s, %s)
                RETURNING id
                """,
                (
                    filename,
                    file_hash,
                    content_type,
                    len(data),
                ),
            )

            document_id = cur.fetchone()[0]

            for record, embedding in zip(
                chunk_records,
                embeddings,
            ):
                cur.execute(
                    """
                    INSERT INTO chunks (
                        document_id,
                        chunk_index,
                        page_number,
                        content,
                        embedding
                    )
                    VALUES (%s, %s, %s, %s, %s)
                    """,
                    (
                        document_id,
                        record["chunk_index"],
                        record["page_number"],
                        record["content"],
                        embedding,
                    ),
                )

        conn.commit()

    return {
        "status": "created",
        "document_id": document_id,
        "filename": filename,
        "sha256": file_hash,
        "chunks": len(chunk_records),
        "size_bytes": len(data),
    }
