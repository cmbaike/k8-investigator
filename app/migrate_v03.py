import os
import psycopg
from dotenv import load_dotenv

load_dotenv()

DATABASE_URL = os.environ["DATABASE_URL"]

statements = [
    """
    ALTER TABLE documents
    ADD COLUMN IF NOT EXISTS sha256 TEXT
    """,
    """
    ALTER TABLE documents
    ADD COLUMN IF NOT EXISTS content_type TEXT
    """,
    """
    ALTER TABLE documents
    ADD COLUMN IF NOT EXISTS size_bytes BIGINT
    """,
    """
    ALTER TABLE chunks
    ADD COLUMN IF NOT EXISTS page_number INTEGER
    """,
    """
    CREATE UNIQUE INDEX IF NOT EXISTS
    idx_documents_sha256
    ON documents(sha256)
    WHERE sha256 IS NOT NULL
    """,
]

with psycopg.connect(DATABASE_URL) as conn:
    with conn.cursor() as cur:
        for statement in statements:
            cur.execute(statement)

    conn.commit()

print("v0.3 migration complete.")
