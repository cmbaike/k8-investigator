import os

import psycopg
from dotenv import load_dotenv


load_dotenv()

DATABASE_URL = os.environ["DATABASE_URL"]


with psycopg.connect(DATABASE_URL) as conn:
    with conn.cursor() as cur:

        cur.execute("""
            CREATE EXTENSION IF NOT EXISTS vector;
        """)

        cur.execute("""
            CREATE TABLE IF NOT EXISTS documents (
                id BIGSERIAL PRIMARY KEY,
                filename TEXT NOT NULL,
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            );
        """)

        cur.execute("""
            CREATE TABLE IF NOT EXISTS chunks (
                id BIGSERIAL PRIMARY KEY,
                document_id BIGINT NOT NULL
                    REFERENCES documents(id)
                    ON DELETE CASCADE,

                chunk_index INTEGER NOT NULL,
                content TEXT NOT NULL,

                embedding VECTOR(384),

                UNIQUE(document_id, chunk_index)
            );
        """)

    conn.commit()

print("Database initialized.")
