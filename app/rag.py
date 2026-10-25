import os
import re

import psycopg
import torch
from dotenv import load_dotenv
from openai import OpenAI
from pgvector.psycopg import register_vector
from sentence_transformers import SentenceTransformer
from app.provenance import source_label
from app.reranker import rerank
from app.llm import VLLM_MODEL, client
from app.model_output import strip_think_blocks

load_dotenv()



DATABASE_URL = os.environ["DATABASE_URL"]
EMBEDDING_MODEL = os.getenv(
    "EMBEDDING_MODEL",
    "BAAI/bge-small-en-v1.5",
)
VLLM_BASE_URL = os.environ["VLLM_BASE_URL"]
VLLM_API_KEY = os.environ["VLLM_API_KEY"]
VLLM_MODEL = os.environ["VLLM_MODEL"]

device = "cuda" if torch.cuda.is_available() else "cpu"

print(f"Loading embedding model {EMBEDDING_MODEL} on {device}")

embedding_model = SentenceTransformer(
    EMBEDDING_MODEL,
    device=device,
)
  

def retrieve(question: str, limit: int = 3):
    query_embedding = embedding_model.encode(
        question,
        normalize_embeddings=True,
    )

    with psycopg.connect(DATABASE_URL) as conn:
        register_vector(conn)

        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT
                    d.filename,
                    c.chunk_index,
                    c.page_number,
                    c.content,
                    1 - (c.embedding <=> %s) AS similarity
                FROM chunks c
                JOIN documents d ON d.id = c.document_id
                ORDER BY c.embedding <=> %s
                LIMIT %s
                """,
                (query_embedding, query_embedding, limit),
            )

            rows = cur.fetchall()

    return [
        {
            "filename": row[0],
            "chunk_index": row[1],
            "page_number": row[2],
            "content": row[3],
            "similarity": float(row[4]),
        }
        for row in rows
    ]

VECTOR_CANDIDATE_K = 12
FINAL_EVIDENCE_K = 4
    
def retrieve_evidence(
    question: str,
) -> list[dict]:
    candidates = retrieve(
        question,
        limit=VECTOR_CANDIDATE_K,
    )

    return rerank(
        question,
        candidates,
        limit=FINAL_EVIDENCE_K,
    )      
    
def generate_answer(question: str, sources: list[dict]):
    context = "\n\n".join(
        f"[SOURCE: {source_label(source)}]\n"
        f"{source['content']}"
        for source in sources
    )

    system_prompt = """
You are the Private AI Operations Assistant.

Answer the question using ONLY facts explicitly stated in the supplied context.

STRICT GROUNDING RULES:
- Every factual statement in your answer must be directly supported by the supplied context.
- Do not use outside knowledge, even when it is technically correct.
- Do not infer consequences, causes, guarantees, operational behaviour, availability, safety, timing, or recommendations unless the context explicitly states them.
- Do not turn one fact into a broader conclusion.
- Preserve subjects, conditions, scope, exceptions, and qualifiers from the source.
- If the context supports only part of the requested answer, answer only that supported part.
- If the context does not contain enough information to answer, say so.
- Do not invent operational procedures.
- Preserve any human-approval requirements in the source material.
- Cite factual statements using the exact [SOURCE: ...] identifiers supplied in the context.
- Prefer a short answer containing only supported facts over a more complete answer containing unsupported details.
""".strip()

    response = client.chat.completions.create(
        model=VLLM_MODEL,
        messages=[
            {
                "role": "system",
                "content": system_prompt,
            },
            {
                "role": "user",
                "content": f"CONTEXT\n\n{context}\n\nQUESTION\n\n{question}",
            },
        ],
        temperature=0.1,
        max_tokens=800,
    )
    
    choice = response.choices[0]
    
    print(
    "generation diagnostics:",
    {
        "finish_reason": choice.finish_reason,
        "completion_tokens": (
            response.usage.completion_tokens
            if response.usage
            else None
        ),
    },
)
    
    content = response.choices[0].message.content or ""
    return strip_think_blocks(content)