import os
from pathlib import Path
from typing import Literal
from uuid import uuid4
from time import perf_counter

import psycopg
from dotenv import load_dotenv
from fastapi import Depends, FastAPI, File, HTTPException, UploadFile
from app.investigations.factory import build_investigation_service
from app.security.api_keys import (
    APIKeyPrincipal,
    NamespaceAuthorizationError,
    authorize_namespace,
)
from app.security.dependencies import require_api_key_principal
from pydantic import BaseModel, ConfigDict, Field

from app.audit import write_ask_audit
from app.ingestion import ingest_document
from app.rag import generate_answer, retrieve_evidence
from app.investigations.create_request import InvestigationCreateRequest
from app.tools.explicit_target import compose_question
from app.tools.orchestration import run_read_only_tool_request
from app.tools.workload_target import TargetQuestionError
from app.typed_atomic_sufficiency import (
    assess_typed_atomic_sufficiency,
)

from app.rag import (
    VLLM_MODEL,
    generate_answer,
    retrieve_evidence,
    source_label,
)
from app.investigations.models import InvestigationRecord
from app.investigations.repository import InvestigationRepository
from app.tools.investigation_scope import (
    DEFAULT_SCOPE_REJECTION,
    SCOPE_REJECTION_MESSAGES,
    InvestigationScopeCreationError,
    create_bound_investigation_context,
    resolve_requested_namespace,
)

from fastapi import HTTPException, Depends

from app.investigations.models import InvestigationStatus
from app.investigations.repository import (
    InvestigationRepository,
    InvestigationTransitionError,
)
from app.investigations.service import InvestigationService
from app.reports.models import InvestigationReport
from app.security.api_keys import APIKeyPrincipal
from app.security.dependencies import require_api_key_principal

load_dotenv()

DATABASE_URL = os.environ["DATABASE_URL"]

INSUFFICIENT_EVIDENCE_MESSAGE = (
    "I don't have sufficient evidence in the "
    "retrieved sources to answer this question."
)

app = FastAPI(
    title="Private AI Platform",
    description="Private RAG and AI operations platform",
    version="0.6.0-dev",
)


class DocumentSummary(BaseModel):
    id: int
    filename: str
    sha256: str | None
    content_type: str | None
    size_bytes: int | None
    status: Literal["ready"]
    chunks: int
    pages: int
    created_at: str


class DocumentDetail(DocumentSummary):
    first_page: int | None
    last_page: int | None


class DeleteDocumentResponse(BaseModel):
    status: Literal["deleted"]
    document_id: int
    filename: str

class AskRequest(BaseModel):
    question: str = Field(min_length=1, max_length=4000)


class Source(BaseModel):
    filename: str
    chunk_index: int
    page_number: int | None
    content: str
    similarity: float


class EvidenceSource(Source):
    label: str
    excerpt: str


class SufficiencySummary(BaseModel):
    sufficient: bool


class AskResponse(BaseModel):
    request_id: str
    status: Literal["answered", "insufficient_evidence"]
    question: str
    answer: str
    sources: list[EvidenceSource]
    sufficiency: SufficiencySummary
    timings: AskTimings

class AskTimings(BaseModel):
    retrieval_ms: float
    sufficiency_ms: float
    generation_ms: float | None
    total_ms: float
    
class ToolRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    question: str = Field(
        min_length=1,
        max_length=4000,
    ) 
    
class ToolRunResponse(BaseModel):
    request_id: str
    status: Literal[
        "none",
        "blocked",
        "executed",
    ]
    call: dict | None = None
    execution: dict | None = None
    reason: str | None = None
    
def to_evidence_source(source: dict) -> dict:
    return {
        "label": source_label(source),
        "filename": source["filename"],
        "chunk_index": source["chunk_index"],
        "page_number": source["page_number"],
        "content": source["content"],
        "excerpt": source["content"],
        "similarity": source["similarity"],
    }


@app.get("/health")
def health():
    database = False

    try:
        with psycopg.connect(DATABASE_URL) as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT 1")
                database = cur.fetchone()[0] == 1
    except Exception:
        pass

    return {
        "status": "ok" if database else "degraded",
        "database": database,
    }
    

@app.post(
    "/tools/run",
    response_model=ToolRunResponse,
)
def run_tool(
    request: ToolRequest,
    principal: APIKeyPrincipal = Depends(
        require_api_key_principal
    ),
):
    request_id = uuid4()

    try:
        result = run_read_only_tool_request(
            request_id=request_id,
            user_text=request.question,
            principal=principal,
        )

        return {
            "request_id": str(request_id),
            **result.model_dump(),
        }

    except NamespaceAuthorizationError:
        raise HTTPException(
            status_code=403,
            detail="Namespace access denied.",
        ) from None

    except Exception:
        raise HTTPException(
            status_code=500,
            detail="Tool request failed.",
        ) from None


@app.post("/ask", response_model=AskResponse, dependencies=[Depends(require_api_key_principal)],)
def ask(request: AskRequest):
    request_id = str(uuid4())
    total_started = perf_counter()

    try:
        retrieval_started = perf_counter()

        sources = retrieve_evidence(request.question)

        retrieval_ms = (
            perf_counter() - retrieval_started
        ) * 1000

        sufficiency_started = perf_counter()

        sufficiency = assess_typed_atomic_sufficiency(
            request.question,
            sources,
        )

        sufficiency_ms = (
            perf_counter() - sufficiency_started
        ) * 1000

        response_sources = [
            to_evidence_source(source)
            for source in sources
        ]

        source_labels = [
            source_label(source)
            for source in sources
        ]

        if not sufficiency.sufficient:
            generation_ms = None

            total_ms = (
                perf_counter() - total_started
            ) * 1000

            write_ask_audit(
                request_id=request_id,
                question=request.question,
                status="insufficient_evidence",
                answer=INSUFFICIENT_EVIDENCE_MESSAGE,
                sufficient=False,
                source_labels=source_labels,
                model=VLLM_MODEL,
                retrieval_ms=retrieval_ms,
                sufficiency_ms=sufficiency_ms,
                generation_ms=generation_ms,
                total_ms=total_ms,
            )

            return {
                "request_id": request_id,
                "status": "insufficient_evidence",
                "question": request.question,
                "answer": INSUFFICIENT_EVIDENCE_MESSAGE,
                "sources": response_sources,
                "sufficiency": {
                    "sufficient": False,
                },
                "timings": {
                    "retrieval_ms": retrieval_ms,
                    "sufficiency_ms": sufficiency_ms,
                    "generation_ms": generation_ms,
                    "total_ms": total_ms,
                },
            }

        generation_started = perf_counter()

        answer = generate_answer(
            request.question,
            sources,
        )

        generation_ms = (
            perf_counter() - generation_started
        ) * 1000

        total_ms = (
            perf_counter() - total_started
        ) * 1000

        write_ask_audit(
            request_id=request_id,
            question=request.question,
            status="answered",
            answer=answer,
            sufficient=True,
            source_labels=source_labels,
            model=VLLM_MODEL,
            retrieval_ms=retrieval_ms,
            sufficiency_ms=sufficiency_ms,
            generation_ms=generation_ms,
            total_ms=total_ms,
        )

        return {
            "request_id": request_id,
            "status": "answered",
            "question": request.question,
            "answer": answer,
            "sources": response_sources,
            "sufficiency": {
                "sufficient": True,
            },
            "timings": {
                "retrieval_ms": retrieval_ms,
                "sufficiency_ms": sufficiency_ms,
                "generation_ms": generation_ms,
                "total_ms": total_ms,
            },
        }

    except HTTPException:
        raise

    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=str(exc),
        )


@app.post("/documents", dependencies=[Depends(require_api_key_principal)],)
async def upload_document(
    file: UploadFile = File(...),
):
    allowed_extensions = {
        ".txt",
        ".md",
        ".pdf",
    }

    extension = Path(file.filename).suffix.lower()

    if extension not in allowed_extensions:
        raise HTTPException(
            status_code=400,
            detail=(
                "Unsupported document type. "
                "Supported: TXT, MD, PDF."
            ),
        )

    try:
        data = await file.read()

        if not data:
            raise HTTPException(
                status_code=400,
                detail="Uploaded file is empty.",
            )

        result = ingest_document(
            filename=file.filename,
            content_type=(
                file.content_type
                or "application/octet-stream"
            ),
            data=data,
        )

        return result

    except HTTPException:
        raise

    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=str(exc),
        )


@app.get(
    "/documents",
    response_model=list[DocumentSummary], dependencies=[Depends(require_api_key_principal)],
)
def list_documents():
    try:
        with psycopg.connect(DATABASE_URL) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT
                        d.id,
                        d.filename,
                        d.sha256,
                        d.content_type,
                        d.size_bytes,
                        d.created_at,
                        COUNT(c.id) AS chunks,
                        COUNT(
                            DISTINCT c.page_number
                        ) AS pages
                    FROM documents d
                    LEFT JOIN chunks c
                        ON c.document_id = d.id
                    GROUP BY
                        d.id,
                        d.filename,
                        d.sha256,
                        d.content_type,
                        d.size_bytes,
                        d.created_at
                    ORDER BY d.created_at DESC
                    """
                )

                rows = cur.fetchall()

        return [
            {
                "id": row[0],
                "filename": row[1],
                "sha256": row[2],
                "content_type": row[3],
                "size_bytes": row[4],
                "created_at": row[5].isoformat(),
                "status": "ready",
                "chunks": row[6],
                "pages": row[7],
            }
            for row in rows
        ]

    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=str(exc),
        )


@app.get(
    "/documents/{document_id}",
    response_model=DocumentDetail, dependencies=[Depends(require_api_key_principal)],)
def get_document(document_id: int):
    try:
        with psycopg.connect(DATABASE_URL) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT
                        d.id,
                        d.filename,
                        d.sha256,
                        d.content_type,
                        d.size_bytes,
                        d.created_at,
                        COUNT(c.id) AS chunks,
                        COUNT(
                            DISTINCT c.page_number
                        ) AS pages,
                        MIN(c.page_number) AS first_page,
                        MAX(c.page_number) AS last_page
                    FROM documents d
                    LEFT JOIN chunks c
                        ON c.document_id = d.id
                    WHERE d.id = %s
                    GROUP BY
                        d.id,
                        d.filename,
                        d.sha256,
                        d.content_type,
                        d.size_bytes,
                        d.created_at
                    """,
                    (document_id,),
                )

                row = cur.fetchone()

        if row is None:
            raise HTTPException(
                status_code=404,
                detail="Document not found.",
            )

        return {
            "id": row[0],
            "filename": row[1],
            "sha256": row[2],
            "content_type": row[3],
            "size_bytes": row[4],
            "created_at": row[5].isoformat(),
            "status": "ready",
            "chunks": row[6],
            "pages": row[7],
            "first_page": row[8],
            "last_page": row[9],
        }

    except HTTPException:
        raise

    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=str(exc),
        )


@app.delete("/documents/{document_id}", response_model=DeleteDocumentResponse,dependencies=[Depends(require_api_key_principal)],)
def delete_document(document_id: int):

    with psycopg.connect(DATABASE_URL) as conn:
        with conn.cursor() as cur:

            cur.execute(
                """
                DELETE FROM documents
                WHERE id = %s
                RETURNING filename
                """,
                (document_id,),
            )

            deleted = cur.fetchone()

        conn.commit()

    if not deleted:
        raise HTTPException(
            status_code=404,
            detail="Document not found.",
        )

    return {
        "status": "deleted",
        "document_id": document_id,
        "filename": deleted[0],
    }  


@app.post(
    "/investigations",
    response_model=InvestigationRecord,
    status_code=201,
)
def create_investigation(
    request: InvestigationCreateRequest,
    principal: APIKeyPrincipal = Depends(
        require_api_key_principal
    ),
):
    def reject(exc: InvestigationScopeCreationError) -> HTTPException:
        return HTTPException(
            status_code=422,
            detail=SCOPE_REJECTION_MESSAGES.get(
                exc.code, DEFAULT_SCOPE_REJECTION
            ),
        )

    # 1. Which namespace is requested (structured field; syntax only).
    try:
        namespace = resolve_requested_namespace(
            request.question, request.namespace
        )
    except InvestigationScopeCreationError as exc:
        raise reject(exc) from None

    # 2. The namespace must be on the demo allow-list before the question
    #    is evaluated or any model is involved.
    try:
        authorize_namespace(principal, namespace)
    except NamespaceAuthorizationError:
        raise HTTPException(
            status_code=403,
            detail="Namespace access denied.",
        ) from None

    # 3. The question, as text only: it is checked against the authorized
    #    namespace, never allowed to widen or change it. The investigation
    #    kind is bound into the context here, before any model is invoked.
    try:
        question = compose_question(
            request.question,
            namespace=namespace,
            target=request.target,
            namespace_wide=request.namespace_wide,
        )

        if len(question) > 4000:
            raise InvestigationScopeCreationError(
                "Question too long.", code="question_too_long"
            )

        context = create_bound_investigation_context(
            question,
            namespace=namespace,
            max_steps=request.max_steps,
        )
    except TargetQuestionError as exc:
        raise reject(InvestigationScopeCreationError(str(exc), code=exc.code)) from None
    except InvestigationScopeCreationError as exc:
        raise reject(exc) from None

    try:
        repository = InvestigationRepository()

        return repository.create_investigation(
            investigation_id=context.investigation_id,
            authorized_namespace=namespace,
            user_text=context.user_text,
            max_steps=context.max_steps,
        )
    except Exception:
        raise HTTPException(
            status_code=500,
            detail="Investigation creation failed.",
        ) from None
        
        
@app.post(
    "/investigations/{investigation_id}/execute",
    response_model=InvestigationRecord,
)
def execute_investigation(
    investigation_id: str,
    principal: APIKeyPrincipal = Depends(require_api_key_principal),
):
    repository = InvestigationRepository()

    try:
        record = repository.get_investigation_for_namespaces(
            investigation_id=investigation_id,
            allowed_namespaces=principal.allowed_namespaces,
        )
    except Exception:
        raise HTTPException(
            status_code=500,
            detail="Investigation lookup failed.",
        ) from None

    if record is None:
        raise HTTPException(
            status_code=404,
            detail="Investigation not found.",
        )

    if record.status != InvestigationStatus.PENDING:
        raise HTTPException(
            status_code=409,
            detail="Investigation is not pending.",
        )

    if record.user_text is None or record.max_steps is None:
        raise HTTPException(
            status_code=409,
            detail="Investigation execution inputs are unavailable.",
        )

    try:
        service = build_investigation_service(repository=repository)

        result = service.execute_existing(
            investigation_id=record.investigation_id,
            authorized_namespace=record.authorized_namespace,
        )
    except InvestigationTransitionError:
        raise HTTPException(
            status_code=409,
            detail="Investigation cannot be executed.",
        ) from None
    except Exception:
        raise HTTPException(
            status_code=500,
            detail="Investigation execution failed.",
        ) from None

    return result.record


@app.get(
    "/investigations/{investigation_id}",
    response_model=InvestigationRecord,
)
def get_investigation(
    investigation_id: str,
    principal: APIKeyPrincipal = Depends(require_api_key_principal),
):
    repository = InvestigationRepository()

    try:
        record = repository.get_investigation_for_namespaces(
            investigation_id=investigation_id,
            allowed_namespaces=principal.allowed_namespaces,
        )
    except Exception:
        raise HTTPException(
            status_code=500,
            detail="Investigation lookup failed.",
        ) from None

    if record is None:
        raise HTTPException(
            status_code=404,
            detail="Investigation not found.",
        )

    return record       

@app.get(
    "/investigations/{investigation_id}/report",
    response_model=InvestigationReport,
)
def get_investigation_report(
    investigation_id: str,
    principal: APIKeyPrincipal = Depends(require_api_key_principal),
):
    repository = InvestigationRepository()

    try:
        record = repository.get_investigation_for_namespaces(
            investigation_id=investigation_id,
            allowed_namespaces=principal.allowed_namespaces,
        )
    except Exception:
        raise HTTPException(
            status_code=500,
            detail="Investigation lookup failed.",
        ) from None

    # Out-of-scope and nonexistent investigations are indistinguishable.
    if record is None:
        raise HTTPException(
            status_code=404,
            detail="Investigation not found.",
        )

    if record.status != InvestigationStatus.COMPLETED:
        raise HTTPException(
            status_code=409,
            detail=f"Report unavailable: investigation is {record.status.value}.",
        )

    try:
        report = repository.get_report(
            investigation_id=record.investigation_id,
            authorized_namespace=record.authorized_namespace,
        )
    except Exception:
        raise HTTPException(
            status_code=500,
            detail="Report retrieval failed.",
        ) from None

    if report is None:
        raise HTTPException(
            status_code=404,
            detail="Report not found.",
        )

    return report


# Browser-facing API (session-authenticated, same application code) and, when
# the frontend has been built, the single-page app. See frontend/README.md.
from app.web.routes import router as web_router  # noqa: E402
from app.web.static import mount_frontend  # noqa: E402

app.include_router(web_router)
mount_frontend(app)
