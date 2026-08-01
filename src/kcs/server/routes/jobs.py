"""Authenticated FastAPI adapter for the first executable KCS V2 Job journey."""
# ruff: noqa: E501

from __future__ import annotations

import hashlib
import hmac
import os
import re
import tempfile
from collections.abc import Callable, Coroutine, Iterator
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Annotated, Any, Literal
from uuid import UUID, uuid4

from fastapi import APIRouter, Depends, Header, Query, Request, Response
from fastapi import Path as ApiPath
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, StreamingResponse
from fastapi.routing import APIRoute
from pydantic import BaseModel
from starlette.background import BackgroundTask

from kcs.jobs.canonical import DigestMismatchError as CanonicalDigestMismatchError
from kcs.jobs.contracts import (
    AgentStartRequest,
    CreateJobRequest,
    CredentialGrantMetadata,
    CredentialGrantSnapshot,
    FinalizeJobRequest,
    GenerationSnapshot,
    JobBindingSnapshot,
    JobBindingSnapshotList,
    JobBindingState,
    JobTombstone,
    LogContainer,
    RoleLogs,
    TransferCancelRequest,
    TransferRegisterRequest,
    TransferSnapshot,
    WorkspaceFrame,
    WorkspaceInvokeRequest,
    WorkspaceOperationSnapshot,
)
from kcs.jobs.errors import (
    DigestMismatchError,
    InvalidRequestError,
    KcsV2Error,
    PayloadTooLargeError,
    TransferBytesMismatchError,
)
from kcs.jobs.provider import (
    DEFAULT_LOG_LIMIT_BYTES,
    DEFAULT_PAGE_SIZE,
    MAX_LOG_LIMIT_BYTES,
    MAX_PAGE_SIZE,
    JobListQuery,
    V2JobProvider,
)

API_VERSION = "2.0.0"
_OPAQUE_REF_PATTERN = r"^[^\x00-\x1f\x7f]+$"
_OPAQUE_TOKEN_PATTERN = r"^[A-Za-z0-9_-]+$"
_SHA256_PATTERN = r"^[0-9a-f]{64}$"
_REQUEST_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_DEFAULT_OPENAPI_PATH = (
    Path(__file__).resolve().parents[4] / "openapi/generated/kcs-v2-jobs.openapi.json"
)


@dataclass(frozen=True, slots=True)
class V2Caller:
    """Non-secret authenticated identity passed beyond the HTTP boundary."""

    principal: Literal["v2-service"] = "v2-service"
    roles: frozenset[str] = frozenset({"v2-reader", "v2-mutator", "v2-private-credential-writer"})


class _UnauthenticatedError(KcsV2Error):
    code = "UNAUTHENTICATED"
    status_code = 401
    default_message = "Missing or invalid V2 service authentication"


class _ForbiddenError(KcsV2Error):
    code = "FORBIDDEN"
    status_code = 403
    default_message = "The caller is not authorized for this KCS V2 operation"


class _UnsupportedMediaTypeError(KcsV2Error):
    code = "UNSUPPORTED_MEDIA_TYPE"
    status_code = 415
    default_message = "Content-Type must be application/json"


class _CredentialMediaTypeError(_UnsupportedMediaTypeError):
    default_message = "Content-Type must be application/octet-stream"


class _TransferMediaTypeError(_UnsupportedMediaTypeError):
    default_message = "Content-Type must be application/octet-stream"


class _InternalRouteError(KcsV2Error):
    recovery_action = "reconcile"


def _request_id(request: Request) -> str:
    retained = getattr(request.state, "kcs_v2_request_id", None)
    if isinstance(retained, str):
        return retained

    supplied = request.headers.get("x-request-id", "")
    request_id = supplied if _REQUEST_ID_PATTERN.fullmatch(supplied) else f"request-{uuid4()}"
    request.state.kcs_v2_request_id = request_id
    return request_id


def _error_response(error: KcsV2Error, request: Request) -> JSONResponse:
    return JSONResponse(
        status_code=error.status_code,
        content=error.to_envelope(_request_id(request)),
        headers={"Cache-Control": "no-store"},
    )


def _validation_error(error: RequestValidationError) -> KcsV2Error:
    for item in error.errors():
        context = item.get("ctx")
        cause = context.get("error") if isinstance(context, dict) else None
        if isinstance(cause, CanonicalDigestMismatchError):
            return DigestMismatchError()
    return InvalidRequestError()


class _V2Route(APIRoute):
    """Render adapter and framework failures as the canonical public envelope."""

    def get_route_handler(self) -> Callable[[Request], Coroutine[Any, Any, Response]]:
        original = super().get_route_handler()

        async def route_handler(request: Request) -> Response:
            try:
                response = await original(request)
            except RequestValidationError as error:
                response = _error_response(_validation_error(error), request)
            except KcsV2Error as error:
                response = _error_response(error, request)
            except Exception:
                response = _error_response(_InternalRouteError(), request)
            response.headers.setdefault("Cache-Control", "no-store")
            return response

        return route_handler


def _auth_dependency(service_token: str, roles: frozenset[str]) -> Callable[[Request], V2Caller]:
    if not service_token or any(character.isspace() for character in service_token):
        raise ValueError("KCS V2 service token must be configured")
    expected_digest = hashlib.sha256(service_token.encode("utf-8")).digest()

    def require_v2_caller(request: Request) -> V2Caller:
        authorization = request.headers.get("authorization", "")
        scheme, separator, token = authorization.partition(" ")
        supplied_digest = hashlib.sha256(token.encode("utf-8")).digest()
        token_matches = hmac.compare_digest(supplied_digest, expected_digest)
        if separator != " " or scheme.casefold() != "bearer" or not token_matches:
            raise _UnauthenticatedError
        return V2Caller(roles=roles)

    return require_v2_caller


def _require_json_media_type(request: Request) -> None:
    if request.method not in {"POST", "PUT", "PATCH"}:
        return
    media_type = request.headers.get("content-type", "").partition(";")[0].strip()
    if request.url.path.endswith("/agent/credential-grants"):
        if media_type.lower() != "application/octet-stream":
            raise _CredentialMediaTypeError
        return
    if request.method == "PUT" and request.url.path.endswith("/content"):
        if media_type.lower() != "application/octet-stream":
            raise _TransferMediaTypeError
        return
    if media_type.lower() != "application/json":
        raise _UnsupportedMediaTypeError


def _json_model(model: BaseModel, *, status_code: int = 200) -> JSONResponse:
    return JSONResponse(
        status_code=status_code,
        content=model.model_dump(mode="json", by_alias=True),
    )


async def _credential_body(request: Request) -> bytes:
    body = bytearray()
    async for chunk in request.stream():
        if len(body) + len(chunk) > 65536:
            raise PayloadTooLargeError()
        body.extend(chunk)
    return bytes(body)


async def _transfer_body_file(request: Request, content_length: int) -> Path:
    descriptor, raw_path = tempfile.mkstemp(prefix="kcs-http-transfer-")
    path = Path(raw_path)
    received = 0
    try:
        os.chmod(path, 0o600)
        with os.fdopen(descriptor, "wb") as output:
            async for chunk in request.stream():
                received += len(chunk)
                if received > content_length:
                    raise TransferBytesMismatchError()
                output.write(chunk)
            output.flush()
            os.fsync(output.fileno())
        if received != content_length:
            raise TransferBytesMismatchError()
        return path
    except Exception:
        try:
            os.close(descriptor)
        except OSError:
            pass
        path.unlink(missing_ok=True)
        raise


def _content_chunks(path: Path) -> Iterator[bytes]:
    try:
        with path.open("rb") as source:
            while chunk := source.read(1024 * 1024):
                yield chunk
    finally:
        path.unlink(missing_ok=True)


def _error_responses(*status_codes: int) -> dict[int | str, dict[str, Any]]:
    return {
        status_code: {"description": "Canonical KCS V2 error envelope."}
        for status_code in status_codes
    }


def create_jobs_router(
    provider: V2JobProvider,
    service_token: str,
    *,
    canonical_openapi_path: Path | None = None,
    caller_roles: frozenset[str] = frozenset(
        {"v2-reader", "v2-mutator", "v2-private-credential-writer"}
    ),
) -> APIRouter:
    """Build the minimal V2 Job router around explicitly injected runtime dependencies."""

    openapi_bytes = (canonical_openapi_path or _DEFAULT_OPENAPI_PATH).read_bytes()
    openapi_sha256 = hashlib.sha256(openapi_bytes).hexdigest()
    require_v2_caller = _auth_dependency(service_token, caller_roles)

    def require_role(role: str) -> Callable[[Request], V2Caller]:
        def enforce(request: Request) -> V2Caller:
            caller = require_v2_caller(request)
            if role not in caller.roles:
                raise _ForbiddenError()
            return caller

        return enforce

    router = APIRouter(
        route_class=_V2Route,
        dependencies=[Depends(require_v2_caller), Depends(_require_json_media_type)],
    )

    @router.post(
        "/api/v2/jobs",
        operation_id="createJob",
        tags=["Jobs"],
        status_code=201,
        response_model=JobBindingSnapshot,
        responses={
            200: {"model": JobBindingSnapshot, "description": "Stable create replay."},
            **_error_responses(400, 401, 403, 409, 410, 413, 415, 422, 429, 500, 503, 504),
        },
    )
    def create_job(payload: CreateJobRequest) -> Response:
        result = provider.create(payload)
        return _json_model(result.snapshot, status_code=201 if result.created else 200)

    @router.get(
        "/api/v2/jobs",
        operation_id="listJobs",
        tags=["Jobs"],
        response_model=JobBindingSnapshotList,
        responses=_error_responses(400, 401, 403, 409, 429, 500, 503),
    )
    def list_jobs(
        page_token: Annotated[
            str | None,
            Query(
                alias="pageToken",
                min_length=1,
                max_length=4096,
                pattern=_OPAQUE_TOKEN_PATTERN,
            ),
        ] = None,
        page_size: Annotated[
            int,
            Query(alias="pageSize", ge=1, le=MAX_PAGE_SIZE),
        ] = DEFAULT_PAGE_SIZE,
        provider_request_id: Annotated[
            str | None,
            Query(
                alias="providerRequestId",
                min_length=1,
                max_length=256,
                pattern=_OPAQUE_REF_PATTERN,
            ),
        ] = None,
        subject_ref: Annotated[
            str | None,
            Query(
                alias="subjectRef",
                min_length=1,
                max_length=256,
                pattern=_OPAQUE_REF_PATTERN,
            ),
        ] = None,
        states: Annotated[list[JobBindingState] | None, Query(alias="state")] = None,
        created_after: Annotated[datetime | None, Query(alias="createdAfter")] = None,
        include_deleted: Annotated[bool, Query(alias="includeDeleted")] = False,
    ) -> Response:
        if created_after is not None and (
            created_after.tzinfo is None or created_after.utcoffset() is None
        ):
            raise InvalidRequestError("createdAfter must include a timezone")
        result = provider.list_jobs(
            JobListQuery(
                page_token=page_token,
                page_size=page_size,
                provider_request_id=provider_request_id,
                subject_ref=subject_ref,
                states=tuple(states or ()),
                created_after=created_after,
                include_deleted=include_deleted,
            )
        )
        return _json_model(result)

    @router.get(
        "/api/v2/jobs/{jobRef}",
        operation_id="inspectJob",
        tags=["Jobs"],
        response_model=JobBindingSnapshot,
        responses=_error_responses(401, 403, 404, 410, 500, 503),
    )
    def inspect_job(
        job_ref: Annotated[
            str,
            ApiPath(alias="jobRef", min_length=1, max_length=256, pattern=_OPAQUE_REF_PATTERN),
        ],
    ) -> Response:
        return _json_model(provider.inspect(job_ref))

    @router.get(
        "/api/v2/jobs/{jobRef}/logs",
        operation_id="getRoleLogs",
        tags=["Jobs"],
        response_model=RoleLogs,
        responses=_error_responses(400, 401, 403, 404, 409, 410, 500, 503),
    )
    def get_role_logs(
        job_ref: Annotated[
            str,
            ApiPath(alias="jobRef", min_length=1, max_length=256, pattern=_OPAQUE_REF_PATTERN),
        ],
        container: Annotated[LogContainer, Query()],
        cursor: Annotated[
            str | None,
            Query(min_length=1, max_length=4096, pattern=_OPAQUE_TOKEN_PATTERN),
        ] = None,
        limit_bytes: Annotated[
            int,
            Query(alias="limitBytes", ge=1, le=MAX_LOG_LIMIT_BYTES),
        ] = DEFAULT_LOG_LIMIT_BYTES,
    ) -> Response:
        return _json_model(provider.logs(job_ref, container, cursor, limit_bytes))

    @router.post(
        "/api/v2/jobs/{jobRef}/agent/credential-grants",
        operation_id="grantCredential",
        tags=["Credentials"],
        dependencies=[Depends(require_role("v2-private-credential-writer"))],
        status_code=201,
        response_model=CredentialGrantSnapshot,
        responses=_error_responses(400, 401, 403, 404, 409, 413, 415, 422, 500, 503),
    )
    async def grant_credential(
        request: Request,
        job_ref: Annotated[
            str, ApiPath(alias="jobRef", min_length=1, max_length=256, pattern=_OPAQUE_REF_PATTERN)
        ],
        credential_grant_ref: Annotated[
            str,
            Header(
                alias="KCS-Credential-Grant-Ref",
                min_length=1,
                max_length=256,
                pattern=_OPAQUE_REF_PATTERN,
            ),
        ],
        credential_sha256: Annotated[
            str, Header(alias="KCS-Credential-SHA256", pattern=_SHA256_PATTERN)
        ],
        grant_metadata_digest: Annotated[
            str, Header(alias="KCS-Grant-Metadata-Digest", pattern=_SHA256_PATTERN)
        ],
        agent_run_ref: Annotated[
            str,
            Header(
                alias="KCS-Agent-Run-Ref", min_length=1, max_length=256, pattern=_OPAQUE_REF_PATTERN
            ),
        ],
        generation: Annotated[int, Header(alias="KCS-Generation", ge=1)],
        launch_bundle_digest: Annotated[
            str, Header(alias="KCS-Launch-Bundle-Digest", pattern=_SHA256_PATTERN)
        ],
        audience: Annotated[
            str,
            Header(alias="KCS-Audience", min_length=1, max_length=256, pattern=_OPAQUE_REF_PATTERN),
        ],
        ttl_seconds: Annotated[int, Header(alias="KCS-Credential-TTL-Seconds", ge=1, le=900)],
        job_uid: Annotated[UUID, Header(alias="KCS-Job-UID")],
        pod_uid: Annotated[UUID, Header(alias="KCS-Pod-UID")],
    ) -> Response:
        try:
            provider.inspect_credential_grant(job_ref, credential_grant_ref)
            replay = True
        except KcsV2Error:
            replay = False
        metadata = CredentialGrantMetadata(
            credential_grant_ref=credential_grant_ref,
            credential_sha256=credential_sha256,
            grant_metadata_digest=grant_metadata_digest,
            agent_run_ref=agent_run_ref,
            generation=generation,
            launch_bundle_digest=launch_bundle_digest,
            audience=audience,
            ttl_seconds=ttl_seconds,
            job_uid=job_uid,
            pod_uid=pod_uid,
        )
        return _json_model(
            provider.grant_credential(job_ref, metadata, await _credential_body(request)),
            status_code=200 if replay else 201,
        )

    @router.get(
        "/api/v2/jobs/{jobRef}/agent/credential-grants/{credentialGrantRef}",
        operation_id="inspectCredentialGrant",
        tags=["Credentials"],
        response_model=CredentialGrantSnapshot,
        responses=_error_responses(401, 403, 404, 409, 500, 503),
    )
    def inspect_credential_grant(
        job_ref: Annotated[
            str, ApiPath(alias="jobRef", min_length=1, max_length=256, pattern=_OPAQUE_REF_PATTERN)
        ],
        credential_grant_ref: Annotated[
            str,
            ApiPath(
                alias="credentialGrantRef",
                min_length=1,
                max_length=256,
                pattern=_OPAQUE_REF_PATTERN,
            ),
        ],
    ) -> Response:
        return _json_model(provider.inspect_credential_grant(job_ref, credential_grant_ref))

    @router.post(
        "/api/v2/jobs/{jobRef}/agent/start",
        operation_id="startAgent",
        tags=["Jobs"],
        status_code=202,
        response_model=GenerationSnapshot,
        responses=_error_responses(400, 401, 403, 404, 409, 413, 415, 422, 500, 503, 504),
    )
    def start_agent(
        job_ref: Annotated[
            str, ApiPath(alias="jobRef", min_length=1, max_length=256, pattern=_OPAQUE_REF_PATTERN)
        ],
        payload: AgentStartRequest,
    ) -> Response:
        result = provider.start_agent(job_ref, payload)
        return _json_model(result, status_code=200 if result.replayed else 202)

    @router.post(
        "/api/v2/jobs/{jobRef}/transfers",
        operation_id="registerTransfer",
        tags=["Transfers"],
        status_code=201,
        response_model=TransferSnapshot,
        responses={
            200: {"model": TransferSnapshot, "description": "Stable transfer replay."},
            **_error_responses(400, 401, 403, 404, 409, 413, 415, 422, 429, 500, 503),
        },
    )
    def register_transfer(
        job_ref: Annotated[
            str, ApiPath(alias="jobRef", min_length=1, max_length=256, pattern=_OPAQUE_REF_PATTERN)
        ],
        payload: TransferRegisterRequest,
    ) -> Response:
        result = provider.register_transfer(job_ref, payload)
        return _json_model(result.snapshot, status_code=201 if result.created else 200)

    @router.get(
        "/api/v2/jobs/{jobRef}/transfers/{transferRef}",
        operation_id="inspectTransfer",
        tags=["Transfers"],
        response_model=TransferSnapshot,
        responses=_error_responses(401, 403, 404, 409, 410, 500, 503),
    )
    def inspect_transfer(
        job_ref: Annotated[
            str, ApiPath(alias="jobRef", min_length=1, max_length=256, pattern=_OPAQUE_REF_PATTERN)
        ],
        transfer_ref: Annotated[
            str,
            ApiPath(alias="transferRef", min_length=1, max_length=256, pattern=_OPAQUE_REF_PATTERN),
        ],
    ) -> Response:
        return _json_model(provider.inspect_transfer(job_ref, transfer_ref))

    @router.delete(
        "/api/v2/jobs/{jobRef}/transfers/{transferRef}",
        operation_id="discardTransfer",
        tags=["Transfers"],
        response_model=TransferSnapshot,
        responses=_error_responses(400, 401, 403, 404, 409, 422, 500, 503),
    )
    def discard_transfer(
        job_ref: Annotated[
            str, ApiPath(alias="jobRef", min_length=1, max_length=256, pattern=_OPAQUE_REF_PATTERN)
        ],
        transfer_ref: Annotated[
            str,
            ApiPath(alias="transferRef", min_length=1, max_length=256, pattern=_OPAQUE_REF_PATTERN),
        ],
        discard_ref: Annotated[
            str,
            Header(
                alias="KCS-Discard-Ref", min_length=1, max_length=256, pattern=_OPAQUE_REF_PATTERN
            ),
        ],
        request_digest: Annotated[str, Header(alias="KCS-Request-Digest", pattern=_SHA256_PATTERN)],
    ) -> Response:
        return _json_model(
            provider.discard_transfer(job_ref, transfer_ref, discard_ref, request_digest)
        )

    @router.put(
        "/api/v2/jobs/{jobRef}/transfers/{transferRef}/content",
        operation_id="putTransferContent",
        tags=["Transfers"],
        response_model=TransferSnapshot,
        responses=_error_responses(400, 401, 403, 404, 409, 413, 415, 422, 500, 503, 504),
    )
    async def put_transfer_content(
        request: Request,
        job_ref: Annotated[
            str, ApiPath(alias="jobRef", min_length=1, max_length=256, pattern=_OPAQUE_REF_PATTERN)
        ],
        transfer_ref: Annotated[
            str,
            ApiPath(alias="transferRef", min_length=1, max_length=256, pattern=_OPAQUE_REF_PATTERN),
        ],
        content_sha256: Annotated[str, Header(alias="KCS-Content-SHA256", pattern=_SHA256_PATTERN)],
        content_length: Annotated[int, Header(alias="Content-Length", ge=0, le=107374182400)],
    ) -> Response:
        transfer = provider.inspect_transfer(job_ref, transfer_ref)
        if (
            transfer.spec.content_sha256 != content_sha256
            or content_length != transfer.spec.declared_size_bytes
            or content_length > transfer.spec.authorized_max_size_bytes
        ):
            raise TransferBytesMismatchError()
        path = await _transfer_body_file(request, content_length)
        try:
            with path.open("rb") as stream:
                snapshot = provider.stage_transfer_content(
                    job_ref, transfer_ref, stream, content_length=content_length
                )
            return _json_model(snapshot)
        finally:
            path.unlink(missing_ok=True)

    @router.get(
        "/api/v2/jobs/{jobRef}/transfers/{transferRef}/content",
        operation_id="getTransferContent",
        tags=["Transfers"],
        response_class=StreamingResponse,
        responses=_error_responses(401, 403, 404, 409, 410, 500, 503, 504),
    )
    def get_transfer_content(
        job_ref: Annotated[
            str, ApiPath(alias="jobRef", min_length=1, max_length=256, pattern=_OPAQUE_REF_PATTERN)
        ],
        transfer_ref: Annotated[
            str,
            ApiPath(alias="transferRef", min_length=1, max_length=256, pattern=_OPAQUE_REF_PATTERN),
        ],
    ) -> StreamingResponse:
        content = provider.open_collected_content(job_ref, transfer_ref)
        return StreamingResponse(
            _content_chunks(content.path),
            media_type="application/octet-stream",
            headers={
                "Content-Length": str(content.size),
                "X-Content-SHA256": content.sha256,
                "X-KCS-Snapshot-Ref": content.snapshot_ref,
                "Cache-Control": "no-store",
            },
            background=BackgroundTask(content.cleanup),
        )

    @router.post(
        "/api/v2/jobs/{jobRef}/transfers/{transferRef}/cancel",
        operation_id="cancelTransfer",
        tags=["Transfers"],
        status_code=202,
        response_model=TransferSnapshot,
        responses={
            200: {"model": TransferSnapshot, "description": "Stable cancellation replay."},
            **_error_responses(400, 401, 403, 404, 409, 415, 422, 500, 503),
        },
    )
    def cancel_transfer(
        job_ref: Annotated[
            str, ApiPath(alias="jobRef", min_length=1, max_length=256, pattern=_OPAQUE_REF_PATTERN)
        ],
        transfer_ref: Annotated[
            str,
            ApiPath(alias="transferRef", min_length=1, max_length=256, pattern=_OPAQUE_REF_PATTERN),
        ],
        payload: TransferCancelRequest,
    ) -> Response:
        result = provider.cancel_transfer(job_ref, transfer_ref, payload)
        return _json_model(result.snapshot, status_code=202 if result.created else 200)

    @router.post(
        "/api/v2/jobs/{jobRef}/workspace/invoke",
        operation_id="invokeWorkspace",
        tags=["Workspace"],
        status_code=202,
        response_model=WorkspaceOperationSnapshot,
        responses={
            200: {"model": WorkspaceOperationSnapshot, "description": "Stable operation replay."},
            **_error_responses(400, 401, 403, 404, 409, 413, 415, 422, 500, 503, 504),
        },
    )
    def invoke_workspace(
        job_ref: Annotated[
            str, ApiPath(alias="jobRef", min_length=1, max_length=256, pattern=_OPAQUE_REF_PATTERN)
        ],
        payload: WorkspaceFrame,
        operation_ref: Annotated[
            str,
            Header(
                alias="KCS-Operation-Ref", min_length=1, max_length=256, pattern=_OPAQUE_REF_PATTERN
            ),
        ],
        request_digest: Annotated[str, Header(alias="KCS-Request-Digest", pattern=_SHA256_PATTERN)],
        job_uid: Annotated[UUID, Header(alias="KCS-Job-UID")],
        pod_uid: Annotated[UUID, Header(alias="KCS-Pod-UID")],
    ) -> Response:
        existed = True
        try:
            provider.inspect_operation(job_ref, operation_ref)
        except KcsV2Error:
            existed = False
        result = provider.invoke_workspace(
            job_ref,
            WorkspaceInvokeRequest(
                operation_ref=operation_ref,
                request_digest=request_digest,
                job_uid=job_uid,
                pod_uid=pod_uid,
                frame=payload,
            ),
        )
        return _json_model(result, status_code=200 if existed else 202)

    @router.get(
        "/api/v2/jobs/{jobRef}/operations/{operationRef}",
        operation_id="inspectWorkspaceOperation",
        tags=["Workspace"],
        response_model=WorkspaceOperationSnapshot,
        responses=_error_responses(401, 403, 404, 409, 410, 500, 503),
    )
    def inspect_workspace_operation(
        job_ref: Annotated[
            str, ApiPath(alias="jobRef", min_length=1, max_length=256, pattern=_OPAQUE_REF_PATTERN)
        ],
        operation_ref: Annotated[
            str,
            ApiPath(
                alias="operationRef", min_length=1, max_length=256, pattern=_OPAQUE_REF_PATTERN
            ),
        ],
    ) -> Response:
        return _json_model(provider.inspect_operation(job_ref, operation_ref))

    @router.post(
        "/api/v2/jobs/{jobRef}/finalize",
        operation_id="finalizeJob",
        tags=["Jobs"],
        status_code=202,
        response_model=JobBindingSnapshot,
        responses=_error_responses(400, 401, 403, 404, 409, 415, 422, 500, 503, 504),
    )
    def finalize_job(
        job_ref: Annotated[
            str, ApiPath(alias="jobRef", min_length=1, max_length=256, pattern=_OPAQUE_REF_PATTERN)
        ],
        payload: FinalizeJobRequest,
    ) -> Response:
        result = provider.finalize(job_ref, payload)
        return _json_model(result.snapshot, status_code=202 if result.created else 200)

    @router.delete(
        "/api/v2/jobs/{jobRef}",
        operation_id="deleteJob",
        tags=["Jobs"],
        response_model=JobTombstone,
        responses=_error_responses(400, 401, 403, 404, 409, 422, 500, 503, 504),
    )
    def delete_job(
        job_ref: Annotated[
            str,
            ApiPath(alias="jobRef", min_length=1, max_length=256, pattern=_OPAQUE_REF_PATTERN),
        ],
        delete_ref: Annotated[
            str,
            Header(
                alias="KCS-Delete-Ref",
                min_length=1,
                max_length=256,
                pattern=_OPAQUE_REF_PATTERN,
            ),
        ],
        request_digest: Annotated[
            str,
            Header(alias="KCS-Request-Digest", pattern=_SHA256_PATTERN),
        ],
    ) -> Response:
        return _json_model(provider.delete(job_ref, delete_ref, request_digest))

    @router.get(
        "/api/v2/openapi.json",
        operation_id="getCanonicalOpenApi",
        tags=["Contract"],
        response_class=Response,
        responses=_error_responses(401, 403, 500),
    )
    def canonical_openapi() -> Response:
        return Response(
            content=openapi_bytes,
            media_type="application/json",
            headers={
                "Cache-Control": "no-store",
                "ETag": openapi_sha256,
                "X-KCS-API-Version": API_VERSION,
            },
        )

    return router


__all__ = ["V2Caller", "create_jobs_router"]
