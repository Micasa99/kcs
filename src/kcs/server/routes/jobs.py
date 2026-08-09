"""Authenticated FastAPI adapter for the first executable KCS V2 Job journey."""
# ruff: noqa: E501

from __future__ import annotations

import asyncio
import hashlib
import hmac
import importlib.resources
import logging
import os
import re
import tempfile
from collections.abc import Callable, Coroutine, Iterator, Mapping
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Annotated, Any, Literal
from urllib.parse import quote, urlsplit
from uuid import UUID, uuid4

import requests
import yaml  # type: ignore[import-untyped]
from fastapi import APIRouter, Depends, FastAPI, Header, Query, Request, Response, WebSocket
from fastapi import Path as ApiPath
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, StreamingResponse
from fastapi.routing import APIRoute
from pydantic import BaseModel
from starlette.background import BackgroundTask
from websockets.asyncio.client import connect as websocket_connect
from websockets.exceptions import ConnectionClosed

from kcs.jobs.canonical import DigestMismatchError as CanonicalDigestMismatchError
from kcs.jobs.contracts import (
    AgentStartRequest,
    CancelJobRequest,
    CapacitySnapshot,
    CreateJobRequest,
    CredentialGrantMetadata,
    CredentialGrantSnapshot,
    FinalizeJobRequest,
    GenerationSnapshot,
    JobBindingSnapshot,
    JobBindingSnapshotList,
    JobBindingState,
    JobTombstone,
    NodeTelemetryList,
    NvidiaTelemetrySnapshot,
    ObservabilityHealth,
    QueueSnapshot,
    RoleLogs,
    RuntimeEventPage,
    TerminalCreateRequest,
    TerminalResizeRequest,
    TerminalSessionSnapshot,
    TransferCancelRequest,
    TransferRegisterRequest,
    TransferSnapshot,
    WorkspaceFrame,
    WorkspaceInvokeRequest,
    WorkspaceOperationSnapshot,
)
from kcs.jobs.errors import (
    DevSessionRelayDownError,
    DigestMismatchError,
    InvalidRequestError,
    KcsV2Error,
    PayloadTooLargeError,
    TransferBytesMismatchError,
)
from kcs.jobs.m2_contracts import (
    LiveWorkspaceDiffPage,
    LiveWorkspaceSnapshot,
    LiveWorkspaceSnapshotRequest,
    ResolvedRuntimeAssembly,
    RuntimeAssemblyResolutionRequest,
)
from kcs.jobs.native_contracts import (
    AnyJobBindingSnapshotList,
    DevSessionCreateRequest,
    DevSessionRenewRequest,
    DevSessionSnapshot,
    NativeCreateJobRequest,
    NativeFinalizeJobRequest,
    NativeJobBindingSnapshot,
    NativeRoleLogs,
    NativeRunnerGenerationSnapshot,
    NativeTerminalSessionSnapshot,
    ResolvedRuntimeRecipe,
    RunnerCredentialGrantSnapshot,
    RunnerStartRequest,
    RunnerStopRequest,
    RunnerStopSnapshot,
)
from kcs.jobs.native_runtime import RunnerCredentialGrantMetadata
from kcs.jobs.provider import (
    DEFAULT_LOG_LIMIT_BYTES,
    DEFAULT_PAGE_SIZE,
    MAX_LOG_LIMIT_BYTES,
    MAX_PAGE_SIZE,
    JobListQuery,
    V2JobProvider,
)
from kcs.jobs.workspace_runtime import VerifiedContent

API_VERSION = "2.5.0"
_OPAQUE_REF_PATTERN = r"^[^\x00-\x1f\x7f]+$"
_OPAQUE_TOKEN_PATTERN = r"^[A-Za-z0-9_-]+$"
_SHA256_PATTERN = r"^[0-9a-f]{64}$"
_REQUEST_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_DEV_RELAY_RESPONSE_HEADERS = frozenset(
    {
        "content-type",
        "content-encoding",
        "etag",
        "last-modified",
        "cache-control",
        "vary",
        "accept-ranges",
    }
)
log = logging.getLogger("kcs")


def _canonical_openapi_bytes(path: Path | None) -> bytes:
    if path is not None:
        return path.read_bytes()
    return (
        importlib.resources.files("kcs.openapi").joinpath("kcs-v2-jobs.openapi.json").read_bytes()
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


class _TerminalMediaTypeError(_UnsupportedMediaTypeError):
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
                log.exception(
                    "unhandled KCS V2 route failure requestId=%s method=%s path=%s",
                    _request_id(request),
                    request.method,
                    request.url.path,
                )
                response = _error_response(_InternalRouteError(), request)
            response.headers.setdefault("Cache-Control", "no-store")
            return response

        return route_handler


def _auth_dependency(
    service_token: str,
    roles: frozenset[str],
    operation_roles: Mapping[str, str],
) -> Callable[[Request], V2Caller]:
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
        route = request.scope.get("route")
        operation_id = getattr(route, "operation_id", None)
        required_role = operation_roles.get(str(operation_id))
        if required_role is None or required_role not in roles:
            raise _ForbiddenError()
        return V2Caller(roles=roles)

    return require_v2_caller


def _require_json_media_type(request: Request) -> None:
    if request.method not in {"POST", "PUT", "PATCH"}:
        return
    media_type = request.headers.get("content-type", "").partition(";")[0].strip()
    if request.url.path.endswith(("/agent/credential-grants", "/runner/credential-grants")):
        if media_type.lower() != "application/octet-stream":
            raise _CredentialMediaTypeError
        return
    if request.method == "PUT" and request.url.path.endswith("/content"):
        if media_type.lower() != "application/octet-stream":
            raise _TransferMediaTypeError
        return
    if request.method == "POST" and request.url.path.endswith("/input"):
        if media_type.lower() != "application/octet-stream":
            raise _TerminalMediaTypeError
        return
    if media_type.lower() != "application/json":
        raise _UnsupportedMediaTypeError


def _json_model(
    model: BaseModel,
    *,
    status_code: int = 200,
    exclude_unset: bool = False,
) -> JSONResponse:
    return JSONResponse(
        status_code=status_code,
        content=model.model_dump(mode="json", by_alias=True, exclude_unset=exclude_unset),
    )


async def _credential_body(request: Request) -> bytes:
    body = bytearray()
    async for chunk in request.stream():
        if len(body) + len(chunk) > 65536:
            raise PayloadTooLargeError()
        body.extend(chunk)
    return bytes(body)


async def _terminal_input_body(request: Request) -> bytes:
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
                await asyncio.to_thread(output.write, chunk)
            await asyncio.to_thread(output.flush)
            await asyncio.to_thread(os.fsync, output.fileno())
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


def _content_chunks(content: VerifiedContent) -> Iterator[bytes]:
    with content.path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            yield chunk


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

    openapi_bytes = _canonical_openapi_bytes(canonical_openapi_path)
    openapi_sha256 = hashlib.sha256(openapi_bytes).hexdigest()
    canonical = yaml.safe_load(openapi_bytes)
    paths = canonical.get("paths") if isinstance(canonical, Mapping) else None
    if not isinstance(paths, Mapping):
        raise ValueError("canonical OpenAPI paths are invalid")
    operation_roles: dict[str, str] = {}
    for path_item in paths.values():
        if not isinstance(path_item, Mapping):
            raise ValueError("canonical OpenAPI path item is invalid")
        for method, operation in path_item.items():
            if str(method).lower() not in {"get", "post", "put", "patch", "delete"}:
                continue
            if not isinstance(operation, Mapping):
                raise ValueError("canonical OpenAPI operation is invalid")
            operation_id = operation.get("operationId")
            role = operation.get("x-kcs-service-authorization")
            if not isinstance(operation_id, str) or not isinstance(role, str):
                raise ValueError("canonical OpenAPI authorization is incomplete")
            operation_roles[operation_id] = role
    require_v2_caller = _auth_dependency(service_token, caller_roles, operation_roles)

    router = APIRouter(
        route_class=_V2Route,
        dependencies=[Depends(require_v2_caller), Depends(_require_json_media_type)],
    )

    @router.get(
        "/api/v2/telemetry/nodes",
        operation_id="getNodeTelemetry",
        tags=["Cluster observations"],
        response_model=NodeTelemetryList,
        responses=_error_responses(401, 403, 500, 503),
    )
    def get_node_telemetry() -> Response:
        return _json_model(provider.telemetry_nodes(), exclude_unset=True)

    @router.get(
        "/api/v2/events",
        operation_id="getRuntimeEvents",
        tags=["Cluster observations"],
        response_model=RuntimeEventPage,
        responses=_error_responses(400, 401, 403, 500, 503),
    )
    def get_runtime_events(
        cursor: Annotated[
            str | None,
            Query(pattern=_OPAQUE_TOKEN_PATTERN),
        ] = None,
        limit: Annotated[int, Query(ge=1, le=200)] = 200,
    ) -> Response:
        return _json_model(provider.runtime_events(cursor, limit))

    @router.get(
        "/api/v2/healthz",
        operation_id="getObservabilityHealth",
        tags=["Cluster observations"],
        response_model=ObservabilityHealth,
        responses=_error_responses(401, 403, 500),
    )
    def get_observability_health() -> Response:
        return _json_model(provider.observability_health())

    @router.get(
        "/api/v2/capacity",
        operation_id="getCapacity",
        tags=["Cluster observations"],
        response_model=CapacitySnapshot,
        responses=_error_responses(401, 403, 500, 503),
    )
    def get_capacity() -> Response:
        return _json_model(provider.capacity())

    @router.get(
        "/api/v2/queue",
        operation_id="getQueue",
        tags=["Cluster observations"],
        response_model=QueueSnapshot,
        responses=_error_responses(401, 403, 500, 503),
    )
    def get_queue() -> Response:
        return _json_model(provider.queue())

    @router.get(
        "/api/v2/runtime-recipes/resolve",
        operation_id="resolveRuntimeRecipe",
        tags=["Jobs"],
        response_model=ResolvedRuntimeRecipe,
        responses=_error_responses(400, 401, 403, 422, 500, 503),
    )
    def resolve_runtime_recipe(
        runner_ref: Annotated[
            str,
            Query(
                alias="runnerRef",
                min_length=1,
                max_length=256,
                pattern=_OPAQUE_REF_PATTERN,
            ),
        ],
        environment_profile_ref: Annotated[
            str,
            Query(
                alias="environmentProfileRef",
                min_length=1,
                max_length=256,
                pattern=_OPAQUE_REF_PATTERN,
            ),
        ],
    ) -> Response:
        return _json_model(provider.resolve_runtime_recipe(runner_ref, environment_profile_ref))

    @router.post(
        "/api/v2/runtime-assemblies/resolve",
        operation_id="resolveRuntimeAssembly",
        tags=["Runtime assemblies"],
        response_model=ResolvedRuntimeAssembly,
        responses=_error_responses(400, 401, 403, 422, 500, 503),
    )
    def resolve_runtime_assembly(
        payload: RuntimeAssemblyResolutionRequest,
    ) -> Response:
        return _json_model(provider.resolve_runtime_assembly(payload))

    @router.post(
        "/api/v2/jobs/{jobRef}/workspace/live-snapshots",
        operation_id="createLiveWorkspaceSnapshot",
        tags=["Live workspace"],
        status_code=201,
        response_model=LiveWorkspaceSnapshot,
        responses=_error_responses(
            200, 400, 401, 403, 404, 409, 410, 413, 415, 422, 500, 503, 504
        ),
    )
    def create_live_workspace_snapshot(
        job_ref: Annotated[
            str,
            ApiPath(
                alias="jobRef", min_length=1, max_length=256, pattern=_OPAQUE_REF_PATTERN
            ),
        ],
        payload: LiveWorkspaceSnapshotRequest,
    ) -> Response:
        result = provider.create_live_workspace_snapshot(job_ref, payload)
        response = _json_model(
            result.snapshot, status_code=201 if result.created else 200
        )
        response.headers["ETag"] = str(result.snapshot.root["snapshotDigest"])
        return response

    @router.get(
        "/api/v2/jobs/{jobRef}/workspace/live-snapshots/{snapshotRef}",
        operation_id="inspectLiveWorkspaceSnapshot",
        tags=["Live workspace"],
        response_model=LiveWorkspaceSnapshot,
        responses=_error_responses(401, 403, 404, 409, 410, 500, 503),
    )
    def inspect_live_workspace_snapshot(
        job_ref: Annotated[str, ApiPath(alias="jobRef", pattern=_OPAQUE_REF_PATTERN)],
        snapshot_ref: Annotated[
            str, ApiPath(alias="snapshotRef", pattern=_OPAQUE_REF_PATTERN)
        ],
    ) -> Response:
        snapshot = provider.inspect_live_workspace_snapshot(job_ref, snapshot_ref)
        response = _json_model(snapshot)
        response.headers["ETag"] = str(snapshot.root["snapshotDigest"])
        return response

    @router.delete(
        "/api/v2/jobs/{jobRef}/workspace/live-snapshots/{snapshotRef}",
        operation_id="releaseLiveWorkspaceSnapshot",
        tags=["Live workspace"],
        response_model=LiveWorkspaceSnapshot,
        responses=_error_responses(401, 403, 404, 409, 410, 500, 503),
    )
    def release_live_workspace_snapshot(
        job_ref: Annotated[str, ApiPath(alias="jobRef", pattern=_OPAQUE_REF_PATTERN)],
        snapshot_ref: Annotated[
            str, ApiPath(alias="snapshotRef", pattern=_OPAQUE_REF_PATTERN)
        ],
    ) -> Response:
        snapshot = provider.release_live_workspace_snapshot(job_ref, snapshot_ref)
        response = _json_model(snapshot)
        response.headers["ETag"] = str(snapshot.root["snapshotDigest"])
        return response

    @router.get(
        "/api/v2/jobs/{jobRef}/workspace/live-snapshots/{snapshotRef}/content",
        operation_id="readLiveWorkspaceContent",
        tags=["Live workspace"],
        response_class=Response,
        responses=_error_responses(400, 401, 403, 404, 409, 410, 413, 422, 500, 503),
    )
    def read_live_workspace_content(
        job_ref: Annotated[str, ApiPath(alias="jobRef", pattern=_OPAQUE_REF_PATTERN)],
        snapshot_ref: Annotated[
            str, ApiPath(alias="snapshotRef", pattern=_OPAQUE_REF_PATTERN)
        ],
        path: Annotated[str, Query(min_length=1, max_length=4096)],
        offset: Annotated[int, Query(ge=0)] = 0,
        limit_bytes: Annotated[
            int, Query(alias="limitBytes", ge=1, le=1048576)
        ] = 1048576,
    ) -> Response:
        result = provider.read_live_workspace_content(
            job_ref,
            snapshot_ref,
            path,
            offset=offset,
            limit_bytes=limit_bytes,
        )
        content_range = (
            "bytes */0"
            if result.total_size == 0
            else f"bytes {result.offset}-{result.end_offset - 1}/{result.total_size}"
        )
        return Response(
            content=result.content,
            media_type="application/octet-stream",
            headers={
                "Cache-Control": "no-store",
                "ETag": result.snapshot_digest,
                "Content-Range": content_range,
                "KCS-Content-SHA256": result.content_sha256,
                "KCS-Snapshot-Sequence": str(result.sequence),
            },
        )

    @router.get(
        "/api/v2/jobs/{jobRef}/workspace/live-snapshots/{snapshotRef}/diff",
        operation_id="getLiveWorkspaceDiff",
        tags=["Live workspace"],
        response_model=LiveWorkspaceDiffPage,
        responses=_error_responses(400, 401, 403, 404, 409, 410, 500, 503),
    )
    def get_live_workspace_diff(
        job_ref: Annotated[str, ApiPath(alias="jobRef", pattern=_OPAQUE_REF_PATTERN)],
        snapshot_ref: Annotated[
            str, ApiPath(alias="snapshotRef", pattern=_OPAQUE_REF_PATTERN)
        ],
        page_token: Annotated[
            str | None, Query(alias="pageToken", pattern=_OPAQUE_TOKEN_PATTERN)
        ] = None,
        page_size: Annotated[
            int, Query(alias="pageSize", ge=1, le=MAX_PAGE_SIZE)
        ] = DEFAULT_PAGE_SIZE,
    ) -> Response:
        page = provider.get_live_workspace_diff(
            job_ref,
            snapshot_ref,
            page_token=page_token,
            page_size=page_size,
        )
        response = _json_model(page)
        response.headers["ETag"] = str(page.root["snapshotDigest"])
        return response

    @router.post(
        "/api/v2/jobs/{jobRef}/dev-sessions",
        operation_id="createDevSession",
        tags=["Dev sessions"],
        status_code=201,
        response_model=DevSessionSnapshot,
        responses=_error_responses(200, 400, 401, 403, 404, 409, 410, 415, 422, 500, 503),
    )
    def create_dev_session(
        job_ref: Annotated[
            str, ApiPath(alias="jobRef", min_length=1, max_length=256, pattern=_OPAQUE_REF_PATTERN)
        ],
        payload: DevSessionCreateRequest,
    ) -> Response:
        result = provider.create_dev_session(job_ref, payload)
        headers = {"KCS-Dev-Session-Credential": result.credential or ""}
        response = _json_model(result.snapshot, status_code=201 if result.created else 200)
        response.headers.update(headers)
        return response

    @router.get(
        "/api/v2/jobs/{jobRef}/dev-sessions/{devSessionRef}",
        operation_id="inspectDevSession",
        tags=["Dev sessions"],
        response_model=DevSessionSnapshot,
        responses=_error_responses(401, 403, 404, 409, 410, 500, 503),
    )
    def inspect_dev_session(
        job_ref: Annotated[str, ApiPath(alias="jobRef", pattern=_OPAQUE_REF_PATTERN)],
        dev_session_ref: Annotated[
            str, ApiPath(alias="devSessionRef", pattern=_OPAQUE_REF_PATTERN)
        ],
        credential: Annotated[
            str,
            Header(
                alias="KCS-Dev-Session-Credential",
                min_length=32,
                max_length=128,
                pattern=_OPAQUE_TOKEN_PATTERN,
            ),
        ],
    ) -> Response:
        return _json_model(
            provider.inspect_dev_session(job_ref, dev_session_ref, credential)
        )

    @router.post(
        "/api/v2/jobs/{jobRef}/dev-sessions/{devSessionRef}/renew",
        operation_id="renewDevSession",
        tags=["Dev sessions"],
        response_model=DevSessionSnapshot,
        responses=_error_responses(400, 401, 403, 404, 409, 410, 415, 422, 500, 503),
    )
    def renew_dev_session(
        job_ref: Annotated[str, ApiPath(alias="jobRef", pattern=_OPAQUE_REF_PATTERN)],
        dev_session_ref: Annotated[
            str, ApiPath(alias="devSessionRef", pattern=_OPAQUE_REF_PATTERN)
        ],
        payload: DevSessionRenewRequest,
        credential: Annotated[
            str,
            Header(
                alias="KCS-Dev-Session-Credential",
                min_length=32,
                max_length=128,
                pattern=_OPAQUE_TOKEN_PATTERN,
            ),
        ],
    ) -> Response:
        result = provider.renew_dev_session(
            job_ref, dev_session_ref, credential, payload
        )
        response = _json_model(result.snapshot)
        response.headers["KCS-Dev-Session-Credential"] = result.credential or ""
        return response

    @router.delete(
        "/api/v2/jobs/{jobRef}/dev-sessions/{devSessionRef}",
        operation_id="revokeDevSession",
        tags=["Dev sessions"],
        response_model=DevSessionSnapshot,
        responses=_error_responses(401, 403, 404, 409, 410, 500, 503),
    )
    def revoke_dev_session(
        job_ref: Annotated[str, ApiPath(alias="jobRef", pattern=_OPAQUE_REF_PATTERN)],
        dev_session_ref: Annotated[
            str, ApiPath(alias="devSessionRef", pattern=_OPAQUE_REF_PATTERN)
        ],
        credential: Annotated[
            str,
            Header(
                alias="KCS-Dev-Session-Credential",
                min_length=32,
                max_length=128,
                pattern=_OPAQUE_TOKEN_PATTERN,
            ),
        ],
    ) -> Response:
        return _json_model(provider.revoke_dev_session(job_ref, dev_session_ref, credential))

    @router.get(
        "/api/v2/jobs/{jobRef}/dev-sessions/{devSessionRef}/relay",
        operation_id="relayDevSession",
        tags=["Dev sessions"],
        response_class=Response,
        responses=_error_responses(401, 403, 404, 409, 410, 500, 503),
    )
    def relay_dev_session(
        request: Request,
        job_ref: Annotated[str, ApiPath(alias="jobRef", pattern=_OPAQUE_REF_PATTERN)],
        dev_session_ref: Annotated[
            str, ApiPath(alias="devSessionRef", pattern=_OPAQUE_REF_PATTERN)
        ],
        path: Annotated[str, Query(min_length=1, max_length=4096, pattern=r"^/")],
        credential: Annotated[
            str,
            Header(
                alias="KCS-Dev-Session-Credential",
                min_length=32,
                max_length=128,
                pattern=_OPAQUE_TOKEN_PATTERN,
            ),
        ],
    ) -> Response:
        target = provider.dev_session_relay_target(
            job_ref, dev_session_ref, credential, path
        )
        forward_headers = {
            name: value
            for name, value in request.headers.items()
            if name.casefold()
            in {"accept", "accept-encoding", "accept-language", "range", "if-none-match", "if-modified-since", "user-agent"}
        }
        forward_headers["X-RC-Dev-Session-Credential"] = credential
        try:
            upstream = requests.get(
                f"http://{target.host}:{target.port}{target.path}",
                headers=forward_headers,
                allow_redirects=False,
                stream=True,
                timeout=(3, 30),
            )
            upstream.raw.decode_content = False
        except requests.RequestException as error:
            raise DevSessionRelayDownError() from error
        if upstream.status_code in {401, 410, 429, 503}:
            upstream.close()
            raise DevSessionRelayDownError()
        provider.observe_dev_session_relay_ready(
            job_ref, dev_session_ref, credential
        )
        headers = {
            name: value
            for name, value in upstream.headers.items()
            if name.casefold() in _DEV_RELAY_RESPONSE_HEADERS
        }
        location = upstream.headers.get("Location")
        if location:
            parsed = urlsplit(location)
            relocated = parsed.path or "/"
            if parsed.query:
                relocated += f"?{parsed.query}"
            headers["Location"] = (
                f"/api/v2/jobs/{quote(job_ref, safe='')}/dev-sessions/"
                f"{quote(dev_session_ref, safe='')}/relay?path={quote(relocated, safe='')}"
            )
        headers["Cache-Control"] = "no-store"
        media_type = headers.pop("Content-Type", headers.pop("content-type", None))
        def relay_chunks() -> Iterator[bytes]:
            try:
                yield from upstream.raw.stream(64 * 1024, decode_content=False)
            finally:
                upstream.close()

        return StreamingResponse(
            relay_chunks(),
            status_code=upstream.status_code,
            media_type=media_type,
            headers=headers,
            background=BackgroundTask(upstream.close),
        )

    @router.post(
        "/api/v2/jobs",
        operation_id="createJob",
        tags=["Jobs"],
        status_code=201,
        response_model=JobBindingSnapshot | NativeJobBindingSnapshot,
        responses={
            200: {
                "model": JobBindingSnapshot | NativeJobBindingSnapshot,
                "description": "Stable create replay.",
            },
            **_error_responses(400, 401, 403, 409, 410, 413, 415, 422, 429, 500, 503, 504),
        },
    )
    def create_job(payload: CreateJobRequest | NativeCreateJobRequest) -> Response:
        result = provider.create(payload)
        return _json_model(result.snapshot, status_code=201 if result.created else 200)

    @router.get(
        "/api/v2/jobs",
        operation_id="listJobs",
        tags=["Jobs"],
        response_model=JobBindingSnapshotList | AnyJobBindingSnapshotList,
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
        response_model=JobBindingSnapshot | NativeJobBindingSnapshot,
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
        response_model=RoleLogs | NativeRoleLogs,
        responses=_error_responses(400, 401, 403, 404, 409, 410, 500, 503),
    )
    def get_role_logs(
        job_ref: Annotated[
            str,
            ApiPath(alias="jobRef", min_length=1, max_length=256, pattern=_OPAQUE_REF_PATTERN),
        ],
        container: Annotated[Literal["agent", "workspace", "runner", "control"], Query()],
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

    @router.get(
        "/api/v2/jobs/{jobRef}/telemetry/nvidia",
        operation_id="getNvidiaTelemetry",
        tags=["Cluster observations"],
        response_model=NvidiaTelemetrySnapshot,
        responses=_error_responses(401, 403, 404, 409, 410, 500, 503, 504),
    )
    def get_nvidia_telemetry(
        job_ref: Annotated[
            str,
            ApiPath(alias="jobRef", min_length=1, max_length=256, pattern=_OPAQUE_REF_PATTERN),
        ],
    ) -> Response:
        return _json_model(provider.nvidia_telemetry(job_ref))

    @router.post(
        "/api/v2/jobs/{jobRef}/workspace/terminal-sessions",
        operation_id="createTerminalSession",
        tags=["Workspace terminal"],
        status_code=201,
        response_model=TerminalSessionSnapshot | NativeTerminalSessionSnapshot,
        responses={
            200: {
                "model": TerminalSessionSnapshot | NativeTerminalSessionSnapshot,
                "description": "Stable session replay.",
            },
            **_error_responses(400, 401, 403, 404, 409, 410, 415, 422, 500, 503, 504),
        },
    )
    def create_terminal_session(
        job_ref: Annotated[
            str,
            ApiPath(alias="jobRef", min_length=1, max_length=256, pattern=_OPAQUE_REF_PATTERN),
        ],
        payload: TerminalCreateRequest,
    ) -> Response:
        result = provider.create_terminal(job_ref, payload)
        response = _json_model(result.snapshot, status_code=201 if result.created else 200)
        response.headers["KCS-Terminal-Credential"] = result.credential
        return response

    @router.get(
        "/api/v2/jobs/{jobRef}/workspace/terminal-sessions/{terminalRef}",
        operation_id="inspectTerminalSession",
        tags=["Workspace terminal"],
        response_model=TerminalSessionSnapshot | NativeTerminalSessionSnapshot,
        responses=_error_responses(401, 403, 404, 409, 410, 500, 503),
    )
    def inspect_terminal_session(
        job_ref: Annotated[
            str,
            ApiPath(alias="jobRef", min_length=1, max_length=256, pattern=_OPAQUE_REF_PATTERN),
        ],
        terminal_ref: Annotated[
            str,
            ApiPath(alias="terminalRef", min_length=1, max_length=256, pattern=_OPAQUE_REF_PATTERN),
        ],
        subject_ref: Annotated[str, Header(alias="KCS-Subject-Ref")],
        credential: Annotated[str, Header(alias="KCS-Terminal-Credential")],
    ) -> Response:
        return _json_model(
            provider.inspect_terminal(
                job_ref, terminal_ref, subject_ref=subject_ref, credential=credential
            )
        )

    @router.post(
        "/api/v2/jobs/{jobRef}/workspace/terminal-sessions/{terminalRef}/input",
        operation_id="writeTerminalInput",
        tags=["Workspace terminal"],
        response_model=TerminalSessionSnapshot | NativeTerminalSessionSnapshot,
        responses=_error_responses(400, 401, 403, 404, 409, 410, 413, 415, 500, 503),
    )
    async def write_terminal_input(
        request: Request,
        job_ref: Annotated[str, ApiPath(alias="jobRef")],
        terminal_ref: Annotated[str, ApiPath(alias="terminalRef")],
        subject_ref: Annotated[str, Header(alias="KCS-Subject-Ref")],
        credential: Annotated[str, Header(alias="KCS-Terminal-Credential")],
    ) -> Response:
        content = await _terminal_input_body(request)
        return _json_model(
            await asyncio.to_thread(
                provider.write_terminal,
                job_ref,
                terminal_ref,
                content,
                subject_ref=subject_ref,
                credential=credential,
            )
        )

    @router.get(
        "/api/v2/jobs/{jobRef}/workspace/terminal-sessions/{terminalRef}/output",
        operation_id="readTerminalOutput",
        tags=["Workspace terminal"],
        responses=_error_responses(400, 401, 403, 404, 409, 410, 500, 503),
    )
    def read_terminal_output(
        job_ref: Annotated[str, ApiPath(alias="jobRef")],
        terminal_ref: Annotated[str, ApiPath(alias="terminalRef")],
        subject_ref: Annotated[str, Header(alias="KCS-Subject-Ref")],
        credential: Annotated[str, Header(alias="KCS-Terminal-Credential")],
        cursor: Annotated[int, Query(ge=0)] = 0,
        limit_bytes: Annotated[int, Query(alias="limitBytes", ge=1, le=65536)] = 65536,
    ) -> Response:
        content, next_cursor, open_state, _snapshot = provider.read_terminal(
            job_ref,
            terminal_ref,
            cursor=cursor,
            limit_bytes=limit_bytes,
            subject_ref=subject_ref,
            credential=credential,
        )
        return Response(
            content=content,
            media_type="application/octet-stream",
            headers={
                "KCS-Terminal-Next-Cursor": str(next_cursor),
                "KCS-Terminal-Open": "true" if open_state else "false",
            },
        )

    @router.post(
        "/api/v2/jobs/{jobRef}/workspace/terminal-sessions/{terminalRef}/resize",
        operation_id="resizeTerminalSession",
        tags=["Workspace terminal"],
        response_model=TerminalSessionSnapshot | NativeTerminalSessionSnapshot,
        responses=_error_responses(400, 401, 403, 404, 409, 410, 415, 422, 500, 503),
    )
    def resize_terminal_session(
        job_ref: Annotated[str, ApiPath(alias="jobRef")],
        terminal_ref: Annotated[str, ApiPath(alias="terminalRef")],
        subject_ref: Annotated[str, Header(alias="KCS-Subject-Ref")],
        credential: Annotated[str, Header(alias="KCS-Terminal-Credential")],
        payload: TerminalResizeRequest,
    ) -> Response:
        return _json_model(
            provider.resize_terminal(
                job_ref,
                terminal_ref,
                rows=payload.rows,
                columns=payload.columns,
                subject_ref=subject_ref,
                credential=credential,
            )
        )

    @router.delete(
        "/api/v2/jobs/{jobRef}/workspace/terminal-sessions/{terminalRef}",
        operation_id="closeTerminalSession",
        tags=["Workspace terminal"],
        response_model=TerminalSessionSnapshot | NativeTerminalSessionSnapshot,
        responses=_error_responses(401, 403, 404, 409, 410, 500, 503),
    )
    def close_terminal_session(
        job_ref: Annotated[str, ApiPath(alias="jobRef")],
        terminal_ref: Annotated[str, ApiPath(alias="terminalRef")],
        subject_ref: Annotated[str, Header(alias="KCS-Subject-Ref")],
        credential: Annotated[str, Header(alias="KCS-Terminal-Credential")],
    ) -> Response:
        return _json_model(
            provider.close_terminal(
                job_ref, terminal_ref, subject_ref=subject_ref, credential=credential
            )
        )

    @router.post(
        "/api/v2/jobs/{jobRef}/runner/credential-grants",
        operation_id="grantRunnerCredential",
        tags=["Credentials"],
        status_code=201,
        response_model=RunnerCredentialGrantSnapshot,
        responses={
            200: {
                "model": RunnerCredentialGrantSnapshot,
                "description": "Stable runner credential replay.",
            },
            **_error_responses(400, 401, 403, 404, 409, 413, 415, 422, 500, 503),
        },
    )
    async def grant_runner_credential(
        request: Request,
        job_ref: Annotated[
            str,
            ApiPath(
                alias="jobRef",
                min_length=1,
                max_length=256,
                pattern=_OPAQUE_REF_PATTERN,
            ),
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
        credential_kind: Annotated[
            Literal["modelGatewayToken"], Header(alias="KCS-Credential-Kind")
        ],
        agent_run_ref: Annotated[
            str,
            Header(
                alias="KCS-Agent-Run-Ref",
                min_length=1,
                max_length=256,
                pattern=_OPAQUE_REF_PATTERN,
            ),
        ],
        generation: Annotated[int, Header(alias="KCS-Generation", ge=1)],
        native_launch_digest: Annotated[
            str, Header(alias="KCS-Native-Launch-Digest", pattern=_SHA256_PATTERN)
        ],
        audience: Annotated[
            str,
            Header(
                alias="KCS-Audience",
                min_length=1,
                max_length=256,
                pattern=_OPAQUE_REF_PATTERN,
            ),
        ],
        job_uid: Annotated[UUID, Header(alias="KCS-Job-UID")],
        pod_uid: Annotated[UUID, Header(alias="KCS-Pod-UID")],
        projection_ttl_seconds: Annotated[
            int, Header(alias="KCS-Projection-TTL-Seconds", ge=120, le=900)
        ],
    ) -> Response:
        metadata = RunnerCredentialGrantMetadata(
            credential_grant_ref=credential_grant_ref,
            credential_sha256=credential_sha256,
            grant_metadata_digest=grant_metadata_digest,
            kind=credential_kind,
            agent_run_ref=agent_run_ref,
            generation=generation,
            native_launch_digest=native_launch_digest,
            audience=audience,
            projection_ttl_seconds=projection_ttl_seconds,
            job_uid=str(job_uid),
            pod_uid=str(pod_uid),
        )
        credential = await _credential_body(request)
        result = await asyncio.to_thread(
            provider.grant_runner_credential_result,
            job_ref,
            metadata,
            credential,
        )
        return _json_model(result.snapshot, status_code=201 if result.created else 200)

    @router.get(
        "/api/v2/jobs/{jobRef}/runner/credential-grants/{credentialGrantRef}",
        operation_id="inspectRunnerCredentialGrant",
        tags=["Credentials"],
        response_model=RunnerCredentialGrantSnapshot,
        responses=_error_responses(401, 403, 404, 409, 500, 503),
    )
    def inspect_runner_credential_grant(
        job_ref: Annotated[str, ApiPath(alias="jobRef")],
        credential_grant_ref: Annotated[str, ApiPath(alias="credentialGrantRef")],
    ) -> Response:
        return _json_model(provider.inspect_runner_credential_grant(job_ref, credential_grant_ref))

    @router.post(
        "/api/v2/jobs/{jobRef}/runner/start",
        operation_id="startRunner",
        tags=["Jobs"],
        status_code=202,
        response_model=NativeRunnerGenerationSnapshot,
        responses={
            200: {
                "model": NativeRunnerGenerationSnapshot,
                "description": "Stable runner generation replay.",
            },
            **_error_responses(400, 401, 403, 404, 409, 415, 422, 500, 503, 504),
        },
    )
    def start_runner(
        job_ref: Annotated[str, ApiPath(alias="jobRef")],
        payload: RunnerStartRequest,
    ) -> Response:
        result = provider.start_runner(job_ref, payload)
        return _json_model(result, status_code=200 if result.root["replayed"] else 202)

    @router.post(
        "/api/v2/jobs/{jobRef}/runner/stop",
        operation_id="stopRunner",
        tags=["Jobs"],
        status_code=202,
        response_model=RunnerStopSnapshot,
        responses={
            200: {
                "model": RunnerStopSnapshot,
                "description": "Stable runner stop replay.",
            },
            **_error_responses(400, 401, 403, 404, 409, 415, 422, 500, 503, 504),
        },
    )
    def stop_runner(
        job_ref: Annotated[str, ApiPath(alias="jobRef")],
        payload: RunnerStopRequest,
    ) -> Response:
        result = provider.stop_runner(job_ref, payload)
        return _json_model(result.snapshot, status_code=202 if result.created else 200)

    @router.post(
        "/api/v2/jobs/{jobRef}/agent/credential-grants",
        operation_id="grantCredential",
        tags=["Credentials"],
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
        credential = await _credential_body(request)
        result = await asyncio.to_thread(
            provider.grant_credential_result,
            job_ref,
            metadata,
            credential,
        )
        return _json_model(result.snapshot, status_code=201 if result.created else 200)

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
        transfer = await asyncio.to_thread(provider.inspect_transfer, job_ref, transfer_ref)
        if (
            transfer.spec.content_sha256 != content_sha256
            or content_length != transfer.spec.declared_size_bytes
            or content_length > transfer.spec.authorized_max_size_bytes
        ):
            raise TransferBytesMismatchError()
        path = await _transfer_body_file(request, content_length)
        try:
            with path.open("rb") as stream:
                snapshot = await asyncio.to_thread(
                    provider.stage_transfer_content,
                    job_ref,
                    transfer_ref,
                    stream,
                    content_length=content_length,
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
            _content_chunks(content),
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
        return _json_model(result.snapshot, status_code=202 if result.created else 200)

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
        response_model=JobBindingSnapshot | NativeJobBindingSnapshot,
        responses=_error_responses(400, 401, 403, 404, 409, 415, 422, 500, 503, 504),
    )
    def finalize_job(
        job_ref: Annotated[
            str, ApiPath(alias="jobRef", min_length=1, max_length=256, pattern=_OPAQUE_REF_PATTERN)
        ],
        payload: FinalizeJobRequest | NativeFinalizeJobRequest,
    ) -> Response:
        result = provider.finalize(job_ref, payload)
        return _json_model(result.snapshot, status_code=202 if result.created else 200)

    @router.post(
        "/api/v2/jobs/{jobRef}/cancel",
        operation_id="cancelJob",
        tags=["Jobs"],
        status_code=202,
        response_model=JobBindingSnapshot | NativeJobBindingSnapshot,
        responses=_error_responses(400, 401, 403, 404, 409, 415, 422, 500, 503, 504),
    )
    def cancel_job(
        job_ref: Annotated[
            str, ApiPath(alias="jobRef", min_length=1, max_length=256, pattern=_OPAQUE_REF_PATTERN)
        ],
        payload: CancelJobRequest,
    ) -> Response:
        result = provider.cancel(job_ref, payload)
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


def install_dev_session_websocket(
    app: FastAPI,
    provider: V2JobProvider,
    service_token: str,
) -> None:
    """Install the WebSocket half of the frozen HTTP/upgrade relay route.

    FastAPI's HTTP dependency stack doesn't run for WebSocket upgrades, so this
    adapter repeats the same service-token check before resolving the exact Pod
    binding.  The browser credential reaches only the private relay sidecar;
    OpenVSCode itself still owns no KCS or ResearchCosmos credential.
    """

    expected_token = hashlib.sha256(service_token.encode("utf-8")).digest()

    @app.websocket(
        "/api/v2/jobs/{job_ref}/dev-sessions/{dev_session_ref}/relay",
        name="relayDevSessionWebSocket",
    )
    async def relay_dev_session_websocket(
        websocket: WebSocket,
        job_ref: str,
        dev_session_ref: str,
    ) -> None:
        authorization = websocket.headers.get("authorization", "")
        scheme, separator, supplied_token = authorization.partition(" ")
        authenticated = (
            separator == " "
            and scheme.casefold() == "bearer"
            and hmac.compare_digest(
                hashlib.sha256(supplied_token.encode("utf-8")).digest(),
                expected_token,
            )
        )
        credential = websocket.headers.get("kcs-dev-session-credential", "")
        relay_path = websocket.query_params.get("path", "")
        if not authenticated or not credential:
            await websocket.close(code=4401, reason="unauthenticated")
            return
        if not relay_path.startswith("/") or len(relay_path) > 4096:
            await websocket.close(code=4400, reason="invalid relay path")
            return
        try:
            target = await asyncio.to_thread(
                provider.dev_session_relay_target,
                job_ref,
                dev_session_ref,
                credential,
                relay_path,
            )
        except KcsV2Error as error:
            await websocket.close(
                code=4410 if error.status_code == 410 else 4403,
                reason=error.code,
            )
            return

        offered = websocket.headers.get("sec-websocket-protocol", "")
        subprotocols = [item.strip() for item in offered.split(",") if item.strip()]
        try:
            async with websocket_connect(
                f"ws://{target.host}:{target.port}{target.path}",
                additional_headers={"X-RC-Dev-Session-Credential": credential},
                subprotocols=subprotocols or None,
                open_timeout=3,
                close_timeout=3,
                max_size=8 * 1024 * 1024,
            ) as upstream:
                await asyncio.to_thread(
                    provider.observe_dev_session_relay_ready,
                    job_ref,
                    dev_session_ref,
                    credential,
                )
                await websocket.accept(subprotocol=upstream.subprotocol)

                async def browser_to_relay() -> None:
                    while True:
                        message = await websocket.receive()
                        kind = message.get("type")
                        if kind == "websocket.disconnect":
                            return
                        if message.get("bytes") is not None:
                            await upstream.send(message["bytes"])
                        elif message.get("text") is not None:
                            await upstream.send(message["text"])

                async def relay_to_browser() -> None:
                    async for message in upstream:
                        if isinstance(message, bytes):
                            await websocket.send_bytes(message)
                        else:
                            await websocket.send_text(message)

                tasks = {
                    asyncio.create_task(browser_to_relay()),
                    asyncio.create_task(relay_to_browser()),
                }
                done, pending = await asyncio.wait(
                    tasks, return_when=asyncio.FIRST_COMPLETED
                )
                for task in pending:
                    task.cancel()
                await asyncio.gather(*pending, return_exceptions=True)
                for task in done:
                    task.result()
        except (ConnectionClosed, DevSessionRelayDownError):
            if websocket.client_state.name != "DISCONNECTED":
                await websocket.close(code=1011, reason="relay disconnected")
        except Exception:
            log.exception("dev-session WebSocket relay failed jobRef=%s", job_ref)
            if websocket.client_state.name != "DISCONNECTED":
                await websocket.close(code=1013, reason="relay unavailable")


__all__ = ["V2Caller", "create_jobs_router", "install_dev_session_websocket"]
