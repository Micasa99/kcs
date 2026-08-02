"""Typed, sanitized errors for the KCS V2 job provider."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True, slots=True)
class ErrorDetail:
    """One public validation detail; values must never contain secret material."""

    field: str
    reason: str


class KcsV2Error(Exception):
    """Base domain error that can be rendered as the canonical V2 error envelope."""

    code = "INTERNAL_ERROR"
    status_code = 500
    retryable = False
    recovery_action = "none"
    default_message = "The provider could not complete the request"

    def __init__(
        self,
        message: str | None = None,
        *,
        details: Sequence[ErrorDetail] = (),
        context: Mapping[str, Any] | None = None,
    ) -> None:
        self.message = message or self.default_message
        self.details = tuple(details)
        self.context = dict(context) if context is not None else None
        super().__init__(self.message)

    def to_envelope(self, request_id: str) -> dict[str, object]:
        """Return the public OpenAPI error shape without retaining a raw cause."""

        error: dict[str, object] = {
            "code": self.code,
            "message": self.message,
            "retryable": self.retryable,
            "recoveryAction": self.recovery_action,
            "requestId": request_id,
        }
        if self.details:
            error["details"] = [
                {"field": detail.field, "reason": detail.reason} for detail in self.details
            ]
        if self.context is not None:
            error["context"] = self.context
        return {"error": error}


class InvalidRequestError(KcsV2Error):
    code = "INVALID_REQUEST"
    status_code = 400
    default_message = "The request is invalid"


class DigestMismatchError(KcsV2Error):
    code = "DIGEST_MISMATCH"
    status_code = 422
    default_message = "The supplied digest does not match the request payload"


class PreconditionFailedError(KcsV2Error):
    code = "PRECONDITION_FAILED"
    status_code = 422
    recovery_action = "inspect_job"
    default_message = "Required staged runtime material is not ready for agent start"


class InvalidCursorError(KcsV2Error):
    code = "INVALID_CURSOR"
    status_code = 400
    default_message = "The log cursor is invalid"


class StaleCursorError(KcsV2Error):
    code = "STALE_CURSOR"
    status_code = 409
    recovery_action = "inspect_job"
    default_message = "The log cursor no longer matches the immutable workload"


class InvalidPageTokenError(KcsV2Error):
    code = "INVALID_PAGE_TOKEN"
    status_code = 400
    default_message = "The page token is invalid"


class StalePageTokenError(KcsV2Error):
    code = "STALE_PAGE_TOKEN"
    status_code = 409
    default_message = "The page token does not match the current query"


class IdentityDigestConflictError(KcsV2Error):
    code = "IDENTITY_CONFLICT"
    status_code = 409
    recovery_action = "inspect_job"
    default_message = "The retained identity is bound to different request data"


# The execution plan and provider API use this concise public name.
IdentityDigestConflict = IdentityDigestConflictError


class GrantIdentityConflictError(IdentityDigestConflictError):
    recovery_action = "inspect_grant"


class TransferIdentityConflictError(IdentityDigestConflictError):
    recovery_action = "inspect_transfer"


class OperationIdentityConflictError(IdentityDigestConflictError):
    recovery_action = "inspect_operation"


class StateConflictError(KcsV2Error):
    code = "STATE_CONFLICT"
    status_code = 409
    recovery_action = "inspect_job"
    default_message = "The job is not in a state that permits this operation"


class OperationIndeterminateError(StateConflictError):
    code = "OPERATION_INDETERMINATE"
    recovery_action = "inspect_operation"
    default_message = "A requested operation has indeterminate retained state"


class TransferIndeterminateError(StateConflictError):
    code = "TRANSFER_INDETERMINATE"
    recovery_action = "inspect_transfer"
    default_message = "A requested transfer has indeterminate retained state"


class TransferBytesMismatchError(StateConflictError):
    code = "TRANSFER_BYTES_MISMATCH"
    recovery_action = "inspect_transfer"
    default_message = "The streamed bytes do not match the registered transfer"


class OverwriteForbiddenError(StateConflictError):
    code = "OVERWRITE_FORBIDDEN"
    recovery_action = "inspect_transfer"
    default_message = "The transfer would overwrite workspace content without authority"


class UnsafePathError(KcsV2Error):
    code = "UNSAFE_PATH"
    status_code = 422
    default_message = "The transfer path is unsafe in the bound workspace"


class IllegalGenerationError(KcsV2Error):
    code = "ILLEGAL_GENERATION"
    status_code = 409
    recovery_action = "inspect_job"
    default_message = "The requested agent generation is not legal for this supervisor"


class CredentialActiveError(KcsV2Error):
    code = "CREDENTIAL_ACTIVE"
    status_code = 409
    recovery_action = "inspect_grant"
    default_message = "Another credential grant is still active"


class CredentialExpiredError(KcsV2Error):
    code = "CREDENTIAL_EXPIRED"
    status_code = 409
    recovery_action = "inspect_grant"
    default_message = "The credential grant is no longer usable"


class CredentialDestroyFailedError(KcsV2Error):
    code = "CREDENTIAL_DESTROY_FAILED"
    status_code = 500
    recovery_action = "reconcile"
    default_message = "The projected credential could not be destroyed"


class PayloadTooLargeError(KcsV2Error):
    code = "PAYLOAD_TOO_LARGE"
    status_code = 413
    default_message = "The request body exceeds the allowed size"


class ReplacementPodError(KcsV2Error):
    code = "REPLACEMENT_POD"
    status_code = 409
    recovery_action = "new_attempt"
    default_message = "The Job has multiple or replacement Pod identities"


class StaleBindingError(KcsV2Error):
    code = "STALE_BINDING"
    status_code = 409
    recovery_action = "new_attempt"
    default_message = "The supplied immutable Job or Pod binding is stale"


class TombstonedError(KcsV2Error):
    code = "TOMBSTONED"
    status_code = 410
    recovery_action = "inspect_job"
    default_message = "The retained provider identity has been deleted"

    def __init__(self, tombstone: Mapping[str, Any]) -> None:
        super().__init__(context={"tombstone": dict(tombstone)})


class JobNotFoundError(KcsV2Error):
    code = "NOT_FOUND"
    status_code = 404
    default_message = "The requested job was not found"


class DependencyUnavailableError(KcsV2Error):
    code = "DEPENDENCY_UNAVAILABLE"
    status_code = 503
    retryable = True
    recovery_action = "retry_same"
    default_message = "Kubernetes state is temporarily unavailable"


class DependencyTimeoutError(KcsV2Error):
    code = "DEPENDENCY_TIMEOUT"
    status_code = 504
    retryable = True
    recovery_action = "retry_same"
    default_message = "Kubernetes did not confirm the operation before the timeout"
