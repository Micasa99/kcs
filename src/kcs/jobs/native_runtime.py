"""Durable native-runner grant, start, stop, and launcher lifecycle."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, Protocol

from .canonical import canonical_digest
from .errors import (
    CredentialDestroyFailedError,
    DependencyUnavailableError,
    DigestMismatchError,
    IdentityDigestConflict,
    JobNotFoundError,
    PreconditionFailedError,
    RunnerCredentialActiveError,
    RunnerCredentialExpiredError,
    RunnerGrantIdentityConflictError,
    StaleBindingError,
    StateConflictError,
)
from .native_contracts import (
    NativeFinalizeJobRequest,
    NativeRunnerGenerationSnapshot,
    RunnerCredentialGrantSnapshot,
    RunnerStartRequest,
    RunnerStopRequest,
    RunnerStopSnapshot,
)
from .renderer import runner_credential_secret_name
from .transport import WorkspaceRpcTransportProtocol


class NativeStoreProtocol(Protocol):
    def reserve_runtime(
        self, kind: str, identity: str, job_ref: str, values: Mapping[str, str]
    ) -> tuple[object, bool]: ...

    def read_runtime(self, kind: str, job_ref: str, identity: str) -> object | None: ...

    def list_runtime(
        self, kind: str, job_ref: str | None = None, *, strict: bool = False
    ) -> Sequence[object]: ...

    def update_runtime(
        self, kind: str, job_ref: str, identity: str, values: Mapping[str, str]
    ) -> object: ...


class NativeKubeProtocol(Protocol):
    def create_secret(self, body: object) -> object: ...

    def read_secret(self, name: str) -> object | None: ...

    def delete_secret(self, name: str, secret_uid: str) -> bool: ...


@dataclass(frozen=True, slots=True)
class RunnerCredentialGrantMetadata:
    credential_grant_ref: str
    credential_sha256: str
    grant_metadata_digest: str
    kind: str
    agent_run_ref: str
    generation: int
    native_launch_digest: str
    audience: str
    projection_ttl_seconds: int
    job_uid: str
    pod_uid: str

    def digest_payload(self) -> dict[str, object]:
        return {
            "kind": self.kind,
            "agentRunRef": self.agent_run_ref,
            "generation": self.generation,
            "nativeLaunchDigest": self.native_launch_digest,
            "audience": self.audience,
            "credentialSha256": self.credential_sha256,
            "projectionTtlSeconds": self.projection_ttl_seconds,
            "jobUid": self.job_uid,
            "podUid": self.pod_uid,
        }


@dataclass(frozen=True, slots=True)
class NativeMutationResult:
    snapshot: Any
    created: bool


class NativeRuntimeController:
    """Keep KCS native control facts durable without interpreting research output."""

    def __init__(
        self,
        store: NativeStoreProtocol,
        kube: NativeKubeProtocol,
        transport: WorkspaceRpcTransportProtocol | None,
        *,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._store = store
        self._kube = kube
        self._transport = transport
        self._clock = clock or (lambda: datetime.now(UTC))

    def grant(
        self,
        job_ref: str,
        binding: Mapping[str, Any],
        metadata: RunnerCredentialGrantMetadata,
        raw_bytes: bytes,
    ) -> NativeMutationResult:
        if (
            metadata.kind != "modelGatewayToken"
            or not 120 <= metadata.projection_ttl_seconds <= 900
        ):
            raise PreconditionFailedError("invalid native runner credential policy")
        if len(raw_bytes) > 65536:
            from .errors import PayloadTooLargeError

            raise PayloadTooLargeError()
        if not hmac.compare_digest(
            hashlib.sha256(raw_bytes).hexdigest(), metadata.credential_sha256
        ):
            raise DigestMismatchError()
        if not hmac.compare_digest(
            canonical_digest(metadata.digest_payload()), metadata.grant_metadata_digest
        ):
            raise DigestMismatchError()
        self._require_binding(binding, metadata.job_uid, metadata.pod_uid)
        identity_digest = hashlib.sha256(
            f"{metadata.grant_metadata_digest}:{metadata.credential_sha256}".encode()
        ).hexdigest()
        existing = self._store.read_runtime(
            "runner-credential", job_ref, metadata.credential_grant_ref
        )
        if existing is not None:
            if _values(existing).get("identityDigest") != identity_digest:
                raise RunnerGrantIdentityConflictError()
            retained = self.inspect_grant(job_ref, metadata.credential_grant_ref)
            if retained.root["state"] != "accepted" or retained.root["secretPresent"]:
                return NativeMutationResult(retained, False)
            record = existing
            payload = retained.wire()
            created = False
        else:
            for record in self._store.list_runtime("runner-credential", job_ref):
                snapshot = _runner_grant_snapshot(record)
                if snapshot.root["secretPresent"] and self._now() >= _datetime(
                    snapshot.root["projectionExpiresAt"]
                ):
                    self._destroy_grant(record, "expired")
                    continue
                if snapshot.root["secretPresent"] is not False:
                    raise RunnerCredentialActiveError()
            now = self._now()
            payload = {
                "credentialGrantRef": metadata.credential_grant_ref,
                "kind": "modelGatewayToken",
                "credentialSha256": metadata.credential_sha256,
                "grantMetadataDigest": metadata.grant_metadata_digest,
                "agentRunRef": metadata.agent_run_ref,
                "generation": metadata.generation,
                "nativeLaunchDigest": metadata.native_launch_digest,
                "audience": metadata.audience,
                "projectionTtlSeconds": metadata.projection_ttl_seconds,
                "jobRef": job_ref,
                "jobUid": metadata.job_uid,
                "podUid": metadata.pod_uid,
                "state": "accepted",
                "acceptedAt": now.isoformat(),
                "availableAt": None,
                "acknowledgedAt": None,
                "ackAgentRunRef": None,
                "ackGeneration": None,
                "consumedAt": None,
                "destroyedAt": None,
                "projectionExpiresAt": (
                    now + timedelta(seconds=metadata.projection_ttl_seconds)
                ).isoformat(),
                "tombstoneExpiresAt": (now + timedelta(days=7)).isoformat(),
                "secretPresent": False,
                "destroyFailureReason": None,
                "observedAt": now.isoformat(),
            }
            record, created = self._store.reserve_runtime(
                "runner-credential",
                metadata.credential_grant_ref,
                job_ref,
                {
                    "identityDigest": identity_digest,
                    "jobUid": metadata.job_uid,
                    "podUid": metadata.pod_uid,
                    "payload": _json(payload),
                },
            )
            if not created:
                retained = _runner_grant_snapshot(record)
                if retained.root["state"] != "accepted" or retained.root["secretPresent"]:
                    return NativeMutationResult(retained, False)
                payload = retained.wire()
        try:
            secret = self._kube.read_secret(runner_credential_secret_name(job_ref))
            if secret is None:
                self._kube.create_secret(self._secret(job_ref, metadata, raw_bytes))
            else:
                annotations = _nested(secret, "metadata", "annotations")
                if (
                    not isinstance(annotations, Mapping)
                    or str(annotations.get("researchcosmos.io/job-uid")) != metadata.job_uid
                    or str(annotations.get("researchcosmos.io/pod-uid")) != metadata.pod_uid
                    or str(annotations.get("researchcosmos.io/grant-ref"))
                    != metadata.credential_grant_ref
                    or str(annotations.get("researchcosmos.io/credential-sha256"))
                    != metadata.credential_sha256
                ):
                    raise StaleBindingError("native credential Secret belongs to another grant")
        except Exception as error:
            if isinstance(error, StaleBindingError):
                raise
            raise DependencyUnavailableError("native credential projection was rejected") from error
        payload.update(state="accepted", secretPresent=True, observedAt=self._now().isoformat())
        record = self._store.update_runtime(
            "runner-credential",
            job_ref,
            metadata.credential_grant_ref,
            {**_values(record), "payload": _json(payload)},
        )
        return NativeMutationResult(_runner_grant_snapshot(record), True)

    def inspect_grant(self, job_ref: str, grant_ref: str) -> RunnerCredentialGrantSnapshot:
        record = self._store.read_runtime("runner-credential", job_ref, grant_ref)
        if record is None:
            raise JobNotFoundError()
        snapshot = _runner_grant_snapshot(record)
        payload = snapshot.wire()
        now = self._now()
        if payload["state"] == "accepted" and payload["secretPresent"]:
            try:
                reply = self._rpc(
                    self._binding_from_grant(payload),
                    {
                        "command": "credentialStatus",
                        "requestRef": grant_ref,
                        "generation": int(payload["generation"]),
                    },
                )
            except DependencyUnavailableError:
                reply = {}
            if reply.get("credentialReady") is True and hmac.compare_digest(
                str(reply.get("credentialSha256", "")), str(payload["credentialSha256"])
            ):
                payload.update(
                    state="available", availableAt=now.isoformat(), observedAt=now.isoformat()
                )
                self._store.update_runtime(
                    "runner-credential",
                    job_ref,
                    grant_ref,
                    {**_values(record), "payload": _json(payload)},
                )
                return RunnerCredentialGrantSnapshot.model_validate(payload)
        if payload["secretPresent"] and now >= _datetime(payload["projectionExpiresAt"]):
            self._destroy_grant(record, "expired")
            record = self._store.read_runtime("runner-credential", job_ref, grant_ref)
            if record is None:
                raise DependencyUnavailableError()
            return _runner_grant_snapshot(record)
        payload["observedAt"] = now.isoformat()
        return RunnerCredentialGrantSnapshot.model_validate(payload)

    def start(
        self,
        job_ref: str,
        binding: Mapping[str, Any],
        native_spec: Mapping[str, Any],
        recipe: Mapping[str, Any],
        request: RunnerStartRequest,
        transfer_ready: Callable[[str], bool],
    ) -> NativeRunnerGenerationSnapshot:
        body = request.root
        descriptor = body["descriptor"]
        self._require_binding(binding, descriptor["jobUid"], descriptor["podUid"])
        if (
            descriptor["assemblyDigest"] != native_spec["assemblyDigest"]
            or descriptor["taskPath"] != native_spec["taskPath"]
            or descriptor["selectedModelProtocol"] != native_spec["selectedModelProtocol"]
            or descriptor["recipeDigest"] != recipe["recipeDigest"]
        ):
            raise PreconditionFailedError()
        activation = native_spec.get("capabilityActivation")
        if isinstance(activation, Mapping):
            if (
                descriptor.get("capabilityActivationPlanRef")
                != activation["planRef"]
                or descriptor.get("capabilityActivationPlanDigest")
                != activation["planDigest"]
            ):
                raise PreconditionFailedError(
                    "runner start capability plan differs from the Native Job"
                )
        elif (
            descriptor.get("capabilityActivationPlanRef") is not None
            or descriptor.get("capabilityActivationPlanDigest") is not None
        ):
            raise PreconditionFailedError(
                "runner start declared a capability plan absent from the Native Job"
            )
        if descriptor["selectedModelProtocol"] not in recipe["supportedModelProtocols"]:
            raise PreconditionFailedError("selected model protocol is not supported by recipe")
        if any(not transfer_ready(ref) for ref in descriptor["stagingTransferRefs"]):
            raise PreconditionFailedError("staging transfers are not available")
        identity = str(body["generation"])
        digest = canonical_digest(
            {key: value for key, value in body.items() if key != "generation"}
        )
        existing = self._store.read_runtime("runner-generation", job_ref, identity)
        if existing is not None:
            retained = _runner_generation_snapshot(existing)
            if _values(existing).get("identityDigest") != digest:
                raise IdentityDigestConflict()
            payload = retained.wire()
            if payload["credentialDestroyedAt"] is None:
                grant_record = self._store.read_runtime(
                    "runner-credential", job_ref, descriptor["credentialGrantRef"]
                )
                if grant_record is None:
                    raise DependencyUnavailableError("runner credential record disappeared")
                grant_payload = _runner_grant_snapshot(grant_record).wire()
                if grant_payload["secretPresent"]:
                    destroyed = self._destroy_grant(
                        grant_record,
                        "destroyed",
                        acknowledged_at=_datetime(payload["credentialAcknowledgedAt"]),
                        agent_run_ref=descriptor["agentRunRef"],
                        generation=body["generation"],
                    )
                    destroyed_at = destroyed.root["destroyedAt"]
                else:
                    destroyed_at = grant_payload["destroyedAt"]
                if destroyed_at is None:
                    raise CredentialDestroyFailedError()
                payload["credentialDestroyedAt"] = destroyed_at
                payload["observedAt"] = self._now().isoformat()
                self._store.update_runtime(
                    "runner-generation",
                    job_ref,
                    identity,
                    {**_values(existing), "payload": _json(payload)},
                )
            self._complete_start_intent(job_ref, identity, digest)
            payload["replayed"] = True
            return NativeRunnerGenerationSnapshot.model_validate(payload)
        intent, _intent_created = self._store.reserve_runtime(
            "runner-start",
            identity,
            job_ref,
            {
                "identityDigest": digest,
                "jobUid": str(binding["jobUid"]),
                "podUid": str(binding["podUid"]),
                "requestSpec": request.model_dump_json(),
                "state": "accepted",
            },
        )
        intent_values = _values(intent)
        if (
            intent_values.get("identityDigest") != digest
            or intent_values.get("jobUid") != str(binding["jobUid"])
            or intent_values.get("podUid") != str(binding["podUid"])
            or intent_values.get("requestSpec") != request.model_dump_json()
        ):
            raise IdentityDigestConflict()
        grant = self.inspect_grant(job_ref, descriptor["credentialGrantRef"])
        grant_payload = grant.root
        if (
            grant_payload["state"] != "available"
            or self._now() >= _datetime(grant_payload["projectionExpiresAt"])
            or grant_payload["agentRunRef"] != descriptor["agentRunRef"]
            or grant_payload["generation"] != descriptor["generation"]
            or grant_payload["nativeLaunchDigest"] != body["nativeLaunchDigest"]
            or grant_payload["jobUid"] != descriptor["jobUid"]
            or grant_payload["podUid"] != descriptor["podUid"]
        ):
            raise RunnerCredentialExpiredError()
        reply = self._rpc(
            binding,
            {
                "command": "start",
                "requestRef": f"runner-start-{identity}",
                "generation": body["generation"],
                "nativeLaunchDigest": body["nativeLaunchDigest"],
                "descriptor": descriptor,
            },
        )
        observation = reply.get("runnerObservation")
        if not isinstance(observation, dict):
            raise DependencyUnavailableError("launcher did not return a runner observation")
        now = self._now()
        snapshot = {
            "jobRef": job_ref,
            "generation": body["generation"],
            "agentRunRef": descriptor["agentRunRef"],
            "nativeLaunchDigest": body["nativeLaunchDigest"],
            "credentialGrantRef": descriptor["credentialGrantRef"],
            "runnerStartMetadataDigest": digest,
            "runnerObservation": observation,
            "launcherAlive": bool(reply.get("launcherAlive", True)),
            "softTimerStartedAt": now.isoformat(),
            "softDeadlineAt": (
                now + timedelta(seconds=int(native_spec["runnerDeadlineSeconds"]))
            ).isoformat(),
            "observedAt": now.isoformat(),
            "replayed": False,
            "credentialAcknowledgedAt": now.isoformat(),
            "credentialDestroyedAt": None,
        }
        validated = NativeRunnerGenerationSnapshot.model_validate(snapshot)
        self._store.reserve_runtime(
            "runner-generation",
            identity,
            job_ref,
            {
                "identityDigest": digest,
                "jobUid": str(binding["jobUid"]),
                "podUid": str(binding["podUid"]),
                "payload": _json(validated.root),
            },
        )
        grant_record = self._store.read_runtime(
            "runner-credential", job_ref, descriptor["credentialGrantRef"]
        )
        if grant_record is None:
            raise DependencyUnavailableError()
        destroyed = self._destroy_grant(
            grant_record,
            "destroyed",
            acknowledged_at=now,
            agent_run_ref=descriptor["agentRunRef"],
            generation=body["generation"],
        )
        completed = validated.wire()
        completed["credentialDestroyedAt"] = destroyed.root["destroyedAt"]
        completed["observedAt"] = self._now().isoformat()
        validated = NativeRunnerGenerationSnapshot.model_validate(completed)
        self._store.update_runtime(
            "runner-generation",
            job_ref,
            identity,
            {
                "identityDigest": digest,
                "jobUid": str(binding["jobUid"]),
                "podUid": str(binding["podUid"]),
                "payload": _json(validated.root),
            },
        )
        self._complete_start_intent(job_ref, identity, digest)
        return validated

    def _complete_start_intent(self, job_ref: str, identity: str, digest: str) -> None:
        record = self._store.read_runtime("runner-start", job_ref, identity)
        if record is None:
            return
        values = dict(_values(record))
        if values.get("identityDigest") != digest:
            raise IdentityDigestConflict()
        if values.get("state") == "succeeded":
            return
        values["state"] = "succeeded"
        self._store.update_runtime("runner-start", job_ref, identity, values)

    def refresh_generation(
        self, job_ref: str, binding: Mapping[str, Any]
    ) -> NativeRunnerGenerationSnapshot | None:
        records = list(self._store.list_runtime("runner-generation", job_ref))
        if not records:
            return None
        record = max(records, key=lambda item: int(str(_field(item, "identity"))))
        snapshot = _runner_generation_snapshot(record)
        try:
            reply = self._rpc(
                binding,
                {
                    "command": "inspect",
                    "requestRef": f"runner-inspect-{snapshot.root['generation']}",
                    "generation": snapshot.root["generation"],
                },
            )
        except DependencyUnavailableError:
            return snapshot
        observation = reply.get("runnerObservation")
        if isinstance(observation, dict):
            payload = snapshot.wire()
            payload.update(
                runnerObservation=observation,
                launcherAlive=bool(reply.get("launcherAlive", payload["launcherAlive"])),
                observedAt=self._now().isoformat(),
                replayed=False,
            )
            validated = NativeRunnerGenerationSnapshot.model_validate(payload)
            self._store.update_runtime(
                "runner-generation",
                job_ref,
                str(payload["generation"]),
                {**_values(record), "payload": _json(validated.root)},
            )
            return validated
        return snapshot

    def stop(
        self,
        job_ref: str,
        binding: Mapping[str, Any],
        request: RunnerStopRequest,
    ) -> NativeMutationResult:
        body = request.root
        spec = body["spec"]
        self._require_binding(binding, spec["jobUid"], spec["podUid"])
        existing = self._store.read_runtime("runner-stop", job_ref, body["stopRef"])
        if existing is not None:
            if _values(existing).get("identityDigest") != body["requestDigest"]:
                raise IdentityDigestConflict()
            payload = _runner_stop_snapshot(existing).wire()
            payload["replayed"] = True
            return NativeMutationResult(RunnerStopSnapshot.model_validate(payload), False)
        generation = self.refresh_generation(job_ref, binding)
        if generation is None or generation.root["generation"] != spec["generation"]:
            raise StateConflictError("runner generation is not active")
        reply = self._rpc(
            binding,
            {
                "command": "stop",
                "requestRef": body["stopRef"],
                "generation": spec["generation"],
                "reason": spec["reason"],
            },
        )
        observation = reply.get("runnerObservation")
        if not isinstance(observation, dict):
            raise DependencyUnavailableError("launcher stop returned no observation")
        now = self._now()
        snapshot = {
            "jobRef": job_ref,
            "stopRef": body["stopRef"],
            "requestDigest": body["requestDigest"],
            "binding": {"jobUid": str(binding["jobUid"]), "podUid": str(binding["podUid"])},
            "generation": spec["generation"],
            "state": "succeeded",
            "result": str(reply.get("result", "terminated")),
            "termSentAt": reply.get("termSentAt", now.isoformat()),
            "killSentAt": reply.get("killSentAt"),
            "runnerTerminalAt": reply.get("runnerTerminalAt", now.isoformat()),
            "runnerObservation": observation,
            "observedAt": now.isoformat(),
            "replayed": False,
        }
        validated = RunnerStopSnapshot.model_validate(snapshot)
        self._store.reserve_runtime(
            "runner-stop",
            body["stopRef"],
            job_ref,
            {
                "identityDigest": body["requestDigest"],
                "stopRef": body["stopRef"],
                "jobUid": str(binding["jobUid"]),
                "podUid": str(binding["podUid"]),
                "payload": _json(validated.root),
            },
        )
        self._replace_generation_observation(job_ref, observation)
        return NativeMutationResult(validated, True)

    def finalize(
        self,
        job_ref: str,
        binding: Mapping[str, Any],
        request: NativeFinalizeJobRequest,
        transfers_terminal: Callable[[list[str]], bool],
    ) -> NativeMutationResult:
        body = request.root
        barrier = body["spec"]["captureBarrier"]
        self._require_binding(binding, barrier["jobUid"], barrier["podUid"])
        generation = self.refresh_generation(job_ref, binding)
        if generation is None:
            raise PreconditionFailedError("runner generation is absent")
        observation = generation.root["runnerObservation"]
        if (
            generation.root["generation"] != barrier["generation"]
            or observation["state"] not in {"exited", "killed"}
            or observation["sequence"] != barrier["runnerObservationSequence"]
            or observation["stateDigest"] != barrier["runnerObservationDigest"]
            or set(barrier["capturedTransferRefs"]) != set(body["spec"]["transferRefs"])
            or not transfers_terminal(body["spec"]["transferRefs"])
        ):
            raise PreconditionFailedError("native capture barrier is not ready")
        existing = self._store.read_runtime("native-finalize", job_ref, body["finalizeRef"])
        if existing is not None:
            if _values(existing).get("identityDigest") != body["requestDigest"]:
                raise IdentityDigestConflict()
            record = existing
            payload = dict(json.loads(_values(record)["payload"]))
            created = False
        else:
            payload = {
                "state": "reserved",
                "captureBarrier": barrier,
                "observedAt": self._now().isoformat(),
            }
            record, created = self._store.reserve_runtime(
                "native-finalize",
                body["finalizeRef"],
                job_ref,
                {
                    "identityDigest": body["requestDigest"],
                    "finalizeRef": body["finalizeRef"],
                    "jobUid": str(binding["jobUid"]),
                    "podUid": str(binding["podUid"]),
                    "requestSpec": _json(body),
                    "payload": _json(payload),
                },
            )
            if not created:
                if _values(record).get("identityDigest") != body["requestDigest"]:
                    raise IdentityDigestConflict()
                payload = dict(json.loads(_values(record)["payload"]))
        if payload.get("state") == "succeeded":
            return NativeMutationResult(payload, False)
        if payload.get("state") == "reserved":
            acknowledged = self._inspect_finalize_receipt(binding, body, barrier)
            if not acknowledged:
                try:
                    reply = self._rpc(
                        binding,
                        {
                            "command": "finalize",
                            "requestRef": body["finalizeRef"],
                            "generation": barrier["generation"],
                            "captureReceiptDigest": barrier["captureReceiptDigest"],
                        },
                    )
                except Exception:
                    # The launcher may have durably acknowledged and exited
                    # while the transport response was lost.  The formal
                    # control authority retains that receipt for adoption.
                    if not self._inspect_finalize_receipt(binding, body, barrier):
                        raise
                else:
                    if reply.get("finalized") is not True:
                        raise DependencyUnavailableError("launcher did not acknowledge finalize")
            payload.update(state="launcher_acknowledged", observedAt=self._now().isoformat())
            record = self._store.update_runtime(
                "native-finalize",
                job_ref,
                body["finalizeRef"],
                {**_values(record), "payload": _json(payload)},
            )
        if payload.get("state") != "launcher_acknowledged":
            raise DependencyUnavailableError("native finalize phase is not recoverable")
        # The sidecar waits until the launcher socket no longer accepts a
        # connection, then exits last. A retained launcher ACK makes this step
        # safely replayable after an API interruption.
        try:
            if self._transport is not None:
                response = self._transport.rpc(binding, {"action": "shutdown"}).header
                if response.get("ok") is not True:
                    raise DependencyUnavailableError()
        except Exception as error:
            raise DependencyUnavailableError("control sidecar did not finalize") from error
        payload.update(state="succeeded", observedAt=self._now().isoformat())
        record = self._store.update_runtime(
            "native-finalize",
            job_ref,
            body["finalizeRef"],
            {**_values(record), "payload": _json(payload)},
        )
        return NativeMutationResult(dict(json.loads(_values(record)["payload"])), created)

    def _inspect_finalize_receipt(
        self,
        binding: Mapping[str, Any],
        body: Mapping[str, Any],
        barrier: Mapping[str, Any],
    ) -> bool:
        """Adopt a durable control receipt after an unknown finalize outcome."""

        if self._transport is None:
            return False
        launcher_request_digest = canonical_digest(
            {"captureReceiptDigest": barrier["captureReceiptDigest"]}
        )
        try:
            response = self._transport.rpc(
                binding,
                {
                    "action": "inspectNativeFinalize",
                    "jobUid": str(binding["jobUid"]),
                    "podUid": str(binding["podUid"]),
                    "finalizeRef": str(body["finalizeRef"]),
                    "generation": int(barrier["generation"]),
                    "requestDigest": launcher_request_digest,
                },
            ).header
        except Exception:
            return False
        if response.get("ok") is not True or response.get("state") == "absent":
            return False
        if (
            response.get("state") != "acknowledged"
            or response.get("finalizeRef") != body["finalizeRef"]
            or response.get("generation") != barrier["generation"]
            or response.get("requestDigest") != launcher_request_digest
            or response.get("captureReceiptDigest") != barrier["captureReceiptDigest"]
        ):
            raise StateConflictError("retained native finalize receipt differs")
        return True

    def revoke_all(self, job_ref: str) -> None:
        for record in self._store.list_runtime("runner-credential", job_ref):
            snapshot = _runner_grant_snapshot(record)
            if snapshot.root["secretPresent"] is not False:
                self._destroy_grant(record, "revoked")

    def launcher_rpc(
        self, binding: Mapping[str, Any], frame: Mapping[str, Any]
    ) -> Mapping[str, Any]:
        """Forward one closed control frame without exposing the launcher socket."""
        return self._rpc(binding, frame)

    def _replace_generation_observation(self, job_ref: str, observation: Mapping[str, Any]) -> None:
        records = list(self._store.list_runtime("runner-generation", job_ref))
        if not records:
            return
        record = max(records, key=lambda item: int(str(_field(item, "identity"))))
        payload = _runner_generation_snapshot(record).wire()
        payload.update(runnerObservation=dict(observation), observedAt=self._now().isoformat())
        self._store.update_runtime(
            "runner-generation",
            job_ref,
            str(payload["generation"]),
            {**_values(record), "payload": _json(payload)},
        )

    def _destroy_grant(
        self,
        record: object,
        state: str,
        *,
        acknowledged_at: datetime | None = None,
        agent_run_ref: str | None = None,
        generation: int | None = None,
    ) -> RunnerCredentialGrantSnapshot:
        snapshot = _runner_grant_snapshot(record)
        payload = snapshot.wire()
        name = runner_credential_secret_name(str(payload["jobRef"]))
        secret = self._kube.read_secret(name)
        try:
            if secret is not None:
                uid = str(_nested(secret, "metadata", "uid"))
                if not self._kube.delete_secret(name, uid):
                    raise DependencyUnavailableError()
        except Exception as error:
            payload.update(
                state="destroy_failed",
                destroyFailureReason="Kubernetes Secret delete failed",
                observedAt=self._now().isoformat(),
            )
            self._store.update_runtime(
                "runner-credential",
                str(payload["jobRef"]),
                str(payload["credentialGrantRef"]),
                {**_values(record), "payload": _json(payload)},
            )
            raise CredentialDestroyFailedError() from error
        now = self._now()
        payload.update(
            state=state,
            secretPresent=False,
            destroyedAt=now.isoformat(),
            observedAt=now.isoformat(),
            destroyFailureReason=None,
        )
        if acknowledged_at is not None:
            payload.update(
                acknowledgedAt=acknowledged_at.isoformat(),
                ackAgentRunRef=agent_run_ref,
                ackGeneration=generation,
                consumedAt=acknowledged_at.isoformat(),
            )
        updated = self._store.update_runtime(
            "runner-credential",
            str(payload["jobRef"]),
            str(payload["credentialGrantRef"]),
            {**_values(record), "payload": _json(payload)},
        )
        return _runner_grant_snapshot(updated)

    def _secret(
        self,
        job_ref: str,
        metadata: RunnerCredentialGrantMetadata,
        raw_bytes: bytes,
    ) -> dict[str, object]:
        return {
            "apiVersion": "v1",
            "kind": "Secret",
            "metadata": {
                "name": runner_credential_secret_name(job_ref),
                "labels": {
                    "researchcosmos.io/managed-by": "v2-attempt-runtime",
                    "researchcosmos.io/runtime-lane": "native",
                },
                "ownerReferences": [
                    {
                        "apiVersion": "batch/v1",
                        "kind": "Job",
                        "name": job_ref,
                        "uid": metadata.job_uid,
                        "controller": False,
                        "blockOwnerDeletion": False,
                    }
                ],
                "annotations": {
                    "researchcosmos.io/job-uid": metadata.job_uid,
                    "researchcosmos.io/pod-uid": metadata.pod_uid,
                    "researchcosmos.io/grant-ref": metadata.credential_grant_ref,
                    "researchcosmos.io/credential-sha256": metadata.credential_sha256,
                },
            },
            "type": "Opaque",
            "data": {"token": base64.b64encode(raw_bytes).decode("ascii")},
        }

    def _rpc(self, binding: Mapping[str, Any], frame: Mapping[str, Any]) -> Mapping[str, Any]:
        if self._transport is None:
            raise DependencyUnavailableError("native launcher transport is unavailable")
        mutable = dict(frame)
        command = mutable.pop("command", None)
        request_ref = mutable.pop("requestRef", None)
        generation = mutable.pop("generation", None)
        if (
            not isinstance(command, str)
            or not isinstance(request_ref, str)
            or not request_ref
            or type(generation) is not int
            or generation < 0
        ):
            raise PreconditionFailedError("native launcher request identity is invalid")
        command_payload = mutable
        request = {
            "action": "nativeLauncher",
            "jobUid": str(binding["jobUid"]),
            "podUid": str(binding["podUid"]),
            "frame": {
                "command": command,
                "requestRef": request_ref,
                "requestDigest": canonical_digest(command_payload),
                "generation": generation,
                "payload": command_payload,
            },
        }
        try:
            response = self._transport.rpc(binding, request).header
        except Exception as error:
            raise DependencyUnavailableError("native launcher RPC failed") from error
        if response.get("ok") is not True:
            raw_message = response.get("message")
            message = (
                raw_message
                if isinstance(raw_message, str)
                and raw_message.startswith("native launcher rejected ")
                and len(raw_message) <= 160
                else "native launcher rejected the request"
            )
            if response.get("code") == "PRECONDITION_FAILED":
                raise PreconditionFailedError(message)
            if response.get("code") == "STATE_CONFLICT":
                raise StateConflictError(message)
            raise DependencyUnavailableError(message)
        result = response.get("result")
        if not isinstance(result, Mapping):
            raise DependencyUnavailableError("native launcher returned an invalid result")
        return result

    @staticmethod
    def _require_binding(binding: Mapping[str, Any], job_uid: object, pod_uid: object) -> None:
        if str(binding.get("jobUid")) != str(job_uid) or str(binding.get("podUid")) != str(pod_uid):
            raise StaleBindingError()

    @staticmethod
    def _binding_from_grant(payload: Mapping[str, Any]) -> dict[str, Any]:
        return {
            "jobRef": payload["jobRef"],
            "jobUid": payload["jobUid"],
            "podUid": payload["podUid"],
            "runtimeLane": "native",
        }

    def _now(self) -> datetime:
        now = self._clock()
        if now.tzinfo is None:
            raise RuntimeError("native runtime clock must be timezone-aware")
        return now


def _runner_grant_snapshot(record: object) -> RunnerCredentialGrantSnapshot:
    return RunnerCredentialGrantSnapshot.model_validate_json(_values(record)["payload"])


def _runner_generation_snapshot(record: object) -> NativeRunnerGenerationSnapshot:
    return NativeRunnerGenerationSnapshot.model_validate_json(_values(record)["payload"])


def _runner_stop_snapshot(record: object) -> RunnerStopSnapshot:
    return RunnerStopSnapshot.model_validate_json(_values(record)["payload"])


def _values(record: object) -> dict[str, str]:
    value = _field(record, "values", {})
    if not isinstance(value, Mapping):
        raise DependencyUnavailableError("native runtime record is malformed")
    return {str(key): str(item) for key, item in value.items()}


def _field(value: object, name: str, default: object | None = None) -> object:
    if isinstance(value, Mapping):
        return value.get(name, default)
    return getattr(value, name, default)


def _nested(value: object, *parts: str) -> object:
    result: object = value
    for part in parts:
        result = _field(result, part)
    return result


def _datetime(value: object) -> datetime:
    if not isinstance(value, str):
        raise DependencyUnavailableError("native timestamp is malformed")
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise DependencyUnavailableError("native timestamp is not timezone-aware")
    return parsed


def _json(value: Mapping[str, Any]) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


__all__ = [
    "NativeMutationResult",
    "NativeRuntimeController",
    "RunnerCredentialGrantMetadata",
]
