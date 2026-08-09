package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"strings"
)

type durableFinalizeReceipt struct {
	SchemaVersion        int     `json:"schemaVersion"`
	RequestRef           string  `json:"requestRef"`
	RequestDigest        string  `json:"requestDigest"`
	CaptureReceiptDigest string  `json:"captureReceiptDigest"`
	JobUID               string  `json:"jobUid"`
	PodUID               string  `json:"podUid"`
	Generation           int     `json:"generation"`
	ReceiptDigest        string  `json:"receiptDigest"`
	State                string  `json:"state"`
	AcceptedAt           string  `json:"acceptedAt"`
	CommitRequestRef     *string `json:"commitRequestRef"`
	CommitRequestDigest  *string `json:"commitRequestDigest"`
	CommittedAt          *string `json:"committedAt"`
}

type finalizeReceiptIdentity struct {
	SchemaVersion        int    `json:"schemaVersion"`
	RequestRef           string `json:"requestRef"`
	RequestDigest        string `json:"requestDigest"`
	CaptureReceiptDigest string `json:"captureReceiptDigest"`
	JobUID               string `json:"jobUid"`
	PodUID               string `json:"podUid"`
	Generation           int    `json:"generation"`
	AcceptedAt           string `json:"acceptedAt"`
}

func (receipt *durableFinalizeReceipt) identity() finalizeReceiptIdentity {
	return finalizeReceiptIdentity{
		SchemaVersion: receipt.SchemaVersion, RequestRef: receipt.RequestRef,
		RequestDigest: receipt.RequestDigest, CaptureReceiptDigest: receipt.CaptureReceiptDigest,
		JobUID: receipt.JobUID, PodUID: receipt.PodUID, Generation: receipt.Generation,
		AcceptedAt: receipt.AcceptedAt,
	}
}

func (receipt *durableFinalizeReceipt) public() map[string]any {
	return map[string]any{
		"requestRef": receipt.RequestRef, "requestDigest": receipt.RequestDigest,
		"captureReceiptDigest": receipt.CaptureReceiptDigest,
		"receiptDigest":        receipt.ReceiptDigest, "state": receipt.State,
		"acceptedAt": receipt.AcceptedAt, "commitRequestRef": receipt.CommitRequestRef,
		"commitRequestDigest": receipt.CommitRequestDigest, "committedAt": receipt.CommittedAt,
	}
}

func (l *launcher) finalize(frame request) (map[string]any, error) {
	var payload struct {
		CaptureReceiptDigest string `json:"captureReceiptDigest"`
	}
	if err := decodePayload(frame.Payload, &payload); err != nil || len(payload.CaptureReceiptDigest) != 64 {
		return nil, errors.New("finalize_invalid")
	}
	if l.finalizeReceipt != nil {
		receipt := l.finalizeReceipt
		if receipt.RequestRef != frame.RequestRef ||
			!strings.EqualFold(receipt.RequestDigest, frame.RequestDigest) ||
			!strings.EqualFold(receipt.CaptureReceiptDigest, payload.CaptureReceiptDigest) ||
			receipt.JobUID != frame.JobUID || receipt.PodUID != frame.PodUID ||
			receipt.Generation != frame.Generation {
			return nil, errors.New("identity_conflict")
		}
		return map[string]any{"finalized": true, "launcherAlive": true, "finalizeReceipt": receipt.public()}, nil
	}
	if l.obs.State != "exited" && l.obs.State != "killed" {
		return nil, errors.New("runner_not_terminal")
	}
	receipt := &durableFinalizeReceipt{
		SchemaVersion: 1, RequestRef: frame.RequestRef, RequestDigest: frame.RequestDigest,
		CaptureReceiptDigest: strings.ToLower(payload.CaptureReceiptDigest),
		JobUID:               frame.JobUID, PodUID: frame.PodUID, Generation: frame.Generation,
		State: "accepted", AcceptedAt: now(),
	}
	identityBytes, _ := json.Marshal(receipt.identity())
	digest := sha256.Sum256(identityBytes)
	receipt.ReceiptDigest = hex.EncodeToString(digest[:])
	if err := writeAtomicJSON(l.finalizeReceiptPath(), receipt); err != nil {
		return nil, errors.New("finalize_receipt_write_failed")
	}
	l.finalizeReceipt = receipt
	return map[string]any{"finalized": true, "launcherAlive": true, "finalizeReceipt": receipt.public()}, nil
}

func (l *launcher) commitFinalize(frame request) (map[string]any, error) {
	var payload struct {
		FinalizeReceiptDigest string `json:"finalizeReceiptDigest"`
	}
	if err := decodePayload(frame.Payload, &payload); err != nil || len(payload.FinalizeReceiptDigest) != 64 {
		return nil, errors.New("commit_finalize_invalid")
	}
	receipt := l.finalizeReceipt
	if receipt == nil {
		return nil, errors.New("finalize_receipt_missing")
	}
	if !strings.EqualFold(receipt.ReceiptDigest, payload.FinalizeReceiptDigest) ||
		receipt.JobUID != frame.JobUID || receipt.PodUID != frame.PodUID ||
		receipt.Generation != frame.Generation {
		return nil, errors.New("identity_conflict")
	}
	if receipt.State == "committed" {
		if receipt.CommitRequestRef == nil || receipt.CommitRequestDigest == nil ||
			*receipt.CommitRequestRef != frame.RequestRef ||
			!strings.EqualFold(*receipt.CommitRequestDigest, frame.RequestDigest) {
			return nil, errors.New("identity_conflict")
		}
	} else {
		committedAt := now()
		receipt.State, receipt.CommittedAt = "committed", &committedAt
		receipt.CommitRequestRef, receipt.CommitRequestDigest = &frame.RequestRef, &frame.RequestDigest
		if err := writeAtomicJSON(l.finalizeReceiptPath(), receipt); err != nil {
			return nil, errors.New("finalize_receipt_write_failed")
		}
	}
	return map[string]any{"committed": true, "launcherAlive": false, "finalizeReceipt": receipt.public()}, nil
}

func (l *launcher) finalizeReceiptPath() string {
	if l.finalizePath != "" {
		return l.finalizePath
	}
	return receiptPath
}

func loadFinalizeReceipt(path string) (*durableFinalizeReceipt, error) {
	if info, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
		return nil, nil
	} else if err != nil {
		return nil, err
	} else if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return nil, errors.New("unsafe_finalize_receipt")
	}
	payload, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var receipt durableFinalizeReceipt
	decoder := json.NewDecoder(strings.NewReader(string(payload)))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&receipt) != nil || decoder.Decode(&struct{}{}) != io.EOF ||
		receipt.SchemaVersion != 1 || receipt.RequestRef == "" || receipt.RequestDigest == "" ||
		!validHexDigest(receipt.RequestDigest) || !validHexDigest(receipt.CaptureReceiptDigest) ||
		!validHexDigest(receipt.ReceiptDigest) || receipt.JobUID == "" || receipt.PodUID == "" ||
		receipt.Generation < 1 || (receipt.State != "accepted" && receipt.State != "committed") {
		return nil, errors.New("finalize_receipt_invalid")
	}
	if (receipt.State == "accepted" && (receipt.CommitRequestRef != nil || receipt.CommitRequestDigest != nil || receipt.CommittedAt != nil)) ||
		(receipt.State == "committed" && (receipt.CommitRequestRef == nil || receipt.CommitRequestDigest == nil || receipt.CommittedAt == nil || !validHexDigest(*receipt.CommitRequestDigest))) {
		return nil, errors.New("finalize_receipt_invalid")
	}
	identityBytes, _ := json.Marshal(receipt.identity())
	digest := sha256.Sum256(identityBytes)
	if !strings.EqualFold(receipt.ReceiptDigest, hex.EncodeToString(digest[:])) {
		return nil, errors.New("finalize_receipt_digest_mismatch")
	}
	return &receipt, nil
}

func validHexDigest(value string) bool {
	if len(value) != 64 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}
