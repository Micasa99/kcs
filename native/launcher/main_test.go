package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestChildIdentityClearsInheritedSupplementaryGroups(t *testing.T) {
	attributes := childProcessAttributes(10002, 10001)
	credential := attributes.Credential
	if credential == nil || credential.Uid != 10002 || credential.Gid != 10001 {
		t.Fatalf("child identity differs from the requested uid/gid: %+v", credential)
	}
	if credential.NoSetGroups || len(credential.Groups) != 0 {
		t.Fatalf("child would retain launcher supplementary groups: %+v", credential)
	}
}

func TestRunnerAdapterSelectionIsExplicitAndClosed(t *testing.T) {
	t.Setenv("RC_NATIVE_RUNNER_REF", "native-lane/codex-runner@1")
	t.Setenv("RC_NATIVE_SELECTED_MODEL_PROTOCOL", "openai-responses")
	adapter, err := resolveRunnerAdapter([]string{"/opt/rc-runner/bin/codex", "exec"})
	if err != nil || adapter.TraceSchema != "codex-jsonl" {
		t.Fatalf("codex declaration not selected: adapter=%+v err=%v", adapter, err)
	}

	t.Setenv("RC_NATIVE_RUNNER_REF", "native-lane/unknown-runner@1")
	if _, err := resolveRunnerAdapter([]string{"/opt/rc-runner/usr/local/bin/unknown"}); err == nil || err.Error() != "runner_adapter_unsupported" {
		t.Fatalf("unknown runner was not rejected with the typed error: %v", err)
	}

	t.Setenv("RC_NATIVE_RUNNER_REF", "native-lane/codex-runner@1")
	if _, err := resolveRunnerAdapter([]string{"/usr/local/bin/codex"}); err == nil || err.Error() != "runner_entrypoint_mismatch" {
		t.Fatalf("undeclared executable path was accepted: %v", err)
	}

	t.Setenv("RC_NATIVE_RUNNER_REF", "native-lane/pi-runner@1")
	t.Setenv("RC_NATIVE_SELECTED_MODEL_PROTOCOL", "anthropic-messages")
	if _, err := resolveRunnerAdapter([]string{"/opt/rc-runner/bin/pi"}); err != nil {
		t.Fatalf("pi declaration should remain supported: %v", err)
	}
}

func TestRunnerImageCanDeclareAnEnvironmentOnlyAdapter(t *testing.T) {
	t.Setenv("RC_NATIVE_RUNNER_REF", "runner-custom")
	path := filepath.Join(t.TempDir(), "adapter.json")
	document := `{"schemaVersion":1,"runnerRef":"runner-custom","executable":"/opt/rc-runner/usr/local/bin/custom-agent","promptDelivery":"last-argument","configuration":"environment-only-v1","traceSchema":"custom-jsonl","modelProtocols":["openai-responses"],"terminalEvents":{"completed":{}}}`
	if err := os.WriteFile(path, []byte(document), 0600); err != nil {
		t.Fatal(err)
	}
	adapter, err := declaredRunnerAdapter(path)
	if err != nil {
		t.Fatal(err)
	}
	if adapter.RunnerRef != "runner-custom" || adapter.Configuration != "environment-only-v1" {
		t.Fatalf("unexpected runner-image declaration: %+v", adapter)
	}
}

func TestRunnerSpecificEnvironmentIsOwnedByAdapter(t *testing.T) {
	codexEnv, err := childEnvironment(runnerAdapters["native-lane/codex-runner@1"], "token")
	if err != nil {
		t.Fatal(err)
	}
	codex := strings.Join(codexEnv, "\n")
	if !strings.HasPrefix(codex, "PATH=/opt/rc-runner/bin:") {
		t.Fatalf("exact runner image bin directory is not first in PATH: %s", codex)
	}
	if !strings.Contains(codex, "CODEX_HOME=") || strings.Contains(codex, "PI_CODING_AGENT_DIR=") {
		t.Fatalf("codex environment leaked another runner's configuration: %s", codex)
	}
	piEnv, err := childEnvironment(runnerAdapters["native-lane/pi-runner@1"], "token")
	if err != nil {
		t.Fatal(err)
	}
	pi := strings.Join(piEnv, "\n")
	if !strings.Contains(pi, "PI_CODING_AGENT_DIR=") || strings.Contains(pi, "CODEX_HOME=") {
		t.Fatalf("pi environment leaked another runner's configuration: %s", pi)
	}
	custom := runnerAdapter{Configuration: "environment-only-v1"}
	genericEnv, err := childEnvironment(custom, "token")
	if err != nil {
		t.Fatal(err)
	}
	generic := strings.Join(genericEnv, "\n")
	if strings.Contains(generic, "CODEX_HOME=") || strings.Contains(generic, "PI_CODING_AGENT_DIR=") {
		t.Fatalf("generic adapter inherited a built-in runner's configuration: %s", generic)
	}
}

func TestExactToolDiscoveryPathsExtendChildPATH(t *testing.T) {
	root := t.TempDir()
	directory := filepath.Join(root, "metrics", "bin")
	if err := os.MkdirAll(directory, 0755); err != nil {
		t.Fatal(err)
	}
	executable := filepath.Join(root, "evidence", "rc-evidence")
	if err := os.MkdirAll(filepath.Dir(executable), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(executable, []byte("#!/bin/sh\n"), 0555); err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal([]string{directory, executable, executable})
	if err != nil {
		t.Fatal(err)
	}
	paths, err := toolSearchPaths(string(raw), root)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{directory, filepath.Dir(executable)}
	if strings.Join(paths, "|") != strings.Join(want, "|") {
		t.Fatalf("unexpected exact tool search paths: got=%v want=%v", paths, want)
	}
	if _, err := toolSearchPaths(`["/tmp/not-an-activation-mount"]`, root); err == nil {
		t.Fatal("tool path outside its exact activation mount was accepted")
	}
}

func TestTrajectoryRecorderPreservesRawStreamsAndSessionLines(t *testing.T) {
	directory := t.TempDir()
	adapter := runnerAdapters["native-lane/codex-runner@1"]
	recorder, err := newTrajectoryRecorderWithOwnership(
		filepath.Join(directory, "stdout.raw"),
		filepath.Join(directory, "stderr.raw"),
		filepath.Join(directory, ".trajectory", "session.jsonl"),
		adapter,
		false,
	)
	if err != nil {
		t.Fatal(err)
	}
	var console bytes.Buffer
	recorder.stdout.console = &console
	stderr := recorder.stderr.(*synchronizedMultiWriter)
	var errorConsole bytes.Buffer
	stderr.writers[1] = &errorConsole
	stdoutBytes := []byte("{\"type\":\"thread.started\"}\n{\"type\":\"turn.completed\"}\n")
	stderrBytes := []byte("native warning\n")
	if _, err := recorder.stdout.Write(stdoutBytes); err != nil {
		t.Fatal(err)
	}
	if _, err := recorder.stderr.Write(stderrBytes); err != nil {
		t.Fatal(err)
	}
	recorder.close()

	assertFileBytes(t, filepath.Join(directory, "stdout.raw"), stdoutBytes)
	assertFileBytes(t, filepath.Join(directory, "stderr.raw"), stderrBytes)
	assertFileBytes(t, filepath.Join(directory, ".trajectory", "session.jsonl"), stdoutBytes)
	if got := console.String(); got != "RCJL|{\"type\":\"thread.started\"}\nRCJL|{\"type\":\"turn.completed\"}\n" {
		t.Fatalf("unexpected framed stdout: %q", got)
	}
	if errorConsole.String() != string(stderrBytes) {
		t.Fatalf("stderr tee changed bytes: %q", errorConsole.String())
	}
	terminal := recorder.terminal()
	if !terminal.Observed || terminal.EventKind == nil || *terminal.EventKind != "turn.completed" {
		t.Fatalf("terminal JSONL fact was not retained: %+v", terminal)
	}
}

func TestBlockedPTYWriteDoesNotBlockInspectAndTimesOut(t *testing.T) {
	cancelled := make(chan struct{})
	entered := make(chan struct{})
	session := &terminalSession{
		ptyRef:    "pty-1",
		writeGate: make(chan struct{}, 1),
		factPath:  filepath.Join(t.TempDir(), "terminal.jsonl"),
		expiresAt: time.Now().Add(time.Minute),
		write: func([]byte) (int, error) {
			close(entered)
			<-cancelled
			return 0, errors.New("closed")
		},
	}
	session.cancelWrite = func() {
		select {
		case <-cancelled:
		default:
			close(cancelled)
		}
		session.mu.Lock()
		session.closed = true
		session.mu.Unlock()
	}
	l := &launcher{
		jobUID: "job-uid", podUID: "pod-uid", generation: 1,
		obs:              observation{State: "running"},
		terminals:        map[string]*terminalSession{"pty-1": session},
		acknowledgements: map[string]retainedAcknowledgement{},
		writeTimeout:     50 * time.Millisecond,
	}
	writePayload := map[string]any{
		"ptyRef": "pty-1", "contentBase64": base64.StdEncoding.EncodeToString([]byte("hello")),
	}
	writeFrame := requestFor(t, "writePty", "write-1", writePayload)
	writeDone := make(chan acknowledgement, 1)
	go func() { writeDone <- l.handle(writeFrame) }()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("PTY writer was not entered")
	}

	inspectDone := make(chan acknowledgement, 1)
	go func() { inspectDone <- l.handle(requestFor(t, "inspect", "inspect-1", map[string]any{})) }()
	select {
	case ack := <-inspectDone:
		if ack.State != "completed" {
			t.Fatalf("inspect failed while PTY was blocked: %+v", ack)
		}
	case <-time.After(25 * time.Millisecond):
		t.Fatal("inspect waited behind the blocked PTY write")
	}
	select {
	case ack := <-writeDone:
		if ack.ErrorCode == nil || *ack.ErrorCode != "pty_write_timeout" {
			t.Fatalf("blocked PTY did not return the bounded typed result: %+v", ack)
		}
	case <-time.After(time.Second):
		t.Fatal("blocked PTY write did not terminate")
	}
}

func TestConcurrentPTYReplayWritesOnlyOnce(t *testing.T) {
	entered := make(chan struct{})
	release := make(chan struct{})
	writes := 0
	session := &terminalSession{
		ptyRef: "pty-1", writeGate: make(chan struct{}, 1),
		factPath:  filepath.Join(t.TempDir(), "terminal.jsonl"),
		expiresAt: time.Now().Add(time.Minute),
		write: func(payload []byte) (int, error) {
			writes++
			close(entered)
			<-release
			return len(payload), nil
		},
	}
	l := &launcher{
		jobUID: "job-uid", podUID: "pod-uid", generation: 1,
		terminals:        map[string]*terminalSession{"pty-1": session},
		acknowledgements: map[string]retainedAcknowledgement{}, pending: map[string]pendingAcknowledgement{},
		writeTimeout: time.Second,
	}
	frame := requestFor(t, "writePty", "write-1", map[string]any{
		"ptyRef": "pty-1", "contentBase64": base64.StdEncoding.EncodeToString([]byte("hello")),
	})
	results := make(chan acknowledgement, 2)
	go func() { results <- l.handle(frame) }()
	<-entered
	go func() { results <- l.handle(frame) }()
	close(release)
	first, second := <-results, <-results
	if first.State != "completed" || second.State != "completed" || first.Replayed == second.Replayed || writes != 1 {
		t.Fatalf("first-wins PTY replay failed: first=%+v second=%+v writes=%d", first, second, writes)
	}
}

func TestFinalizeReceiptIsDurableReplayableAndExplicitlyCommitted(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "finalize-receipt.json")
	l := &launcher{
		jobUID: "job-uid", podUID: "pod-uid", generation: 1,
		obs:              observation{State: "exited"},
		terminals:        map[string]*terminalSession{},
		acknowledgements: map[string]retainedAcknowledgement{},
		finalizePath:     path,
	}
	captureDigest := strings.Repeat("a", 64)
	frame := requestFor(t, "finalize", "finalize-1", map[string]any{"captureReceiptDigest": captureDigest})
	ack := l.handle(frame)
	if ack.State != "completed" || ack.Payload["finalized"] != true || ack.Payload["launcherAlive"] != true {
		t.Fatalf("finalize should durably ACK without exiting: %+v", ack)
	}
	receipt, err := loadFinalizeReceipt(path)
	if err != nil || receipt == nil || receipt.State != "accepted" {
		t.Fatalf("accepted receipt was not durable: receipt=%+v err=%v", receipt, err)
	}
	replay := l.handle(frame)
	if replay.State != "completed" || !replay.Replayed {
		t.Fatalf("same finalize identity did not replay: %+v", replay)
	}

	restarted := &launcher{
		jobUID: receipt.JobUID, podUID: receipt.PodUID, generation: receipt.Generation,
		finalizeReceipt: receipt, finalizePath: path,
		terminals: map[string]*terminalSession{}, acknowledgements: map[string]retainedAcknowledgement{},
	}
	durableReplay := restarted.handle(frame)
	if durableReplay.State != "completed" || durableReplay.Payload["finalized"] != true {
		t.Fatalf("receipt-backed replay failed: %+v", durableReplay)
	}
	commit := requestFor(t, "commitFinalize", "commit-1", map[string]any{"finalizeReceiptDigest": receipt.ReceiptDigest})
	committed := restarted.handle(commit)
	if committed.State != "completed" || committed.Payload["launcherAlive"] != false {
		t.Fatalf("explicit commit did not close the launcher phase: %+v", committed)
	}
	retained, err := loadFinalizeReceipt(path)
	if err != nil || retained.State != "committed" || retained.CommittedAt == nil {
		t.Fatalf("committed receipt was not durable: receipt=%+v err=%v", retained, err)
	}
}

func requestFor(t *testing.T, command, ref string, value any) request {
	t.Helper()
	payload, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(payload)
	return request{
		SchemaVersion: 1, Command: command, RequestRef: ref,
		RequestDigest: hex.EncodeToString(digest[:]), JobUID: "job-uid", PodUID: "pod-uid",
		Generation: 1, Payload: payload,
	}
}

func assertFileBytes(t *testing.T, path string, expected []byte) {
	t.Helper()
	actual, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(actual, expected) {
		t.Fatalf("%s bytes differ: got %q want %q", path, actual, expected)
	}
}
