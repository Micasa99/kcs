// rc-native-launcher is the native runtime PID 1 and the only process owner.
package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/creack/pty"
)

const (
	controlDir        = "/run/rc-control"
	socketPath        = controlDir + "/launcher.sock"
	statePath         = controlDir + "/runner-state.json"
	receiptPath       = controlDir + "/finalize-receipt.json"
	rawStdoutPath     = controlDir + "/runner-stdout.raw"
	rawStderrPath     = controlDir + "/runner-stderr.raw"
	terminalFactsPath = controlDir + "/terminal-session.jsonl"
	tokenPath         = "/var/run/rc/model-gateway/token"
	worktree          = "/workspace/worktree"
	trajectoryDir     = worktree + "/.trajectory"
	sessionPath       = trajectoryDir + "/session.jsonl"
	maxFrame          = 131072
	maxPTYData        = 65536
)

type processExit struct {
	Kind     string `json:"kind"`
	ExitCode *int   `json:"exitCode"`
	Signal   *int   `json:"signal"`
}

type protocolTerminal struct {
	Observed   bool    `json:"observed"`
	EventKind  *string `json:"eventKind"`
	StopReason *string `json:"stopReason"`
	ErrorCode  *string `json:"errorCode"`
}

type observation struct {
	State            string           `json:"state"`
	Sequence         int64            `json:"sequence"`
	StateDigest      string           `json:"stateDigest"`
	ChildPID         *int             `json:"childPid"`
	ProcessExit      processExit      `json:"processExit"`
	StopCause        string           `json:"stopCause"`
	ProtocolTerminal protocolTerminal `json:"protocolTerminal"`
	ChildStartedAt   *string          `json:"childStartedAt"`
	ChildFinishedAt  *string          `json:"childFinishedAt"`
	ObservedAt       string           `json:"observedAt"`
}

type request struct {
	SchemaVersion int             `json:"schemaVersion"`
	Command       string          `json:"command"`
	RequestRef    string          `json:"requestRef"`
	RequestDigest string          `json:"requestDigest"`
	JobUID        string          `json:"jobUid"`
	PodUID        string          `json:"podUid"`
	Generation    int             `json:"generation"`
	Payload       json.RawMessage `json:"payload"`
}

type acknowledgement struct {
	SchemaVersion int            `json:"schemaVersion"`
	Command       string         `json:"command"`
	RequestRef    string         `json:"requestRef"`
	RequestDigest string         `json:"requestDigest"`
	JobUID        string         `json:"jobUid"`
	PodUID        string         `json:"podUid"`
	Generation    int            `json:"generation"`
	State         string         `json:"state"`
	Replayed      bool           `json:"replayed"`
	ObservedAt    string         `json:"observedAt"`
	ErrorCode     *string        `json:"errorCode"`
	Payload       map[string]any `json:"payload"`
}

type retainedAcknowledgement struct {
	digest string
	ack    acknowledgement
}

type pendingAcknowledgement struct {
	digest string
	done   chan struct{}
}

type terminalSession struct {
	ptyRef       string
	jobUID       string
	podUID       string
	generation   int
	cmd          *exec.Cmd
	pty          *os.File
	write        func([]byte) (int, error)
	cancelWrite  func()
	writeGate    chan struct{}
	factPath     string
	output       []byte
	base         int
	closed       bool
	expiresAt    time.Time
	pausedRunner bool
	mu           sync.Mutex
	factMu       sync.Mutex
	factSequence int64
}

type launcher struct {
	mu               sync.Mutex
	obs              observation
	cmd              *exec.Cmd
	generation       int
	jobUID           string
	podUID           string
	stopCause        string
	protocolTerminal protocolTerminal
	finalizeReceipt  *durableFinalizeReceipt
	finalizePath     string
	writeTimeout     time.Duration
	terminals        map[string]*terminalSession
	acknowledgements map[string]retainedAcknowledgement
	pending          map[string]pendingAcknowledgement
}

func main() {
	if len(os.Args) > 1 && os.Args[1] == "__rc_unprivileged_child" {
		if err := runUnprivilegedChild(os.Args[2:]); err != nil {
			fatal(err)
		}
		return
	}
	syscall.Umask(0002)
	if err := preparePaths(); err != nil {
		fatal(err)
	}
	l := &launcher{
		terminals:        map[string]*terminalSession{},
		acknowledgements: map[string]retainedAcknowledgement{},
		pending:          map[string]pendingAcknowledgement{},
		finalizePath:     receiptPath,
		writeTimeout:     2 * time.Second,
	}
	if receipt, err := loadFinalizeReceipt(receiptPath); err != nil {
		fatal(err)
	} else if receipt != nil {
		l.finalizeReceipt = receipt
		l.jobUID, l.podUID, l.generation = receipt.JobUID, receipt.PodUID, receipt.Generation
	}
	if err := removeSocket(); err != nil {
		fatal(err)
	}
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		fatal(err)
	}
	if err := os.Chmod(socketPath, 0600); err != nil {
		fatal(err)
	}
	for {
		connection, err := listener.Accept()
		if err != nil {
			fatal(err)
		}
		go l.serve(connection)
	}
}

func (l *launcher) serve(connection net.Conn) {
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(35 * time.Second))
	header := make([]byte, 4)
	if _, err := io.ReadFull(connection, header); err != nil {
		return
	}
	size := binary.BigEndian.Uint32(header)
	if size == 0 || size > maxFrame {
		return
	}
	payload := make([]byte, size)
	if _, err := io.ReadFull(connection, payload); err != nil {
		return
	}
	var frame request
	decoder := json.NewDecoder(strings.NewReader(string(payload)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&frame); err != nil || frame.SchemaVersion != 1 || decoder.Decode(&struct{}{}) != io.EOF {
		return
	}
	ack := l.handle(frame)
	if err := writeFrame(connection, ack); err != nil {
		return
	}
	if frame.Command == "commitFinalize" && ack.State == "completed" {
		os.Exit(0)
	}
}

func (l *launcher) handle(frame request) acknowledgement {
	l.mu.Lock()
	ack := acknowledgement{
		SchemaVersion: 1,
		Command:       frame.Command,
		RequestRef:    frame.RequestRef,
		RequestDigest: frame.RequestDigest,
		JobUID:        frame.JobUID,
		PodUID:        frame.PodUID,
		Generation:    frame.Generation,
		State:         "failed",
		ObservedAt:    now(),
		Payload:       map[string]any{},
	}
	if err := validateRequest(frame); err != nil {
		code := err.Error()
		ack.ErrorCode = &code
		l.mu.Unlock()
		return ack
	}
	if l.jobUID != "" && (l.jobUID != frame.JobUID || l.podUID != frame.PodUID) {
		code := "stale_binding"
		ack.ErrorCode = &code
		l.mu.Unlock()
		return ack
	}
	if l.jobUID == "" {
		l.jobUID, l.podUID = frame.JobUID, frame.PodUID
		l.generation = frame.Generation
		l.setObservation(
			"starting",
			nil,
			processExit{Kind: "not_observed"},
			"none",
			nil,
			nil,
		)
	}
	key := requestIdentity(frame)
	cacheable := !isQuery(frame.Command)
	if cacheable {
		if retained, found := l.acknowledgements[key]; found {
			if retained.digest != frame.RequestDigest {
				code := "identity_conflict"
				ack.ErrorCode = &code
				l.mu.Unlock()
				return ack
			}
			replayed := retained.ack
			replayed.Replayed = true
			replayed.ObservedAt = now()
			l.mu.Unlock()
			return replayed
		}
		if l.pending == nil {
			l.pending = map[string]pendingAcknowledgement{}
		}
		if pending, found := l.pending[key]; found {
			if pending.digest != frame.RequestDigest {
				code := "identity_conflict"
				ack.ErrorCode = &code
				l.mu.Unlock()
				return ack
			}
			l.mu.Unlock()
			<-pending.done
			l.mu.Lock()
			retained := l.acknowledgements[key]
			replayed := retained.ack
			replayed.Replayed = true
			replayed.ObservedAt = now()
			l.mu.Unlock()
			return replayed
		}
		l.pending[key] = pendingAcknowledgement{digest: frame.RequestDigest, done: make(chan struct{})}
	}
	var result map[string]any
	var err error
	if frame.Command == "writePty" {
		var write terminalWrite
		write, err = l.prepareTerminalWrite(frame)
		l.mu.Unlock()
		if err == nil {
			result, err = l.performTerminalWrite(write)
		}
		l.mu.Lock()
	} else {
		result, err = l.dispatch(frame)
	}
	if err != nil {
		code := err.Error()
		ack.ErrorCode = &code
	} else {
		ack.State = "completed"
		ack.Payload = result
	}
	if cacheable {
		l.acknowledgements[key] = retainedAcknowledgement{
			digest: frame.RequestDigest,
			ack:    ack,
		}
		pending := l.pending[key]
		delete(l.pending, key)
		close(pending.done)
	}
	l.mu.Unlock()
	return ack
}

func (l *launcher) dispatch(frame request) (map[string]any, error) {
	switch frame.Command {
	case "credentialStatus":
		if err := decodePayload(frame.Payload, &struct{}{}); err != nil {
			return nil, err
		}
		bytes, err := readCredential()
		if err != nil {
			return map[string]any{"credentialReady": false}, nil
		}
		digest := sha256.Sum256(bytes)
		return map[string]any{"credentialReady": true, "credentialSha256": hex.EncodeToString(digest[:])}, nil
	case "start":
		return l.start(frame)
	case "inspect":
		if err := decodePayload(frame.Payload, &struct{}{}); err != nil {
			return nil, err
		}
		return l.snapshot(), nil
	case "stop":
		return l.stop(frame)
	case "finalize":
		return l.finalize(frame)
	case "commitFinalize":
		return l.commitFinalize(frame)
	case "createPty":
		return l.createTerminal(frame)
	case "writePty":
		return nil, errors.New("internal_dispatch_error")
	case "readPty":
		return l.readTerminal(frame)
	case "resizePty":
		return l.resizeTerminal(frame)
	case "closePty":
		return l.closeTerminal(frame)
	default:
		return nil, errors.New("unsupported_command")
	}
}

func (l *launcher) start(frame request) (map[string]any, error) {
	var payload struct {
		NativeLaunchDigest string         `json:"nativeLaunchDigest"`
		Descriptor         map[string]any `json:"descriptor"`
	}
	if err := decodePayload(frame.Payload, &payload); err != nil {
		return nil, err
	}
	if l.cmd != nil || l.obs.State == "running" {
		if l.generation == frame.Generation {
			return l.snapshot(), nil
		}
		return nil, errors.New("generation_conflict")
	}
	if l.finalizeReceipt != nil {
		return nil, errors.New("finalize_pending")
	}
	if frame.Generation < 1 || payload.NativeLaunchDigest == "" || payload.Descriptor == nil {
		return nil, errors.New("launch_invalid")
	}
	requiredMiB, err := strconv.Atoi(os.Getenv("RC_NATIVE_EPHEMERAL_STORAGE_MIB"))
	if err != nil || requiredMiB < 512 || storagePreflight(requiredMiB) != nil {
		return nil, errors.New("capacity_insufficient")
	}
	token, err := readCredential()
	if err != nil || len(token) == 0 {
		return nil, errors.New("credential_unavailable")
	}
	var argv []string
	if err := json.Unmarshal([]byte(os.Getenv("RC_NATIVE_RUNNER_ENTRYPOINT_JSON")), &argv); err != nil || len(argv) == 0 {
		return nil, errors.New("entrypoint_invalid")
	}
	adapter, err := resolveRunnerAdapter(argv)
	if err != nil {
		return nil, err
	}
	prompt := "Begin the work now and continue autonomously until the task is complete or a concrete blocker is proven. Use your native shell and file tools; do not stop after describing what you intend to do. First read and follow the task book at " + os.Getenv("RC_NATIVE_TASK_PATH") + ", then inspect the actual workspace, implement the work, run relevant verification, and leave all requested outputs in the workspace. Report observed results and blockers honestly."
	argv = adapter.withPrompt(argv, prompt)
	recorder, err := newTrajectoryRecorder(rawStdoutPath, rawStderrPath, sessionPath, adapter)
	if err != nil {
		return nil, errors.New("trajectory_open_failed")
	}
	childArgv := append([]string{"__rc_unprivileged_child"}, argv...)
	cmd := exec.Command("/proc/self/exe", childArgv...)
	cmd.Dir = worktree
	cmd.Stdout = recorder.stdout
	cmd.Stderr = recorder.stderr
	cmd.Stdin = nil
	cmd.Env = childEnvironment(adapter, string(token))
	cmd.SysProcAttr = childProcessAttributes(10001, 10001)
	started := now()
	l.generation = frame.Generation
	l.stopCause = ""
	l.setObservation("starting", nil, processExit{Kind: "not_observed"}, "none", &started, nil)
	if err := cmd.Start(); err != nil {
		recorder.close()
		finished := now()
		code := 127
		l.setObservation("exited", nil, processExit{Kind: "exited", ExitCode: &code}, "natural_exit", &started, &finished)
		return nil, errors.New("child_start_failed")
	}
	l.cmd = cmd
	pid := cmd.Process.Pid
	l.setObservation("running", &pid, processExit{Kind: "not_observed"}, "none", &started, nil)
	go l.wait(cmd, started, recorder)
	return l.snapshot(), nil
}

func (l *launcher) wait(cmd *exec.Cmd, started string, recorder *trajectoryRecorder) {
	err := cmd.Wait()
	recorder.close()
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.cmd != cmd {
		return
	}
	finished := now()
	exit := processExit{Kind: "exited"}
	code := 0
	state := "exited"
	cause := "natural_exit"
	if err != nil {
		var exitError *exec.ExitError
		if errors.As(err, &exitError) {
			status := exitError.Sys().(syscall.WaitStatus)
			if status.Signaled() {
				signal := int(status.Signal())
				exit = processExit{Kind: "signaled", Signal: &signal}
				state = "killed"
				cause = l.stopCause
				if cause == "" {
					cause = "unknown"
				}
			} else {
				code = status.ExitStatus()
				exit.ExitCode = &code
			}
		}
	} else {
		exit.ExitCode = &code
	}
	if l.stopCause == "stop_requested" || l.stopCause == "soft_deadline" || l.stopCause == "cancel_requested" {
		state = "killed"
		cause = l.stopCause
	}
	l.protocolTerminal = recorder.terminal()
	l.setObservation(state, nil, exit, cause, &started, &finished)
	l.cmd = nil
}

func (l *launcher) stop(frame request) (map[string]any, error) {
	var payload struct {
		Reason string `json:"reason"`
	}
	if err := decodePayload(frame.Payload, &payload); err != nil || payload.Reason == "" {
		return nil, errors.New("stop_invalid")
	}
	if frame.Generation != l.generation {
		return nil, errors.New("generation_conflict")
	}
	if l.obs.State == "exited" || l.obs.State == "killed" {
		result := l.snapshot()
		result["result"] = "already_terminal"
		return result, nil
	}
	if l.cmd == nil || l.cmd.Process == nil {
		return nil, errors.New("runner_not_started")
	}
	cause := payload.Reason
	if cause == "stop_requested" {
		cause = "stop_requested"
	}
	l.stopCause = cause
	termAt := now()
	_ = syscall.Kill(-l.cmd.Process.Pid, syscall.SIGTERM)
	deadline := time.Now().Add(10 * time.Second)
	for l.cmd != nil && time.Now().Before(deadline) {
		l.mu.Unlock()
		time.Sleep(50 * time.Millisecond)
		l.mu.Lock()
	}
	var killAt *string
	result := "terminated"
	if l.cmd != nil {
		value := now()
		killAt = &value
		result = "killed"
		_ = syscall.Kill(-l.cmd.Process.Pid, syscall.SIGKILL)
	}
	killDeadline := time.Now().Add(2 * time.Second)
	for l.cmd != nil && time.Now().Before(killDeadline) {
		l.mu.Unlock()
		time.Sleep(25 * time.Millisecond)
		l.mu.Lock()
	}
	snapshot := l.snapshot()
	snapshot["result"] = result
	snapshot["termSentAt"] = termAt
	snapshot["killSentAt"] = killAt
	snapshot["runnerTerminalAt"] = l.obs.ChildFinishedAt
	return snapshot, nil
}

func (l *launcher) snapshot() map[string]any {
	result := map[string]any{"runnerObservation": l.obs, "launcherAlive": true}
	if l.finalizeReceipt != nil {
		result["finalizeReceipt"] = l.finalizeReceipt.public()
	}
	return result
}

func (l *launcher) setObservation(state string, pid *int, exit processExit, cause string, started, finished *string) {
	l.obs = observation{
		State: state, Sequence: l.obs.Sequence + 1, ChildPID: pid, ProcessExit: exit,
		StopCause: cause, ProtocolTerminal: l.protocolTerminal, ChildStartedAt: started,
		ChildFinishedAt: finished, ObservedAt: now(),
	}
	document := l.stateDocument(false)
	bytes, _ := json.Marshal(document)
	digest := sha256.Sum256(bytes)
	l.obs.StateDigest = hex.EncodeToString(digest[:])
	if err := writeAtomicJSON(statePath, l.stateDocument(true)); err != nil {
		fatal(errors.New("state_publish_failed"))
	}
}

func (l *launcher) stateDocument(withDigest bool) map[string]any {
	document := map[string]any{
		"schemaVersion": 1,
		"jobUid":        l.jobUID,
		"podUid":        l.podUID,
		"generation":    l.generation,
		"sequence":      l.obs.Sequence,
		"state":         l.obs.State,
		"childPid":      l.obs.ChildPID,
		"processExit": map[string]any{
			"kind":     l.obs.ProcessExit.Kind,
			"exitCode": l.obs.ProcessExit.ExitCode,
			"signal":   l.obs.ProcessExit.Signal,
		},
		"stopCause": l.obs.StopCause,
		"protocolTerminal": map[string]any{
			"observed":   l.obs.ProtocolTerminal.Observed,
			"eventKind":  l.obs.ProtocolTerminal.EventKind,
			"stopReason": l.obs.ProtocolTerminal.StopReason,
			"errorCode":  l.obs.ProtocolTerminal.ErrorCode,
		},
		"childStartedAt":  l.obs.ChildStartedAt,
		"childFinishedAt": l.obs.ChildFinishedAt,
		"observedAt":      l.obs.ObservedAt,
	}
	if withDigest {
		document["stateDigest"] = l.obs.StateDigest
	}
	return document
}

func (l *launcher) createTerminal(frame request) (map[string]any, error) {
	var payload struct {
		PTYRef     string `json:"ptyRef"`
		TTLSeconds int    `json:"ttlSeconds"`
	}
	if err := decodePayload(frame.Payload, &payload); err != nil {
		return nil, err
	}
	if payload.PTYRef == "" || payload.TTLSeconds < 1 || payload.TTLSeconds > 86400 || l.terminals[payload.PTYRef] != nil {
		return nil, errors.New("pty_conflict")
	}
	pausedRunner := false
	if l.cmd != nil && l.cmd.Process != nil && l.obs.State == "running" {
		if err := syscall.Kill(-l.cmd.Process.Pid, syscall.SIGSTOP); err != nil {
			return nil, errors.New("runner_pause_failed")
		}
		pausedRunner = true
	}
	cmd := exec.Command("/proc/self/exe", "__rc_unprivileged_child", "/bin/sh")
	cmd.Dir = worktree
	cmd.Env = []string{"PATH=/usr/local/bin:/usr/bin:/bin", "HOME=/run/rc-terminal/home", "TMPDIR=/run/rc-terminal/tmp", "TERM=xterm-256color", "LANG=C.UTF-8", "RC_NATIVE_CHILD_ROLE=terminal"}
	cmd.SysProcAttr = childProcessAttributes(10002, 10001)
	terminal, err := pty.StartWithAttrs(
		cmd,
		&pty.Winsize{Rows: 24, Cols: 80},
		cmd.SysProcAttr,
	)
	if err != nil {
		return nil, errors.New("pty_failed")
	}
	session := &terminalSession{
		ptyRef:       payload.PTYRef,
		jobUID:       l.jobUID,
		podUID:       l.podUID,
		generation:   l.generation,
		cmd:          cmd,
		pty:          terminal,
		write:        terminal.Write,
		writeGate:    make(chan struct{}, 1),
		factPath:     terminalFactsPath,
		expiresAt:    time.Now().Add(time.Duration(payload.TTLSeconds) * time.Second),
		pausedRunner: pausedRunner,
	}
	session.cancelWrite = func() { l.closeTerminalProcess(session) }
	l.terminals[payload.PTYRef] = session
	if err := session.appendFact("opened", nil); err != nil {
		delete(l.terminals, payload.PTYRef)
		l.closeTerminalProcess(session)
		l.resumeRunnerAfterTerminal(session)
		return nil, errors.New("pty_audit_failed")
	}
	go session.capture(terminal)
	go func() {
		_ = cmd.Wait()
		l.finishTerminal(payload.PTYRef, session, "process_exited")
	}()
	go func() {
		timer := time.NewTimer(time.Until(session.expiresAt))
		defer timer.Stop()
		<-timer.C
		l.finishTerminal(payload.PTYRef, session, "expired")
	}()
	return map[string]any{
		"ptyRef":       payload.PTYRef,
		"open":         true,
		"runnerPaused": pausedRunner,
		"expiresAt":    session.expiresAt.UTC().Format(time.RFC3339Nano),
	}, nil
}

func (s *terminalSession) capture(reader io.Reader) {
	buffer := make([]byte, 4096)
	for {
		n, err := reader.Read(buffer)
		if n > 0 {
			chunk := append([]byte(nil), buffer[:n]...)
			s.mu.Lock()
			s.output = append(s.output, chunk...)
			if len(s.output) > 1048576 {
				drop := len(s.output) - 1048576
				s.output = append([]byte(nil), s.output[drop:]...)
				s.base += drop
			}
			s.mu.Unlock()
			_ = s.appendFact("output", chunk)
		}
		if err != nil {
			return
		}
	}
}

func (l *launcher) readTerminal(frame request) (map[string]any, error) {
	var payload struct {
		PTYRef     string `json:"ptyRef"`
		Cursor     int    `json:"cursor"`
		LimitBytes int    `json:"limitBytes"`
	}
	if err := decodePayload(frame.Payload, &payload); err != nil {
		return nil, err
	}
	s := l.terminals[payload.PTYRef]
	if s == nil {
		return nil, errors.New("pty_not_found")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if payload.Cursor < s.base {
		return nil, errors.New("pty_cursor_stale")
	}
	start := payload.Cursor - s.base
	if start > len(s.output) {
		start = len(s.output)
	}
	limit := payload.LimitBytes
	if limit < 1 || limit > 1048576 {
		limit = 65536
	}
	end := start + limit
	if end > len(s.output) {
		end = len(s.output)
	}
	return map[string]any{
		"contentBase64": base64.StdEncoding.EncodeToString(s.output[start:end]),
		"nextCursor":    s.base + end,
		"open":          !s.closed,
	}, nil
}

func (l *launcher) resizeTerminal(frame request) (map[string]any, error) {
	var payload struct {
		PTYRef  string `json:"ptyRef"`
		Rows    int    `json:"rows"`
		Columns int    `json:"columns"`
	}
	if err := decodePayload(frame.Payload, &payload); err != nil {
		return nil, err
	}
	s := l.terminals[payload.PTYRef]
	if s == nil || payload.Rows < 1 || payload.Columns < 1 || payload.Rows > 1000 || payload.Columns > 1000 {
		return nil, errors.New("pty_resize_invalid")
	}
	s.mu.Lock()
	closed := s.closed
	s.mu.Unlock()
	if closed || time.Now().After(s.expiresAt) {
		return nil, errors.New("pty_expired")
	}
	if err := pty.Setsize(
		s.pty,
		&pty.Winsize{Rows: uint16(payload.Rows), Cols: uint16(payload.Columns)},
	); err != nil {
		return nil, errors.New("pty_resize_failed")
	}
	return map[string]any{"resized": true}, nil
}

func (l *launcher) closeTerminal(frame request) (map[string]any, error) {
	var payload struct {
		PTYRef string `json:"ptyRef"`
		Reason string `json:"reason"`
	}
	if err := decodePayload(frame.Payload, &payload); err != nil || payload.Reason == "" {
		return nil, errors.New("pty_close_invalid")
	}
	s := l.terminals[payload.PTYRef]
	if s == nil {
		return nil, errors.New("pty_not_found")
	}
	_ = s.appendFact("close_requested", nil)
	delete(l.terminals, payload.PTYRef)
	l.closeTerminalProcess(s)
	l.resumeRunnerAfterTerminal(s)
	_ = s.appendFact("closed", nil)
	return map[string]any{"closed": true}, nil
}

func (l *launcher) finishTerminal(ptyRef string, session *terminalSession, reason string) {
	l.mu.Lock()
	if l.terminals[ptyRef] != session {
		l.mu.Unlock()
		return
	}
	l.mu.Unlock()
	_ = session.appendFact(reason, nil)
	if reason != "process_exited" {
		l.closeTerminalProcess(session)
	} else {
		session.mu.Lock()
		session.closed = true
		session.mu.Unlock()
	}
	l.mu.Lock()
	if l.terminals[ptyRef] == session {
		l.resumeRunnerAfterTerminal(session)
	}
	l.mu.Unlock()
	_ = session.appendFact("closed", nil)
}

func (l *launcher) closeTerminalProcess(session *terminalSession) {
	session.mu.Lock()
	alreadyClosed := session.closed
	session.closed = true
	session.mu.Unlock()
	if alreadyClosed {
		return
	}
	if session.pty != nil {
		_ = session.pty.Close()
	}
	if session.cmd != nil && session.cmd.Process != nil {
		_ = syscall.Kill(-session.cmd.Process.Pid, syscall.SIGTERM)
	}
}

func (l *launcher) resumeRunnerAfterTerminal(session *terminalSession) {
	if !session.pausedRunner || l.cmd == nil || l.cmd.Process == nil || l.stopCause != "" {
		return
	}
	for _, other := range l.terminals {
		if other == session {
			continue
		}
		other.mu.Lock()
		activePause := other.pausedRunner && !other.closed
		other.mu.Unlock()
		if activePause {
			return
		}
	}
	_ = syscall.Kill(-l.cmd.Process.Pid, syscall.SIGCONT)
}

func preparePaths() error {
	if err := os.MkdirAll(controlDir, 0700); err != nil {
		return err
	}
	if err := os.Chmod(controlDir, 0700); err != nil {
		return err
	}
	for _, item := range []struct {
		path     string
		uid, gid int
	}{{"/run/rc-user/home", 10001, 10001}, {"/run/rc-user/tmp", 10001, 10001}, {"/run/rc-terminal/home", 10002, 10001}, {"/run/rc-terminal/tmp", 10002, 10001}} {
		if err := os.MkdirAll(item.path, 0700); err != nil {
			return err
		}
		if err := os.Chmod(item.path, 0700); err != nil {
			return err
		}
		if err := os.Chown(item.path, item.uid, item.gid); err != nil {
			return err
		}
	}
	if err := os.MkdirAll(worktree, 02775); err != nil {
		return err
	}
	// Only the platform-owned root is normalized here.  Files installed by
	// staging are handed to the experiment identity at the staging boundary;
	// arbitrary project files and symlinks are never recursively rewritten.
	// Apply the collaborative mode while the platform identity still owns the
	// freshly created root.  After ownership moves to the experiment identity,
	// this deliberately capability-minimal launcher no longer has CAP_FOWNER.
	if err := os.Chmod(worktree, 02775); err != nil {
		return err
	}
	// Reserve the platform trace seam before handing the worktree root to the
	// experiment identity. PID 1 intentionally has no DAC override afterwards.
	if err := os.MkdirAll(trajectoryDir, 02770); err != nil {
		return err
	}
	if err := os.Chmod(trajectoryDir, 02770); err != nil {
		return err
	}
	if err := os.Chown(trajectoryDir, 0, 10001); err != nil {
		return err
	}
	session, err := os.OpenFile(sessionPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0660)
	if err != nil {
		return err
	}
	if err = session.Chmod(0660); err == nil {
		err = session.Chown(0, 10001)
	}
	closeErr := session.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	return os.Chown(worktree, 10001, 10001)
}

func childEnvironment(adapter runnerAdapter, token string) []string {
	values := []string{"PATH=/opt/rc-runner/usr/local/bin:/opt/rc-runner/usr/bin:/usr/local/bin:/usr/bin:/bin", "HOME=/run/rc-user/home", "TMPDIR=/run/rc-user/tmp", "LANG=C.UTF-8", "MODEL_ROUTE=" + os.Getenv("MODEL_ROUTE"), "OPENAI_BASE_URL=" + os.Getenv("OPENAI_BASE_URL"), "ANTHROPIC_BASE_URL=" + os.Getenv("ANTHROPIC_BASE_URL"), "RC_NATIVE_RUNNER_REF=" + os.Getenv("RC_NATIVE_RUNNER_REF"), "RC_NATIVE_SELECTED_MODEL_PROTOCOL=" + os.Getenv("RC_NATIVE_SELECTED_MODEL_PROTOCOL"), "RC_NATIVE_CHILD_ROLE=agent"}
	values = append(values, adapter.environment()...)
	protocol := os.Getenv("RC_NATIVE_SELECTED_MODEL_PROTOCOL")
	if strings.HasPrefix(protocol, "anthropic-") {
		values = append(values, "ANTHROPIC_API_KEY="+token)
	} else {
		values = append(values, "OPENAI_API_KEY="+token)
	}
	return values
}

func readCredential() ([]byte, error) {
	resolved, err := filepath.EvalSymlinks(tokenPath)
	if err != nil {
		return nil, err
	}
	credentialDirectory, err := filepath.EvalSymlinks(filepath.Dir(tokenPath))
	if err != nil {
		return nil, err
	}
	credentialRoot := credentialDirectory + string(os.PathSeparator)
	if !strings.HasPrefix(resolved, credentialRoot) {
		return nil, errors.New("unsafe credential projection")
	}
	descriptor, err := syscall.Open(
		resolved,
		syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW,
		0,
	)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(descriptor), resolved)
	if file == nil {
		_ = syscall.Close(descriptor)
		return nil, errors.New("unsafe credential projection")
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	statValue, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || info.Mode().Perm() != 0400 || statValue.Uid != 0 || statValue.Gid != 0 || info.Size() < 1 || info.Size() > 65536 {
		return nil, errors.New("unsafe credential projection")
	}
	return io.ReadAll(io.LimitReader(file, 65537))
}

func runUnprivilegedChild(argv []string) error {
	if len(argv) == 0 || !filepath.IsAbs(argv[0]) {
		return errors.New("child argv must begin with an absolute path")
	}
	syscall.Umask(0002)
	if os.Getenv("RC_NATIVE_CHILD_ROLE") == "agent" {
		if err := prepareRunnerConfiguration(argv); err != nil {
			return err
		}
	}
	if err := setNoNewPrivileges(); err != nil {
		return err
	}
	status, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return err
	}
	text := string(status)
	if !strings.Contains(text, "CapEff:\t0000000000000000") || !strings.Contains(text, "NoNewPrivs:\t1") {
		return errors.New("child security transition was not effective")
	}
	return syscall.Exec(argv[0], argv, os.Environ())
}

func validateRequest(frame request) error {
	if frame.JobUID == "" || frame.PodUID == "" || frame.RequestRef == "" || frame.Generation < 0 {
		return errors.New("identity_missing")
	}
	if len(frame.RequestDigest) != 64 {
		return errors.New("digest_invalid")
	}
	digest := sha256.Sum256(frame.Payload)
	if !strings.EqualFold(frame.RequestDigest, hex.EncodeToString(digest[:])) {
		return errors.New("digest_mismatch")
	}
	return nil
}

func requestIdentity(frame request) string {
	return strings.Join(
		[]string{frame.Command, frame.RequestRef, frame.JobUID, frame.PodUID, strconv.Itoa(frame.Generation)},
		"\x00",
	)
}

func isQuery(command string) bool {
	return command == "credentialStatus" || command == "inspect" || command == "readPty"
}

func decodePayload(raw json.RawMessage, target any) error {
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return errors.New("payload_invalid")
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		return errors.New("payload_invalid")
	}
	return nil
}

func writeFrame(writer io.Writer, value acknowledgement) error {
	bytes, err := json.Marshal(value)
	if err != nil || len(bytes) > maxFrame {
		return errors.New("ack_invalid")
	}
	header := make([]byte, 4)
	binary.BigEndian.PutUint32(header, uint32(len(bytes)))
	if _, err = writer.Write(header); err != nil {
		return err
	}
	_, err = writer.Write(bytes)
	return err
}

func removeSocket() error {
	info, err := os.Lstat(socketPath)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || info.Mode()&os.ModeSocket == 0 {
		return errors.New("unsafe launcher socket path")
	}
	return os.Remove(socketPath)
}

func writeAtomicJSON(path string, value any) error {
	bytes, err := json.Marshal(value)
	if err != nil {
		return err
	}
	if info, statErr := os.Lstat(path); statErr == nil && info.Mode()&os.ModeSymlink != 0 {
		return errors.New("unsafe state file symlink")
	} else if statErr != nil && !errors.Is(statErr, os.ErrNotExist) {
		return statErr
	}
	directoryPath := filepath.Dir(path)
	temp, err := os.CreateTemp(directoryPath, ".rc-state-")
	if err != nil {
		return err
	}
	tempName := temp.Name()
	defer os.Remove(tempName)
	if err = temp.Chmod(0600); err == nil {
		if os.Geteuid() == 0 {
			err = temp.Chown(0, 0)
		}
	}
	if err == nil {
		_, err = temp.Write(bytes)
	}
	if err == nil {
		err = temp.Sync()
	}
	closeErr := temp.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	if err = os.Rename(tempName, path); err != nil {
		return err
	}
	directory, err := os.Open(directoryPath)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}
func now() string     { return time.Now().UTC().Format(time.RFC3339Nano) }
func fatal(err error) { fmt.Fprintln(os.Stderr, "rc-native-launcher:", err); os.Exit(1) }
