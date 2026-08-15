package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

type trajectoryRecorder struct {
	stdout    *lineTee
	stderr    io.Writer
	rawOut    *os.File
	rawErr    *os.File
	session   *os.File
	adapter   runnerAdapter
	mu        sync.Mutex
	observed  protocolTerminal
	closeOnce sync.Once

	piStopReason string
}

type lineTee struct {
	mu          sync.Mutex
	raw         io.Writer
	session     io.Writer
	console     io.Writer
	partial     []byte
	discardLine bool
	atLineStart bool
	onLine      func([]byte)
}

type synchronizedMultiWriter struct {
	mu      sync.Mutex
	writers []io.Writer
}

func newTrajectoryRecorder(rawOutPath, rawErrPath, sessionFile string, adapter runnerAdapter) (*trajectoryRecorder, error) {
	return newTrajectoryRecorderWithOwnership(rawOutPath, rawErrPath, sessionFile, adapter, true)
}

func newTrajectoryRecorderWithOwnership(rawOutPath, rawErrPath, sessionFile string, adapter runnerAdapter, setOwner bool) (*trajectoryRecorder, error) {
	trajectoryDir := filepath.Dir(sessionFile)
	if err := os.MkdirAll(trajectoryDir, 0770); err != nil {
		return nil, err
	}
	if setOwner {
		if err := os.Chown(trajectoryDir, 0, 10001); err != nil {
			return nil, err
		}
		if err := os.Chmod(trajectoryDir, 02770); err != nil {
			return nil, err
		}
	}
	rawOut, err := openAppendFile(rawOutPath, 0600)
	if err != nil {
		return nil, err
	}
	rawErr, err := openAppendFile(rawErrPath, 0600)
	if err != nil {
		rawOut.Close()
		return nil, err
	}
	session, err := openAppendFile(sessionFile, 0660)
	if err != nil {
		rawOut.Close()
		rawErr.Close()
		return nil, err
	}
	if setOwner {
		if err := session.Chmod(0660); err != nil {
			rawOut.Close()
			rawErr.Close()
			session.Close()
			return nil, err
		}
		if err := session.Chown(0, 10001); err != nil {
			rawOut.Close()
			rawErr.Close()
			session.Close()
			return nil, err
		}
	}
	recorder := &trajectoryRecorder{
		rawOut:  rawOut,
		rawErr:  rawErr,
		session: session,
		adapter: adapter,
	}
	recorder.stdout = &lineTee{
		raw: rawOut, session: session, console: os.Stdout,
		atLineStart: true, onLine: recorder.observeLine,
	}
	recorder.stderr = &synchronizedMultiWriter{writers: []io.Writer{rawErr, os.Stderr}}
	return recorder, nil
}

func openAppendFile(path string, mode os.FileMode) (*os.File, error) {
	if info, err := os.Lstat(path); err == nil && info.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("unsafe_append_path")
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	return os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, mode)
}

func (writer *synchronizedMultiWriter) Write(payload []byte) (int, error) {
	writer.mu.Lock()
	defer writer.mu.Unlock()
	for _, target := range writer.writers {
		if _, err := target.Write(payload); err != nil {
			return 0, err
		}
	}
	return len(payload), nil
}

func (writer *lineTee) Write(payload []byte) (int, error) {
	writer.mu.Lock()
	defer writer.mu.Unlock()
	written := len(payload)
	if _, err := writer.raw.Write(payload); err != nil {
		return 0, err
	}
	if _, err := writer.session.Write(payload); err != nil {
		return 0, err
	}
	for remaining := payload; len(remaining) > 0; {
		if writer.atLineStart {
			if _, err := writer.console.Write([]byte("RCJL|")); err != nil {
				return 0, err
			}
			writer.atLineStart = false
		}
		end := bytes.IndexByte(remaining, '\n')
		if end < 0 {
			if _, err := writer.console.Write(remaining); err != nil {
				return 0, err
			}
			break
		}
		segment := remaining[:end+1]
		if _, err := writer.console.Write(segment); err != nil {
			return 0, err
		}
		writer.atLineStart = true
		remaining = remaining[end+1:]
	}
	for len(payload) > 0 {
		end := bytes.IndexByte(payload, '\n')
		segment := payload
		complete := end >= 0
		if complete {
			segment = payload[:end]
		}
		if !writer.discardLine {
			if len(writer.partial)+len(segment) <= 1048576 {
				writer.partial = append(writer.partial, segment...)
			} else {
				writer.partial = nil
				writer.discardLine = true
			}
		}
		if !complete {
			break
		}
		if !writer.discardLine {
			writer.onLine(bytes.TrimSpace(writer.partial))
		}
		writer.partial = nil
		writer.discardLine = false
		payload = payload[end+1:]
	}
	return written, nil
}

func (writer *lineTee) flush() error {
	writer.mu.Lock()
	defer writer.mu.Unlock()
	if len(writer.partial) == 0 || writer.discardLine {
		return nil
	}
	writer.onLine(bytes.TrimSpace(writer.partial))
	writer.partial = nil
	return nil
}

func (recorder *trajectoryRecorder) observeLine(line []byte) {
	if len(line) == 0 {
		return
	}
	var event map[string]any
	if json.Unmarshal(line, &event) != nil {
		return
	}
	kind := firstString(event, "type", "event", "kind")
	template, terminal := recorder.adapter.TerminalEvents[kind]
	if !terminal {
		return
	}
	stopReason := firstString(event, "stop_reason", "stopReason", "reason")
	piAssistantStopReason := ""
	piAssistantMessageEnd := false
	if recorder.adapter.RunnerRef == "runner-pi" && kind == "message_end" {
		if message, ok := event["message"].(map[string]any); ok && firstString(message, "role") == "assistant" {
			piAssistantMessageEnd = true
			piAssistantStopReason = firstString(message, "stop_reason", "stopReason", "reason")
			if stopReason == "" {
				stopReason = piAssistantStopReason
			}
		}
	}
	if stopReason == "" {
		stopReason = template.StopReason
	}
	errorCode := firstString(event, "error_code", "errorCode", "code")
	if errorCode == "" {
		if nested, ok := event["error"].(map[string]any); ok {
			errorCode = firstString(nested, "code", "type")
		}
		if errorCode == "" {
			errorCode = template.ErrorCode
		}
	}
	recorder.mu.Lock()
	if piAssistantMessageEnd {
		// Pi may retry after an assistant error.  Keeping only the latest
		// assistant terminal lets a later successful message clear that error.
		recorder.piStopReason = piAssistantStopReason
	}
	if recorder.adapter.RunnerRef == "runner-pi" && kind == "agent_end" && stopReason == "" {
		stopReason = recorder.piStopReason
	}
	recorder.observed = protocolTerminal{
		Observed:   true,
		EventKind:  stringPointer(kind),
		StopReason: optionalStringPointer(stopReason),
		ErrorCode:  optionalStringPointer(errorCode),
	}
	recorder.mu.Unlock()
}

func firstString(values map[string]any, keys ...string) string {
	for _, key := range keys {
		if value, ok := values[key].(string); ok && value != "" {
			return value
		}
	}
	return ""
}

func stringPointer(value string) *string { return &value }

func optionalStringPointer(value string) *string {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	return &value
}

func (recorder *trajectoryRecorder) close() {
	recorder.closeOnce.Do(func() {
		_ = recorder.stdout.flush()
		_ = recorder.session.Sync()
		_ = recorder.rawOut.Sync()
		_ = recorder.rawErr.Sync()
		_ = recorder.session.Close()
		_ = recorder.rawOut.Close()
		_ = recorder.rawErr.Close()
	})
}

func (recorder *trajectoryRecorder) terminal() protocolTerminal {
	recorder.mu.Lock()
	defer recorder.mu.Unlock()
	return recorder.observed
}
