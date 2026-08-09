package main

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"time"
)

type terminalWrite struct {
	ptyRef  string
	session *terminalSession
	content []byte
}

type terminalWriteResult struct {
	written int
	err     error
}

func (l *launcher) prepareTerminalWrite(frame request) (terminalWrite, error) {
	var payload struct {
		PTYRef        string `json:"ptyRef"`
		ContentBase64 string `json:"contentBase64"`
	}
	if err := decodePayload(frame.Payload, &payload); err != nil {
		return terminalWrite{}, err
	}
	session := l.terminals[payload.PTYRef]
	if session == nil {
		return terminalWrite{}, errors.New("pty_not_found")
	}
	session.mu.Lock()
	closed := session.closed
	session.mu.Unlock()
	if closed || time.Now().After(session.expiresAt) {
		return terminalWrite{}, errors.New("pty_expired")
	}
	content, err := base64.StdEncoding.DecodeString(payload.ContentBase64)
	if err != nil || len(content) > maxPTYData {
		return terminalWrite{}, errors.New("pty_input_invalid")
	}
	return terminalWrite{ptyRef: payload.PTYRef, session: session, content: content}, nil
}

func (l *launcher) performTerminalWrite(write terminalWrite) (map[string]any, error) {
	timeout := l.writeTimeout
	if timeout <= 0 {
		timeout = 2 * time.Second
	}
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case write.session.writeGate <- struct{}{}:
		defer func() { <-write.session.writeGate }()
	case <-timer.C:
		return nil, errors.New("pty_write_timeout")
	}
	if write.session.write == nil {
		return nil, errors.New("pty_closed")
	}
	if err := write.session.appendFact("input_requested", write.content); err != nil {
		return nil, errors.New("pty_audit_failed")
	}
	result := make(chan terminalWriteResult, 1)
	go func() {
		written, err := write.session.write(write.content)
		result <- terminalWriteResult{written: written, err: err}
	}()
	timer.Reset(timeout)
	select {
	case completed := <-result:
		if completed.err != nil || completed.written != len(write.content) {
			return nil, errors.New("pty_closed")
		}
		_ = write.session.appendFact("input_written", nil)
		return map[string]any{"written": completed.written}, nil
	case <-timer.C:
		if write.session.cancelWrite != nil {
			write.session.cancelWrite()
		}
		l.finishTerminal(write.ptyRef, write.session, "write_timeout")
		return nil, errors.New("pty_write_timeout")
	}
}

func (session *terminalSession) appendFact(event string, content []byte) error {
	if session.factPath == "" {
		return nil
	}
	session.factMu.Lock()
	defer session.factMu.Unlock()
	session.factSequence++
	fact := map[string]any{
		"schemaVersion": 1,
		"event":         event,
		"ptyRef":        session.ptyRef,
		"jobUid":        session.jobUID,
		"podUid":        session.podUID,
		"generation":    session.generation,
		"sequence":      session.factSequence,
		"occurredAt":    now(),
	}
	if content != nil {
		fact["contentBase64"] = base64.StdEncoding.EncodeToString(content)
	}
	return appendJSONLine(session.factPath, fact)
}

func appendJSONLine(path string, value any) error {
	file, err := openAppendFile(path, 0600)
	if err != nil {
		return err
	}
	defer file.Close()
	payload, err := json.Marshal(value)
	if err != nil {
		return err
	}
	payload = append(payload, '\n')
	if _, err := file.Write(payload); err != nil {
		return err
	}
	return nil
}
