package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

func TestGateCredentialExpiryAndHTTPProxy(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Header.Get(credentialHeader) != "" || request.Header.Get("Authorization") != "" {
			t.Fatal("relay leaked a platform credential to OpenVSCode")
		}
		writer.Header().Set("Content-Type", "text/css")
		_, _ = writer.Write([]byte("ready"))
	}))
	defer upstream.Close()
	root := t.TempDir()
	credentialFile := filepath.Join(root, "credential")
	expiresFile := filepath.Join(root, "expires-at")
	revokedFile := filepath.Join(root, "revoked")
	mustWrite(t, credentialFile, "canary-credential")
	mustWrite(t, expiresFile, strconv.FormatInt(time.Now().Add(time.Minute).Unix(), 10))
	parsed, _ := url.Parse(upstream.URL)
	handler := newGate(config{
		upstream: parsed, credentialFile: credentialFile, expiresFile: expiresFile, revokedFile: revokedFile,
	})

	request := httptest.NewRequest(http.MethodGet, "http://relay/style.css", nil)
	request.Header.Set(credentialHeader, "canary-credential")
	request.Header.Set("Authorization", "Bearer must-not-cross")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || response.Header().Get("Content-Type") != "text/css" {
		t.Fatalf("unexpected proxy response: %d %s", response.Code, response.Body.String())
	}
	body, _ := io.ReadAll(response.Result().Body)
	if string(body) != "ready" {
		t.Fatalf("unexpected body %q", body)
	}

	mustWrite(t, revokedFile, "")
	revoked := httptest.NewRecorder()
	handler.ServeHTTP(revoked, request)
	if revoked.Code != http.StatusGone {
		t.Fatalf("revoked status=%d body=%s", revoked.Code, revoked.Body.String())
	}
}

func mustWrite(t *testing.T, path string, value string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(value), 0o600); err != nil {
		t.Fatal(err)
	}
}
