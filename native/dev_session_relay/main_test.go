package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"
)

func TestGateCredentialAndHTTPProxy(t *testing.T) {
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
	mustWrite(t, credentialFile, "canary-credential")
	parsed, _ := url.Parse(upstream.URL)
	handler := newGate(config{
		upstream: parsed, credentialFile: credentialFile,
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

}

func mustWrite(t *testing.T, path string, value string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(value), 0o600); err != nil {
		t.Fatal(err)
	}
}
