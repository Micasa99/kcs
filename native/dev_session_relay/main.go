// rc-dev-session-relay is the credential gate in front of loopback OpenVSCode.
// It owns no provider or platform token and never logs the browser credential.
package main

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"time"
)

const credentialHeader = "X-RC-Dev-Session-Credential"

type config struct {
	listenAddr     string
	upstream       *url.URL
	credentialFile string
}

type gate struct {
	config config
	proxy  *httputil.ReverseProxy
}

func main() {
	cfg, err := configFromEnvironment()
	if err != nil {
		log.Fatal(err)
	}
	server := &http.Server{
		Addr:              cfg.listenAddr,
		Handler:           newGate(cfg),
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       90 * time.Second,
		MaxHeaderBytes:    32 << 10,
	}
	log.Printf("rc-dev-session-relay listening on %s", cfg.listenAddr)
	if err := server.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
		log.Fatal(err)
	}
}

func configFromEnvironment() (config, error) {
	rawUpstream := strings.TrimSpace(os.Getenv("UPSTREAM_URL"))
	upstream, err := url.Parse(rawUpstream)
	if err != nil || upstream.Scheme != "http" || upstream.User != nil || upstream.Host == "" {
		return config{}, errors.New("UPSTREAM_URL must be a loopback HTTP URL")
	}
	host, _, err := net.SplitHostPort(upstream.Host)
	if err != nil {
		host = upstream.Hostname()
	}
	address := net.ParseIP(host)
	if host != "localhost" && (address == nil || !address.IsLoopback()) {
		return config{}, errors.New("UPSTREAM_URL must resolve by literal loopback identity")
	}
	cfg := config{
		listenAddr:     requiredEnv("LISTEN_ADDR"),
		upstream:       upstream,
		credentialFile: requiredEnv("DEV_SESSION_CREDENTIAL_FILE"),
	}
	if cfg.listenAddr == "" || cfg.credentialFile == "" {
		return config{}, errors.New("relay listen and credential settings are required")
	}
	return cfg, nil
}

func requiredEnv(name string) string { return strings.TrimSpace(os.Getenv(name)) }

func newGate(cfg config) http.Handler {
	proxy := httputil.NewSingleHostReverseProxy(cfg.upstream)
	originalDirector := proxy.Director
	proxy.Director = func(request *http.Request) {
		originalDirector(request)
		request.Header.Del(credentialHeader)
		request.Header.Del("Authorization")
		request.Header.Del("Proxy-Authorization")
		request.Header.Del("Cookie")
		request.Header.Del("X-Forwarded-For")
		request.Header.Del("X-Forwarded-Host")
		request.Header.Del("X-Forwarded-Proto")
		request.Host = cfg.upstream.Host
	}
	proxy.ErrorHandler = func(writer http.ResponseWriter, request *http.Request, err error) {
		log.Printf("loopback relay unavailable method=%s", request.Method)
		writeError(writer, http.StatusServiceUnavailable, "RELAY_DOWN")
	}
	return &gate{config: cfg, proxy: proxy}
}

func (g *gate) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	credential, err := readBounded(g.config.credentialFile, 4096)
	if err != nil || credential == "" {
		writeError(writer, http.StatusServiceUnavailable, "CREDENTIAL_NOT_READY")
		return
	}
	supplied := request.Header.Get(credentialHeader)
	if len(supplied) != len(credential) || subtle.ConstantTimeCompare([]byte(supplied), []byte(credential)) != 1 {
		writeError(writer, http.StatusUnauthorized, "INVALID_CREDENTIAL")
		return
	}
	g.proxy.ServeHTTP(writer, request)
}

func readBounded(path string, maximum int64) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	content, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil {
		return "", err
	}
	if int64(len(content)) > maximum {
		return "", fmt.Errorf("%s exceeds the relay limit", path)
	}
	return strings.TrimSpace(string(content)), nil
}

func writeError(writer http.ResponseWriter, status int, code string) {
	writer.Header().Set("Content-Type", "application/json")
	writer.Header().Set("Cache-Control", "no-store")
	writer.WriteHeader(status)
	_ = json.NewEncoder(writer).Encode(map[string]string{"code": code})
}
