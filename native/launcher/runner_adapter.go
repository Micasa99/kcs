package main

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

const runnerAdapterPath = "/opt/rc-runner/etc/rc-runner-adapter.json"

// runnerAdapter is the launcher's closed, declarative seam to a native CLI.
// Selection is by the recipe-owned runnerRef.  The executable is checked only
// as part of that declaration; an unknown executable is never run bare.
type runnerAdapter struct {
	RunnerRef      string
	Executable     string
	PromptDelivery string
	Configuration  string
	TraceSchema    string
	ModelProtocols map[string]struct{}
	TerminalEvents map[string]protocolTerminalTemplate
}

type protocolTerminalTemplate struct {
	StopReason string `json:"stopReason"`
	ErrorCode  string `json:"errorCode"`
}

type runnerAdapterDocument struct {
	SchemaVersion  int                                 `json:"schemaVersion"`
	RunnerRef      string                              `json:"runnerRef"`
	Executable     string                              `json:"executable"`
	PromptDelivery string                              `json:"promptDelivery"`
	Configuration  string                              `json:"configuration"`
	TraceSchema    string                              `json:"traceSchema"`
	ModelProtocols []string                            `json:"modelProtocols"`
	TerminalEvents map[string]protocolTerminalTemplate `json:"terminalEvents"`
}

var runnerAdapters = map[string]runnerAdapter{
	"native-lane/codex-runner@1": {
		RunnerRef:      "native-lane/codex-runner@1",
		Executable:     "/opt/rc-runner/bin/codex",
		PromptDelivery: "last-argument",
		Configuration:  "codex-responses-v1",
		TraceSchema:    "codex-jsonl",
		ModelProtocols: protocolSet("openai-responses"),
		TerminalEvents: map[string]protocolTerminalTemplate{
			"turn.completed": {},
			"turn.failed":    {StopReason: "runner_reported_failure"},
			"error":          {StopReason: "runner_reported_error"},
		},
	},
	"native-lane/pi-runner@1": {
		RunnerRef:      "native-lane/pi-runner@1",
		Executable:     "/opt/rc-runner/bin/pi",
		PromptDelivery: "last-argument",
		Configuration:  "pi-models-v1",
		TraceSchema:    "pi-jsonl",
		ModelProtocols: protocolSet("openai-completions", "anthropic-messages"),
		TerminalEvents: map[string]protocolTerminalTemplate{
			"agent_end":   {},
			"message_end": {},
			"error":       {StopReason: "runner_reported_error"},
		},
	},
}

func protocolSet(values ...string) map[string]struct{} {
	result := make(map[string]struct{}, len(values))
	for _, value := range values {
		result[value] = struct{}{}
	}
	return result
}

func resolveRunnerAdapter(argv []string) (runnerAdapter, error) {
	if len(argv) == 0 {
		return runnerAdapter{}, errors.New("entrypoint_invalid")
	}
	adapter, err := declaredRunnerAdapter(runnerAdapterPath)
	if err != nil {
		return runnerAdapter{}, err
	}
	if !filepath.IsAbs(argv[0]) || filepath.Clean(argv[0]) != adapter.Executable {
		return runnerAdapter{}, errors.New("runner_entrypoint_mismatch")
	}
	if _, found := adapter.ModelProtocols[os.Getenv("RC_NATIVE_SELECTED_MODEL_PROTOCOL")]; !found {
		return runnerAdapter{}, errors.New("runner_protocol_unsupported")
	}
	return adapter, nil
}

func declaredRunnerAdapter(path string) (runnerAdapter, error) {
	runnerRef := os.Getenv("RC_NATIVE_RUNNER_REF")
	file, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		adapter, found := runnerAdapters[runnerRef]
		if !found {
			return runnerAdapter{}, errors.New("runner_adapter_unsupported")
		}
		return adapter, nil
	}
	if err != nil {
		return runnerAdapter{}, errors.New("runner_adapter_invalid")
	}
	defer file.Close()
	var document runnerAdapterDocument
	decoder := json.NewDecoder(io.LimitReader(file, 65537))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&document) != nil || decoder.Decode(&struct{}{}) != io.EOF ||
		document.SchemaVersion != 1 || document.RunnerRef != runnerRef ||
		!filepath.IsAbs(document.Executable) ||
		!strings.HasPrefix(filepath.Clean(document.Executable), "/opt/rc-runner/") ||
		document.PromptDelivery != "last-argument" || document.TraceSchema == "" ||
		len(document.ModelProtocols) == 0 || len(document.TerminalEvents) == 0 {
		return runnerAdapter{}, errors.New("runner_adapter_invalid")
	}
	if document.Configuration != "environment-only-v1" &&
		document.Configuration != "codex-responses-v1" &&
		document.Configuration != "pi-models-v1" {
		return runnerAdapter{}, errors.New("runner_adapter_invalid")
	}
	return runnerAdapter{
		RunnerRef: document.RunnerRef, Executable: filepath.Clean(document.Executable),
		PromptDelivery: document.PromptDelivery, Configuration: document.Configuration,
		TraceSchema: document.TraceSchema, ModelProtocols: protocolSet(document.ModelProtocols...),
		TerminalEvents: document.TerminalEvents,
	}, nil
}

func (adapter runnerAdapter) withPrompt(argv []string, prompt string) []string {
	result := append([]string(nil), argv...)
	// Pi does not select a custom provider merely because models.json contains
	// one. Keep that runner-specific launch detail inside the adapter so every
	// task uses the exact Model Gateway route resolved by the platform.
	if adapter.Configuration == "pi-models-v1" {
		result = append(result, "--provider", "researchcosmos", "--model", os.Getenv("MODEL_ROUTE"))
	}
	if adapter.PromptDelivery == "last-argument" {
		return append(result, prompt)
	}
	return result
}

func (adapter runnerAdapter) environment() []string {
	switch adapter.Configuration {
	case "codex-responses-v1":
		return []string{"CODEX_HOME=/run/rc-user/home/.codex"}
	case "pi-models-v1":
		return []string{"PI_CODING_AGENT_DIR=/run/rc-user/home/pi-agent"}
	case "environment-only-v1":
		return nil
	default:
		return nil
	}
}

func prepareRunnerConfiguration(argv []string) error {
	adapter, err := resolveRunnerAdapter(argv)
	if err != nil {
		return err
	}
	route := os.Getenv("MODEL_ROUTE")
	protocol := os.Getenv("RC_NATIVE_SELECTED_MODEL_PROTOCOL")
	if route == "" {
		return errors.New("model_route_missing")
	}
	switch adapter.Configuration {
	case "codex-responses-v1":
		directory := "/run/rc-user/home/.codex"
		if err := os.MkdirAll(directory, 0700); err != nil {
			return err
		}
		contents := strings.Join([]string{
			"model = " + strconv.Quote(route),
			"model_provider = \"researchcosmos\"",
			"",
			"[model_providers.researchcosmos]",
			"name = \"ResearchCosmos Model Gateway\"",
			"base_url = " + strconv.Quote(os.Getenv("OPENAI_BASE_URL")),
			"env_key = \"OPENAI_API_KEY\"",
			"wire_api = \"responses\"",
			"",
		}, "\n")
		return writeRunnerConfig(filepath.Join(directory, "config.toml"), []byte(contents))
	case "pi-models-v1":
		directory := "/run/rc-user/home/pi-agent"
		if err := os.MkdirAll(directory, 0700); err != nil {
			return err
		}
		baseURL := os.Getenv("OPENAI_BASE_URL")
		keyName := "OPENAI_API_KEY"
		if protocol == "anthropic-messages" {
			baseURL = os.Getenv("ANTHROPIC_BASE_URL")
			keyName = "ANTHROPIC_API_KEY"
		}
		payload := map[string]any{
			"providers": map[string]any{
				"researchcosmos": map[string]any{
					"baseUrl": baseURL,
					"api":     protocol,
					"apiKey":  keyName,
					"models": []map[string]any{{
						"id":            route,
						"name":          route,
						"reasoning":     true,
						"input":         []string{"text"},
						"contextWindow": 200000,
						"maxTokens":     8192,
					}},
				},
			},
		}
		bytes, err := json.Marshal(payload)
		if err != nil {
			return err
		}
		return writeRunnerConfig(filepath.Join(directory, "models.json"), bytes)
	case "environment-only-v1":
		return nil
	default:
		return errors.New("runner_adapter_invalid")
	}
}

func writeRunnerConfig(path string, contents []byte) error {
	if err := os.WriteFile(path, contents, 0600); err != nil {
		return err
	}
	return os.Chmod(path, 0600)
}
