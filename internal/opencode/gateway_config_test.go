package opencode

import (
	"encoding/json"
	"strings"
	"testing"

	"sunaba/internal/modelcatalog"
)

func TestBuildModelGatewayConfigDefinesAuthenticationSpecificCustomProvider(t *testing.T) {
	encoded, err := BuildModelGatewayConfig(ModelGatewayProviderConfig{
		BaseURL: "http://127.0.0.1:4141/v1", AllowedModels: []string{"gpt-5.5", "gpt-5.6-sol"},
		DefaultModel: "gpt-5.5", TokenEnv: "SUNABA_MODEL_GATEWAY_TOKEN", AuthMode: modelcatalog.AuthOAuth,
	})
	if err != nil {
		t.Fatal(err)
	}
	text := string(encoded)
	for _, expected := range []string{
		`"enabled_providers": [`, `"sunaba"`, `"gpt-5.6-sol"`,
		`"whitelist": [`, `"baseURL": "http://127.0.0.1:4141/v1"`,
		`"apiKey": "{env:SUNABA_MODEL_GATEWAY_TOKEN}"`, `"model": "sunaba/gpt-5.5"`,
		`"npm": "@ai-sdk/openai"`, `"context": 400000`, `"input": 272000`,
		`"context": 500000`, `"input": 372000`, `"output": 128000`, `"reasoning": true`,
	} {
		if !strings.Contains(text, expected) {
			t.Fatalf("config=%s missing %s", text, expected)
		}
	}
	if strings.Contains(text, "gateway-token-") || !json.Valid(encoded) {
		t.Fatalf("config is invalid or contains a token: %s", text)
	}
}

func TestBuildModelGatewayConfigRejectsNonLoopbackAndInvalidModelSelection(t *testing.T) {
	base := ModelGatewayProviderConfig{
		BaseURL: "http://127.0.0.1:4141/v1", AllowedModels: []string{"gpt-5", "gpt-5.4-mini"},
		DefaultModel: "gpt-5", TokenEnv: "SUNABA_MODEL_GATEWAY_TOKEN", AuthMode: modelcatalog.AuthAPIKey,
	}
	for _, mutate := range []func(*ModelGatewayProviderConfig){
		func(config *ModelGatewayProviderConfig) { config.BaseURL = "https://api.openai.com/v1" },
		func(config *ModelGatewayProviderConfig) { config.BaseURL = "http://0.0.0.0:4141/v1" },
		func(config *ModelGatewayProviderConfig) { config.TokenEnv = "bad-token" },
		func(config *ModelGatewayProviderConfig) { config.AllowedModels = nil },
		func(config *ModelGatewayProviderConfig) { config.AllowedModels = []string{"gpt-5", "gpt-5"} },
		func(config *ModelGatewayProviderConfig) { config.DefaultModel = "gpt-not-allowed" },
		func(config *ModelGatewayProviderConfig) { config.AuthMode = modelcatalog.AuthMode("unknown") },
		func(config *ModelGatewayProviderConfig) {
			config.AllowedModels = []string{"gpt-not-defined"}
			config.DefaultModel = "gpt-not-defined"
		},
	} {
		config := base
		mutate(&config)
		if _, err := BuildModelGatewayConfig(config); err == nil {
			t.Fatalf("unsafe config was accepted: %+v", config)
		}
	}
}
