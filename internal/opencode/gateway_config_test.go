package opencode

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestBuildModelGatewayConfigOverridesBuiltInOpenAIProviderWithoutDefiningModels(t *testing.T) {
	encoded, err := BuildModelGatewayConfig(ModelGatewayProviderConfig{
		BaseURL: "http://127.0.0.1:4141/v1", AllowedModels: []string{"gpt-5", "gpt-5-mini"},
		DefaultModel: "gpt-5", TokenEnv: "SUNABA_MODEL_GATEWAY_TOKEN",
	})
	if err != nil {
		t.Fatal(err)
	}
	text := string(encoded)
	for _, expected := range []string{
		`"enabled_providers": [`, `"openai"`, `"gpt-5-mini"`,
		`"whitelist": [`, `"baseURL": "http://127.0.0.1:4141/v1"`,
		`"apiKey": "{env:SUNABA_MODEL_GATEWAY_TOKEN}"`, `"model": "openai/gpt-5"`,
	} {
		if !strings.Contains(text, expected) {
			t.Fatalf("config=%s missing %s", text, expected)
		}
	}
	for _, forbidden := range []string{`"npm"`, `"models"`, `"limit"`, `"context"`, `"output"`} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("config defines OpenCode-owned model metadata %s: %s", forbidden, text)
		}
	}
	if strings.Contains(text, "gateway-token-") || !json.Valid(encoded) {
		t.Fatalf("config is invalid or contains a token: %s", text)
	}
}

func TestBuildModelGatewayConfigRejectsNonLoopbackAndInvalidModelSelection(t *testing.T) {
	base := ModelGatewayProviderConfig{
		BaseURL: "http://127.0.0.1:4141/v1", AllowedModels: []string{"gpt-5", "gpt-5-mini"},
		DefaultModel: "gpt-5", TokenEnv: "SUNABA_MODEL_GATEWAY_TOKEN",
	}
	for _, mutate := range []func(*ModelGatewayProviderConfig){
		func(config *ModelGatewayProviderConfig) { config.BaseURL = "https://api.openai.com/v1" },
		func(config *ModelGatewayProviderConfig) { config.BaseURL = "http://0.0.0.0:4141/v1" },
		func(config *ModelGatewayProviderConfig) { config.TokenEnv = "bad-token" },
		func(config *ModelGatewayProviderConfig) { config.AllowedModels = nil },
		func(config *ModelGatewayProviderConfig) { config.AllowedModels = []string{"gpt-5", "gpt-5"} },
		func(config *ModelGatewayProviderConfig) { config.DefaultModel = "gpt-not-allowed" },
	} {
		config := base
		mutate(&config)
		if _, err := BuildModelGatewayConfig(config); err == nil {
			t.Fatalf("unsafe config was accepted: %+v", config)
		}
	}
}
