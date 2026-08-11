package opencode

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestBuildModelGatewayConfigPinsResponsesProviderAndTokenEnvironment(t *testing.T) {
	encoded, err := BuildModelGatewayConfig(ModelGatewayProviderConfig{
		BaseURL: "http://127.0.0.1:4141/v1", Model: "gpt-sunaba", TokenEnv: "SUNABA_MODEL_GATEWAY_TOKEN",
		ContextLimit: 200_000, OutputLimit: 32_000,
	})
	if err != nil {
		t.Fatal(err)
	}
	text := string(encoded)
	for _, expected := range []string{
		`"npm": "@ai-sdk/openai"`, `"enabled_providers": [`, `"sunaba"`,
		`"whitelist": [`, `"baseURL": "http://127.0.0.1:4141/v1"`,
		`"apiKey": "{env:SUNABA_MODEL_GATEWAY_TOKEN}"`, `"model": "sunaba/gpt-sunaba"`,
	} {
		if !strings.Contains(text, expected) {
			t.Fatalf("config=%s missing %s", text, expected)
		}
	}
	if strings.Contains(text, "gateway-token-") || !json.Valid(encoded) {
		t.Fatalf("config is invalid or contains a token: %s", text)
	}
}

func TestBuildModelGatewayConfigRejectsNonLoopbackAndInvalidLimits(t *testing.T) {
	base := ModelGatewayProviderConfig{
		BaseURL: "http://127.0.0.1:4141/v1", Model: "gpt-sunaba", TokenEnv: "SUNABA_MODEL_GATEWAY_TOKEN",
		ContextLimit: 100, OutputLimit: 50,
	}
	for _, mutate := range []func(*ModelGatewayProviderConfig){
		func(config *ModelGatewayProviderConfig) { config.BaseURL = "https://api.openai.com/v1" },
		func(config *ModelGatewayProviderConfig) { config.BaseURL = "http://0.0.0.0:4141/v1" },
		func(config *ModelGatewayProviderConfig) { config.TokenEnv = "bad-token" },
		func(config *ModelGatewayProviderConfig) { config.OutputLimit = 101 },
	} {
		config := base
		mutate(&config)
		if _, err := BuildModelGatewayConfig(config); err == nil {
			t.Fatalf("unsafe config was accepted: %+v", config)
		}
	}
}
