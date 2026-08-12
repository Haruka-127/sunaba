package opencode

import (
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"regexp"
)

const ModelGatewayProviderID = "openai"

var modelIDPattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._:/-]{0,255}$`)
var environmentNamePattern = regexp.MustCompile(`^[A-Z][A-Z0-9_]{0,127}$`)

type ModelGatewayProviderConfig struct {
	BaseURL       string
	AllowedModels []string
	DefaultModel  string
	TokenEnv      string
}

func BuildModelGatewayConfig(config ModelGatewayProviderConfig) ([]byte, error) {
	parsed, err := url.Parse(config.BaseURL)
	if err != nil || parsed.Scheme != "http" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.Path != "/v1" {
		return nil, fmt.Errorf("Model Gateway base URL must be a guest-loopback HTTP /v1 endpoint")
	}
	host, port, err := net.SplitHostPort(parsed.Host)
	if err != nil || host != "127.0.0.1" || port == "" {
		return nil, fmt.Errorf("Model Gateway base URL must use 127.0.0.1 and an explicit port")
	}
	if len(config.AllowedModels) == 0 || len(config.AllowedModels) > 32 || !environmentNamePattern.MatchString(config.TokenEnv) {
		return nil, fmt.Errorf("Model Gateway model allowlist and token environment name are invalid")
	}
	allowed := make([]string, 0, len(config.AllowedModels))
	seen := make(map[string]struct{}, len(config.AllowedModels))
	for _, modelID := range config.AllowedModels {
		if !modelIDPattern.MatchString(modelID) {
			return nil, fmt.Errorf("Model Gateway model allowlist and token environment name are invalid")
		}
		if _, exists := seen[modelID]; exists {
			return nil, fmt.Errorf("Model Gateway model allowlist contains a duplicate")
		}
		seen[modelID] = struct{}{}
		allowed = append(allowed, modelID)
	}
	if !modelIDPattern.MatchString(config.DefaultModel) {
		return nil, fmt.Errorf("Model Gateway default model is invalid")
	}
	if _, exists := seen[config.DefaultModel]; !exists {
		return nil, fmt.Errorf("Model Gateway default model is not allowed")
	}
	type options struct {
		BaseURL string `json:"baseURL"`
		APIKey  string `json:"apiKey"`
	}
	type provider struct {
		Whitelist []string `json:"whitelist"`
		Options   options  `json:"options"`
	}
	payload := struct {
		Schema           string              `json:"$schema"`
		Model            string              `json:"model"`
		SmallModel       string              `json:"small_model"`
		EnabledProviders []string            `json:"enabled_providers"`
		Providers        map[string]provider `json:"provider"`
	}{
		Schema: "https://opencode.ai/config.json", Model: ModelGatewayProviderID + "/" + config.DefaultModel,
		SmallModel:       ModelGatewayProviderID + "/" + config.DefaultModel,
		EnabledProviders: []string{ModelGatewayProviderID},
		Providers: map[string]provider{
			ModelGatewayProviderID: {
				Whitelist: allowed,
				Options:   options{BaseURL: config.BaseURL, APIKey: "{env:" + config.TokenEnv + "}"},
			},
		},
	}
	encoded, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(encoded, '\n'), nil
}
