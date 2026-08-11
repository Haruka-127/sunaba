package opencode

import (
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"regexp"
)

const ModelGatewayProviderID = "sunaba"

var modelIDPattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._:/-]{0,255}$`)
var environmentNamePattern = regexp.MustCompile(`^[A-Z][A-Z0-9_]{0,127}$`)

type ModelGatewayProviderConfig struct {
	BaseURL      string
	Model        string
	TokenEnv     string
	ContextLimit int64
	OutputLimit  int64
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
	if !modelIDPattern.MatchString(config.Model) || !environmentNamePattern.MatchString(config.TokenEnv) {
		return nil, fmt.Errorf("Model Gateway model and token environment name are invalid")
	}
	if config.ContextLimit <= 0 || config.OutputLimit <= 0 || config.OutputLimit > config.ContextLimit {
		return nil, fmt.Errorf("Model Gateway model limits are invalid")
	}
	type limit struct {
		Context int64 `json:"context"`
		Output  int64 `json:"output"`
	}
	type model struct {
		Name  string `json:"name"`
		Limit limit  `json:"limit"`
	}
	type options struct {
		BaseURL string `json:"baseURL"`
		APIKey  string `json:"apiKey"`
	}
	type provider struct {
		NPM       string           `json:"npm"`
		Name      string           `json:"name"`
		Whitelist []string         `json:"whitelist"`
		Options   options          `json:"options"`
		Models    map[string]model `json:"models"`
	}
	payload := struct {
		Schema           string              `json:"$schema"`
		Model            string              `json:"model"`
		SmallModel       string              `json:"small_model"`
		EnabledProviders []string            `json:"enabled_providers"`
		Providers        map[string]provider `json:"provider"`
	}{
		Schema: "https://opencode.ai/config.json", Model: ModelGatewayProviderID + "/" + config.Model,
		SmallModel:       ModelGatewayProviderID + "/" + config.Model,
		EnabledProviders: []string{ModelGatewayProviderID},
		Providers: map[string]provider{
			ModelGatewayProviderID: {
				NPM: "@ai-sdk/openai", Name: "sunaba Model Gateway", Whitelist: []string{config.Model},
				Options: options{BaseURL: config.BaseURL, APIKey: "{env:" + config.TokenEnv + "}"},
				Models:  map[string]model{config.Model: {Name: config.Model, Limit: limit{Context: config.ContextLimit, Output: config.OutputLimit}}},
			},
		},
	}
	encoded, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(encoded, '\n'), nil
}
