package opencode

import (
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"regexp"

	"sunaba/internal/modelcatalog"
)

const ModelGatewayProviderID = "sunaba"

var modelIDPattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._:/-]{0,255}$`)
var environmentNamePattern = regexp.MustCompile(`^[A-Z][A-Z0-9_]{0,127}$`)

type ModelGatewayProviderConfig struct {
	BaseURL       string
	AllowedModels []string
	DefaultModel  string
	TokenEnv      string
	AuthMode      modelcatalog.AuthMode
}

func BuildModelGatewayConfig(config ModelGatewayProviderConfig) ([]byte, error) {
	if config.AuthMode == "" {
		config.AuthMode = modelcatalog.AuthAPIKey
	}
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
	definitions, err := modelcatalog.Resolve(config.AuthMode, allowed)
	if err != nil {
		return nil, fmt.Errorf("Model Gateway model definitions are invalid: %w", err)
	}
	type options struct {
		BaseURL string `json:"baseURL"`
		APIKey  string `json:"apiKey"`
	}
	type modalities struct {
		Input  []string `json:"input"`
		Output []string `json:"output"`
	}
	type model struct {
		ID          string             `json:"id"`
		Name        string             `json:"name"`
		Family      string             `json:"family"`
		ReleaseDate string             `json:"release_date"`
		Attachment  bool               `json:"attachment"`
		Reasoning   bool               `json:"reasoning"`
		Temperature bool               `json:"temperature"`
		ToolCall    bool               `json:"tool_call"`
		Limit       modelcatalog.Limit `json:"limit"`
		Cost        modelcatalog.Cost  `json:"cost"`
		Modalities  modalities         `json:"modalities"`
	}
	type provider struct {
		Name      string           `json:"name"`
		NPM       string           `json:"npm"`
		Whitelist []string         `json:"whitelist"`
		Models    map[string]model `json:"models"`
		Options   options          `json:"options"`
	}
	payload := struct {
		Schema           string              `json:"$schema"`
		Model            string              `json:"model"`
		SmallModel       string              `json:"small_model"`
		Permission       string              `json:"permission"`
		EnabledProviders []string            `json:"enabled_providers"`
		Providers        map[string]provider `json:"provider"`
	}{
		Schema: "https://opencode.ai/config.json", Model: ModelGatewayProviderID + "/" + config.DefaultModel,
		SmallModel: ModelGatewayProviderID + "/" + config.DefaultModel, Permission: "allow",
		EnabledProviders: []string{ModelGatewayProviderID},
		Providers: map[string]provider{
			ModelGatewayProviderID: {
				Name: "sunaba OpenAI Gateway", NPM: "@ai-sdk/openai",
				Whitelist: allowed,
				Models: func() map[string]model {
					models := make(map[string]model, len(definitions))
					for _, definition := range definitions {
						models[definition.ID] = model{
							ID: definition.ID, Name: definition.Name, Family: definition.Family,
							ReleaseDate: definition.ReleaseDate, Attachment: definition.Attachment,
							Reasoning: definition.Reasoning, Temperature: definition.Temperature,
							ToolCall: definition.ToolCall, Limit: definition.Limit,
							Cost:       definition.Cost,
							Modalities: modalities{Input: definition.Input, Output: definition.Output},
						}
					}
					return models
				}(),
				Options: options{BaseURL: config.BaseURL, APIKey: "{env:" + config.TokenEnv + "}"},
			},
		},
	}
	encoded, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(encoded, '\n'), nil
}
