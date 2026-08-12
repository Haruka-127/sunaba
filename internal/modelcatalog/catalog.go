package modelcatalog

import (
	"fmt"
	"sort"
)

type AuthMode string

const (
	AuthAPIKey AuthMode = "api_key"
	AuthOAuth  AuthMode = "oauth"
)

type Limit struct {
	Context int64 `json:"context"`
	Input   int64 `json:"input"`
	Output  int64 `json:"output"`
}

type Model struct {
	ID          string
	Name        string
	Family      string
	ReleaseDate string
	Attachment  bool
	Reasoning   bool
	Temperature bool
	ToolCall    bool
	Input       []string
	Output      []string
	Limit       Limit
	Cost        Cost
}

type Cost struct {
	Input      float64 `json:"input"`
	Output     float64 `json:"output"`
	CacheRead  float64 `json:"cache_read,omitempty"`
	CacheWrite float64 `json:"cache_write,omitempty"`
}

var baseModels = map[string]Model{
	"gpt-5":               model("gpt-5", "GPT-5", "gpt", "2025-08-07", []string{"text", "image"}, Limit{400_000, 272_000, 128_000}),
	"gpt-5.3-codex-spark": model("gpt-5.3-codex-spark", "GPT-5.3 Codex Spark", "gpt-codex-spark", "2026-02-05", []string{"text", "image", "pdf"}, Limit{128_000, 100_000, 32_000}),
	"gpt-5.4":             model("gpt-5.4", "GPT-5.4", "gpt", "2026-03-05", []string{"text", "image", "pdf"}, Limit{1_050_000, 922_000, 128_000}),
	"gpt-5.4-mini":        model("gpt-5.4-mini", "GPT-5.4 mini", "gpt-mini", "2026-03-17", []string{"text", "image"}, Limit{400_000, 272_000, 128_000}),
	"gpt-5.5":             model("gpt-5.5", "GPT-5.5", "gpt", "2026-04-23", []string{"text", "image", "pdf"}, Limit{1_050_000, 922_000, 128_000}),
	"gpt-5.6-sol":         model("gpt-5.6-sol", "GPT-5.6 Sol", "gpt", "2026-07-09", []string{"text", "image", "pdf"}, Limit{1_050_000, 922_000, 128_000}),
	"gpt-5.6-terra":       model("gpt-5.6-terra", "GPT-5.6 Terra", "gpt-mini", "2026-07-09", []string{"text", "image", "pdf"}, Limit{1_050_000, 922_000, 128_000}),
	"gpt-5.6-luna":        model("gpt-5.6-luna", "GPT-5.6 Luna", "gpt-nano", "2026-07-09", []string{"text", "image", "pdf"}, Limit{1_050_000, 922_000, 128_000}),
}

var oauthLimits = map[string]Limit{
	"gpt-5.3-codex-spark": {128_000, 100_000, 32_000},
	"gpt-5.4":             {400_000, 272_000, 128_000},
	"gpt-5.4-mini":        {400_000, 272_000, 128_000},
	"gpt-5.5":             {400_000, 272_000, 128_000},
	"gpt-5.6-sol":         {500_000, 372_000, 128_000},
	"gpt-5.6-terra":       {500_000, 372_000, 128_000},
	"gpt-5.6-luna":        {500_000, 372_000, 128_000},
}

var apiCosts = map[string]Cost{
	"gpt-5":               {1.25, 10, 0.125, 0},
	"gpt-5.3-codex-spark": {1.75, 14, 0.175, 0},
	"gpt-5.4":             {2.5, 15, 0.25, 0},
	"gpt-5.4-mini":        {0.75, 4.5, 0.075, 0},
	"gpt-5.5":             {5, 30, 0.5, 0},
	"gpt-5.6-sol":         {5, 30, 0.5, 6.25},
	"gpt-5.6-terra":       {2.5, 15, 0.25, 3.125},
	"gpt-5.6-luna":        {1, 6, 0.1, 1.25},
}

func model(id, name, family, releaseDate string, input []string, limit Limit) Model {
	return Model{
		ID: id, Name: name, Family: family, ReleaseDate: releaseDate,
		Attachment: true, Reasoning: true, Temperature: false, ToolCall: true,
		Input: input, Output: []string{"text"}, Limit: limit,
	}
}

func ValidateAuthMode(mode AuthMode) error {
	if mode != AuthAPIKey && mode != AuthOAuth {
		return fmt.Errorf("unsupported Model Gateway authentication mode %q", mode)
	}
	return nil
}

func DefaultModel(mode AuthMode) (string, error) {
	if err := ValidateAuthMode(mode); err != nil {
		return "", err
	}
	if mode == AuthOAuth {
		return "gpt-5.5", nil
	}
	return "gpt-5", nil
}

func Available(mode AuthMode) ([]Model, error) {
	if err := ValidateAuthMode(mode); err != nil {
		return nil, err
	}
	ids := make([]string, 0, len(baseModels))
	for id := range baseModels {
		if mode == AuthAPIKey {
			ids = append(ids, id)
			continue
		}
		if _, exists := oauthLimits[id]; exists {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	return Resolve(mode, ids)
}

func Resolve(mode AuthMode, ids []string) ([]Model, error) {
	if err := ValidateAuthMode(mode); err != nil {
		return nil, err
	}
	result := make([]Model, 0, len(ids))
	seen := make(map[string]struct{}, len(ids))
	for _, id := range ids {
		if _, exists := seen[id]; exists {
			return nil, fmt.Errorf("duplicate model %q", id)
		}
		definition, exists := baseModels[id]
		if !exists {
			return nil, fmt.Errorf("model %q is not defined for %s authentication", id, mode)
		}
		if mode == AuthOAuth {
			limit, available := oauthLimits[id]
			if !available {
				return nil, fmt.Errorf("model %q is not available with OAuth authentication", id)
			}
			definition.Limit = limit
			definition.Cost = Cost{}
		} else {
			definition.Cost = apiCosts[id]
		}
		definition.Input = append([]string(nil), definition.Input...)
		definition.Output = append([]string(nil), definition.Output...)
		result = append(result, definition)
		seen[id] = struct{}{}
	}
	if len(result) == 0 {
		return nil, fmt.Errorf("at least one model is required")
	}
	return result, nil
}
