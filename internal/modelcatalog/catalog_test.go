package modelcatalog

import "testing"

func TestDefaultModelsIncludesEntireOAuthCatalogWithPreferredModelFirst(t *testing.T) {
	defaults, err := DefaultModels(AuthOAuth)
	if err != nil {
		t.Fatal(err)
	}
	available, err := Available(AuthOAuth)
	if err != nil {
		t.Fatal(err)
	}
	if len(defaults) != len(available) || defaults[0] != "gpt-5.5" {
		t.Fatalf("defaults=%v available=%v", defaults, available)
	}
	seen := make(map[string]struct{}, len(defaults))
	for _, id := range defaults {
		seen[id] = struct{}{}
	}
	for _, definition := range available {
		if _, exists := seen[definition.ID]; !exists {
			t.Fatalf("OAuth model %q is missing from defaults %v", definition.ID, defaults)
		}
	}
	apiDefaults, err := DefaultModels(AuthAPIKey)
	if err != nil || len(apiDefaults) != 1 || apiDefaults[0] != "gpt-5" {
		t.Fatalf("API key defaults=%v error=%v", apiDefaults, err)
	}
}

func TestResolveUsesAuthenticationSpecificInputLimits(t *testing.T) {
	api, err := Resolve(AuthAPIKey, []string{"gpt-5.5", "gpt-5.6-sol"})
	if err != nil {
		t.Fatal(err)
	}
	oauth, err := Resolve(AuthOAuth, []string{"gpt-5.5", "gpt-5.6-sol"})
	if err != nil {
		t.Fatal(err)
	}
	if api[0].Limit.Input != 922_000 || oauth[0].Limit.Input != 272_000 || oauth[1].Limit.Context != 500_000 || oauth[1].Limit.Input != 372_000 {
		t.Fatalf("api=%+v oauth=%+v", api, oauth)
	}
}

func TestResolveRejectsUnknownAndOAuthUnsupportedModels(t *testing.T) {
	for _, test := range []struct {
		mode AuthMode
		ids  []string
	}{
		{AuthMode("unknown"), []string{"gpt-5"}},
		{AuthAPIKey, []string{"gpt-unknown"}},
		{AuthOAuth, []string{"gpt-5"}},
		{AuthAPIKey, []string{"gpt-5", "gpt-5"}},
	} {
		if _, err := Resolve(test.mode, test.ids); err == nil {
			t.Fatalf("accepted mode=%q ids=%v", test.mode, test.ids)
		}
	}
}
