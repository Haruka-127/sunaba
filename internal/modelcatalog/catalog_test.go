package modelcatalog

import "testing"

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
