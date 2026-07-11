package runtime

import (
	"encoding/json"
	"testing"
)

func TestContainsExactImageTag(t *testing.T) {
	var payload any
	if err := json.Unmarshal([]byte(`[{"configuration":{"name":"sunaba-base:1.20"}}]`), &payload); err != nil {
		t.Fatal(err)
	}
	if containsExactString(payload, "sunaba-base:1.2") {
		t.Fatal("partial image tag matched")
	}
	if !containsExactString(payload, "sunaba-base:1.20") {
		t.Fatal("exact image tag did not match")
	}
}
