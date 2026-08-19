package policy

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	"sunaba/internal/webgateway"
)

func TestClassifyApplicationAssignsEveryMutablePolicyGroup(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	current, err := New(root, strings.Repeat("a", 64), "1.18.18", "1.2.2", "sunaba-base:test", "secure", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name  string
		class ApplicationClass
		path  string
		edit  func(*ProjectPolicy)
	}{
		{"audit", ApplyImmediately, "audit", func(p *ProjectPolicy) { p.Audit.RetentionDays++ }},
		{"session", ApplyNextSession, "session", func(p *ProjectPolicy) { p.Session.IdleSeconds++ }},
		{"model", ApplyNextSession, "model", func(p *ProjectPolicy) { p.Model.MaxRequests++ }},
		{"git", ApplyNextSession, "git", func(p *ProjectPolicy) {
			p.Git.Remotes = []GitRemotePolicy{{Name: "origin", URL: "https://example.com/project.git"}}
		}},
		{"web", ApplyNextSession, "web", func(p *ProjectPolicy) { p.Web.MaxRequests++ }},
		{"mode", ApplyAfterRecreate, "mode", func(p *ProjectPolicy) { p.Mode = "dev" }},
		{"dependency", ApplyAfterRecreate, "dependency", func(p *ProjectPolicy) { p.Dependency.AgentImage = "sunaba-base:changed" }},
		{"resources", ApplyAfterRecreate, "resources", func(p *ProjectPolicy) { p.Resources.CPUs++ }},
		{"export", ApplyAfterRecreate, "export", func(p *ProjectPolicy) { p.Export.MaxEntries++ }},
		{"snapshot", ApplyAfterRecreate, "snapshot", func(p *ProjectPolicy) { p.Snapshot.Exclude = []string{"vendor"} }},
		{"protected", ApplyAfterRecreate, "protected_paths", func(p *ProjectPolicy) { p.ProtectedPaths = append(p.ProtectedPaths, ".cache") }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			desired := current
			desired.Model.AllowedModels = append([]string(nil), current.Model.AllowedModels...)
			desired.Git.Remotes = append([]GitRemotePolicy(nil), current.Git.Remotes...)
			desired.Web.OriginPresets = append([]string(nil), current.Web.OriginPresets...)
			desired.Web.CustomRules = append([]webgateway.OriginRule(nil), current.Web.CustomRules...)
			desired.Web.Rules = append([]webgateway.OriginRule(nil), current.Web.Rules...)
			desired.Snapshot.Exclude = append([]string(nil), current.Snapshot.Exclude...)
			desired.ProtectedPaths = append([]string(nil), current.ProtectedPaths...)
			test.edit(&desired)
			desired.UpdatedAt = current.UpdatedAt.Add(time.Second)
			plan, err := ClassifyApplication(current, desired)
			if err != nil {
				t.Fatal(err)
			}
			if len(plan.Changes) != 1 || plan.Changes[0].Path != test.path || plan.Changes[0].Class != test.class {
				t.Fatalf("plan=%+v", plan)
			}
		})
	}
}
