package policy

import (
	"fmt"
	"reflect"
	"slices"
)

// ApplicationClass describes when a Project policy change can take effect.
// The classification is host-owned and exhaustive: newly added policy fields
// must be assigned here before callers can silently apply them.
type ApplicationClass string

const (
	ApplyImmediately   ApplicationClass = "immediate"
	ApplyNextSession   ApplicationClass = "next-session"
	ApplyAfterRecreate ApplicationClass = "recreate-required"
)

type ApplicationChange struct {
	Path  string
	Class ApplicationClass
}

type ApplicationPlan struct {
	Changes []ApplicationChange
}

func (p ApplicationPlan) Has(class ApplicationClass) bool {
	for _, change := range p.Changes {
		if change.Class == class {
			return true
		}
	}
	return false
}

func (p ApplicationPlan) Paths(class ApplicationClass) []string {
	paths := make([]string, 0)
	for _, change := range p.Changes {
		if change.Class == class {
			paths = append(paths, change.Path)
		}
	}
	return paths
}

// ClassifyApplication compares two policies with the same immutable Project
// identity. Active Agent Session authority is never changed by this function;
// callers use the result to defer authority changes or require VM recreation.
func ClassifyApplication(current, desired ProjectPolicy) (ApplicationPlan, error) {
	if err := current.Validate(); err != nil {
		return ApplicationPlan{}, fmt.Errorf("current Project policy is invalid: %w", err)
	}
	if err := desired.Validate(); err != nil {
		return ApplicationPlan{}, fmt.Errorf("desired Project policy is invalid: %w", err)
	}
	if current.ProjectID != desired.ProjectID || current.ProjectRoot != desired.ProjectRoot || current.CreatedAt != desired.CreatedAt {
		return ApplicationPlan{}, fmt.Errorf("Project policy identity and creation time are immutable")
	}
	plan := ApplicationPlan{}
	appendChange := func(changed bool, path string, class ApplicationClass) {
		if changed {
			plan.Changes = append(plan.Changes, ApplicationChange{Path: path, Class: class})
		}
	}

	appendChange(current.Audit != desired.Audit, "audit", ApplyImmediately)

	appendChange(current.Session != desired.Session, "session", ApplyNextSession)
	appendChange(!equalModelPolicy(current.Model, desired.Model), "model", ApplyNextSession)
	appendChange(!equalGitPolicy(current.Git, desired.Git), "git", ApplyNextSession)
	appendChange(!equalWebPolicy(current.Web, desired.Web), "web", ApplyNextSession)

	appendChange(current.Mode != desired.Mode, "mode", ApplyAfterRecreate)
	appendChange(current.Dependency != desired.Dependency, "dependency", ApplyAfterRecreate)
	appendChange(current.Resources != desired.Resources, "resources", ApplyAfterRecreate)
	appendChange(current.Export != desired.Export, "export", ApplyAfterRecreate)
	appendChange(!slices.Equal(current.Snapshot.Exclude, desired.Snapshot.Exclude), "snapshot", ApplyAfterRecreate)
	appendChange(!slices.Equal(current.ProtectedPaths, desired.ProtectedPaths), "protected_paths", ApplyAfterRecreate)

	return plan, nil
}

func equalModelPolicy(left, right ModelPolicy) bool {
	leftModels, rightModels := left.AllowedModels, right.AllowedModels
	left.AllowedModels, right.AllowedModels = nil, nil
	return reflect.DeepEqual(left, right) && slices.Equal(leftModels, rightModels)
}

func equalGitPolicy(left, right GitPolicy) bool {
	leftRemotes, rightRemotes := left.Remotes, right.Remotes
	left.Remotes, right.Remotes = nil, nil
	return reflect.DeepEqual(left, right) && slices.Equal(leftRemotes, rightRemotes)
}

func equalWebPolicy(left, right WebPolicy) bool {
	leftPresets, rightPresets := left.OriginPresets, right.OriginPresets
	leftCustom, rightCustom := left.CustomRules, right.CustomRules
	leftRules, rightRules := left.Rules, right.Rules
	left.OriginPresets, right.OriginPresets = nil, nil
	left.CustomRules, right.CustomRules = nil, nil
	left.Rules, right.Rules = nil, nil
	return reflect.DeepEqual(left, right) && slices.Equal(leftPresets, rightPresets) && slices.Equal(leftCustom, rightCustom) && slices.Equal(leftRules, rightRules)
}
