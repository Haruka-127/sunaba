package cli

import (
	"context"
	"fmt"
	"path/filepath"
	"time"

	urfavecli "github.com/urfave/cli/v3"

	"sunaba/internal/policy"
)

type projectSelector struct {
	Directory    string
	DirectorySet bool
	ProjectID    string
	ProjectIDSet bool
}

type projectStateTarget struct {
	ProjectID    string
	ProjectState string
}

func projectSelectorFlags(additional ...urfavecli.Flag) []urfavecli.Flag {
	flags := []urfavecli.Flag{
		&urfavecli.StringFlag{Name: "dir", Value: ".", Usage: "Project directory", OnlyOnce: true},
		&urfavecli.StringFlag{Name: "project-id", Usage: "Full Project ID shown by project list", OnlyOnce: true},
	}
	return append(flags, additional...)
}

func addProjectSelectorConstraints(root *urfavecli.Command) {
	var visit func(*urfavecli.Command)
	visit = func(command *urfavecli.Command) {
		var directory, projectID urfavecli.Flag
		for _, flag := range command.Flags {
			for _, name := range flag.Names() {
				switch name {
				case "dir":
					directory = flag
				case "project-id":
					projectID = flag
				}
			}
		}
		if directory != nil && projectID != nil {
			command.MutuallyExclusiveFlags = append(command.MutuallyExclusiveFlags, urfavecli.MutuallyExclusiveFlags{Flags: [][]urfavecli.Flag{{directory}, {projectID}}})
		}
		for _, child := range command.Commands {
			visit(child)
		}
	}
	visit(root)
}

func projectSelectorFromCommand(cmd *urfavecli.Command) projectSelector {
	return projectSelector{
		Directory: cmd.String("dir"), DirectorySet: cmd.IsSet("dir"),
		ProjectID: cmd.String("project-id"), ProjectIDSet: cmd.IsSet("project-id"),
	}
}

func (a *app) withProjectSelector(action func(context.Context, *urfavecli.Command, string) error) urfavecli.ActionFunc {
	return func(ctx context.Context, cmd *urfavecli.Command) error {
		directory, err := a.resolveProjectDirectory(projectSelectorFromCommand(cmd))
		if err != nil {
			return err
		}
		return action(ctx, cmd, directory)
	}
}

func validateProjectSelector(selector projectSelector) error {
	if selector.DirectorySet && selector.ProjectIDSet {
		return fmt.Errorf("accepts only one of --dir or --project-id")
	}
	return nil
}

// resolveProjectDirectory is the strict selector path used by normal Project
// operations. An ID is useful only when its policy still binds it to an
// existing canonical Project root.
func (a *app) resolveProjectDirectory(selector projectSelector) (string, error) {
	if err := validateProjectSelector(selector); err != nil {
		return "", err
	}
	if !selector.ProjectIDSet {
		return selector.Directory, nil
	}
	projectState, err := a.store.LookupProjectState(selector.ProjectID)
	if err != nil {
		return "", err
	}
	loaded, _, err := policy.LoadReadOnly(filepath.Join(projectState.Path, "policy.json"), time.Now())
	if err != nil {
		return "", fmt.Errorf("resolve Project ID %s: %w", selector.ProjectID, err)
	}
	if loaded.ProjectID != selector.ProjectID {
		return "", fmt.Errorf("Project policy identity does not match selected Project ID")
	}
	return loaded.ProjectRoot, nil
}

// resolveProjectStateTarget is reserved for recovery operations that must
// remain available when a policy or its original Project root is unavailable.
func (a *app) resolveProjectStateTarget(selector projectSelector) (projectStateTarget, error) {
	if err := validateProjectSelector(selector); err != nil {
		return projectStateTarget{}, err
	}
	if selector.ProjectIDSet {
		projectState, err := a.store.LookupProjectState(selector.ProjectID)
		if err != nil {
			return projectStateTarget{}, err
		}
		return projectStateTarget{ProjectID: projectState.ProjectID, ProjectState: projectState.Path}, nil
	}
	projectPolicy, _, projectState, err := a.loadEffectivePolicy(selector.Directory)
	if err != nil {
		return projectStateTarget{}, err
	}
	return projectStateTarget{ProjectID: projectPolicy.ProjectID, ProjectState: projectState}, nil
}
