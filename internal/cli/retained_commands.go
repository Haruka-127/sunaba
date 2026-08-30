package cli

import (
	"encoding/json"
	"fmt"

	"sunaba/internal/retention"
	"sunaba/internal/trustedui"
)

func (a *app) retainedList(dir string, jsonOutput bool) error {
	_, _, projectState, err := a.loadEffectivePolicy(dir)
	if err != nil {
		return err
	}
	items, err := retention.ListProjectItems(projectState)
	if err != nil {
		return err
	}
	if jsonOutput {
		data, err := json.MarshalIndent(items, "", "  ")
		if err != nil {
			return err
		}
		if len(data) > 1<<20 {
			return fmt.Errorf("bounded retained item list exceeds 1 MiB")
		}
		_, err = fmt.Fprintf(a.output, "%s\n", data)
		return err
	}
	for _, item := range items {
		fmt.Fprintf(a.output, "%s  %s\n  %d entries · %d bytes\n  Object digest: %s\n", item.RetainedID, trustedui.SanitizeTerminal(item.Root), item.EntryCount, item.LogicalBytes, item.ObjectDigest)
	}
	return nil
}

func (a *app) retainedShow(dir, retainedID string) error {
	_, _, projectState, err := a.loadEffectivePolicy(dir)
	if err != nil {
		return err
	}
	item, err := retention.ShowProjectItem(projectState, retainedID)
	if err != nil {
		return err
	}
	fmt.Fprintf(a.output, "%s\n\nPath\n  %s\n\nExact retained data\n  Entries        %d\n  Logical bytes  %d\n  Object digest  %s\n  Work Set       %s\n", item.RetainedID, trustedui.SanitizeTerminal(item.Root), item.EntryCount, item.LogicalBytes, item.ObjectDigest, item.WorkSetDigest)
	return nil
}

func (a *app) retainedDiscard(dir, retainedID, expectedObject string, expectedBytes int64, yes bool) error {
	projectPolicy, _, projectState, err := a.loadEffectivePolicy(dir)
	if err != nil {
		return err
	}
	if !yes {
		return fmt.Errorf("retained discard requires --yes with exact object digest and logical bytes")
	}
	lock, err := a.store.AcquireProjectLock(projectPolicy.ProjectRoot)
	if err != nil {
		return err
	}
	defer lock.Close()
	if lock.ProjectID != projectPolicy.ProjectID {
		return fmt.Errorf("Project identity mismatch")
	}
	if err := retention.DiscardProjectItem(projectState, retainedID, expectedObject, expectedBytes); err != nil {
		return err
	}
	fmt.Fprintf(a.output, "Discarded retained item %s after verifying its exact object digest and %d logical bytes.\n", retainedID, expectedBytes)
	return nil
}
