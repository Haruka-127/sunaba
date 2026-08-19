package cleanup

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"sunaba/internal/audit"
	"sunaba/internal/lease"
	"sunaba/internal/recovery"
	"sunaba/internal/runtime"
	"sunaba/internal/state"
)

type Config struct {
	Store   *state.Store
	Runtime runtime.Runtime
	Audit   *audit.Recorder
}

type Result struct {
	Removed []string
	Kept    []string
	Refused []string
}

func Run(ctx context.Context, cfg Config) (Result, error) {
	var result Result
	if cfg.Store == nil || cfg.Runtime == nil || cfg.Audit == nil || !filepath.IsAbs(cfg.Store.Root) || filepath.Clean(cfg.Audit.Root) != filepath.Join(filepath.Clean(cfg.Store.Root), "audit") {
		return result, fmt.Errorf("orphan cleanup requires the state store, runtime, and host audit recorder")
	}
	resources, err := cfg.Runtime.List(ctx)
	if err != nil {
		return result, err
	}
	registry := &lease.Registry{Root: filepath.Join(cfg.Store.Root, "leases")}
	for _, listed := range resources {
		if !strings.HasPrefix(listed.Name, "sunaba-") {
			continue
		}
		info, err := cfg.Runtime.Inspect(ctx, listed.Name)
		if err != nil {
			return result, fmt.Errorf("inspect cleanup candidate %s: %w", listed.Name, err)
		}
		projectID, vmID, owned := ownedIdentity(info)
		if !owned {
			result.Refused = append(result.Refused, listed.Name)
			continue
		}
		projectState := filepath.Join(cfg.Store.Root, "projects", projectID)
		if retained, recoveryErr := recovery.Load(projectState); recoveryErr == nil {
			if retained.ProjectID == projectID && retained.VMID == vmID && retained.Container == info.Name && info.State == runtime.StateStopped && info.Labels["dev.sunaba.mode"] == retained.RuntimeMode() {
				result.Kept = append(result.Kept, info.Name)
				continue
			}
			result.Refused = append(result.Refused, info.Name)
			continue
		} else if _, statErr := os.Lstat(recovery.Path(projectState)); statErr == nil || !errors.Is(statErr, os.ErrNotExist) {
			result.Refused = append(result.Refused, info.Name)
			continue
		}
		guard, err := registry.AcquireGuard(vmID)
		if errors.Is(err, lease.ErrGuardHeld) {
			result.Kept = append(result.Kept, info.Name)
			continue
		}
		if err != nil {
			return result, fmt.Errorf("acquire cleanup guard for %s: %w", info.Name, err)
		}
		// A guardless stopped VM can contain work whose recovery record failed
		// to persist. Absence of that record is never terminal evidence that the
		// user authorized deletion.
		if info.State == runtime.StateStopped {
			_ = guard.Close()
			result.Refused = append(result.Refused, info.Name)
			continue
		}
		record, err := registry.FindLatestForVM(projectID, info.Name)
		if err != nil || record.ProjectID != projectID || record.VMID != info.Name || record.Use != "model" {
			_ = guard.Close()
			result.Refused = append(result.Refused, info.Name)
			continue
		}
		removeErr := removeOwned(ctx, cfg, registry, info, record)
		closeErr := guard.Close()
		if removeErr != nil || closeErr != nil {
			return result, errors.Join(removeErr, closeErr)
		}
		result.Removed = append(result.Removed, info.Name)
	}
	return result, nil
}

func ownedIdentity(info runtime.Info) (projectID, vmID string, ok bool) {
	projectID = info.Labels["dev.sunaba.project"]
	vmID = info.Labels["dev.sunaba.vm"]
	mode := info.Labels["dev.sunaba.mode"]
	if info.Labels["dev.sunaba.owner"] != "sunaba-supervisor" || (mode != "secure" && mode != "dev") || projectID == "" || vmID == "" {
		return "", "", false
	}
	if info.Name != "sunaba-"+projectID+"-"+vmID {
		return "", "", false
	}
	return projectID, vmID, true
}

func removeOwned(ctx context.Context, cfg Config, registry *lease.Registry, info runtime.Info, record lease.Record) error {
	details := map[string]string{"resource": info.Name, "lease_state": string(record.State), "reason": "supervisor_guard_absent"}
	if err := cfg.Audit.Append(audit.BoundaryEvent{
		Category: "cleanup", Action: "orphan.remove", Outcome: "started", ProjectID: record.ProjectID,
		VMID: record.VMID, SessionID: record.SessionID, Details: details,
	}); err != nil {
		return err
	}
	if _, err := registry.Revoke(record.SessionID); err != nil {
		return err
	}
	current, err := cfg.Runtime.Inspect(ctx, info.Name)
	if err != nil {
		return err
	}
	projectID, vmID, owned := ownedIdentity(current)
	if !owned || projectID != record.ProjectID || vmID != strings.TrimPrefix(record.VMID, "sunaba-"+record.ProjectID+"-") || current.Name != record.VMID {
		return fmt.Errorf("cleanup candidate identity changed before removal")
	}
	if current.State == runtime.StateRunning {
		if err := cfg.Runtime.Stop(ctx, current.Name); err != nil {
			return err
		}
	} else if current.State != runtime.StateStopped {
		return fmt.Errorf("cleanup candidate has unsupported state %s", current.State)
	}
	if err := cfg.Runtime.Remove(ctx, current.Name); err != nil {
		return err
	}
	return cfg.Audit.Append(audit.BoundaryEvent{
		Category: "cleanup", Action: "orphan.remove", Outcome: "success", ProjectID: record.ProjectID,
		VMID: record.VMID, SessionID: record.SessionID, Details: details,
	})
}
