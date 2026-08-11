package cleanup

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"

	"sunaba/internal/audit"
	"sunaba/internal/lease"
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
		projectID, sessionID, owned := ownedIdentity(info)
		if !owned {
			result.Refused = append(result.Refused, listed.Name)
			continue
		}
		record, err := registry.Load(sessionID)
		if err != nil || record.ProjectID != projectID || record.VMID != info.Name || record.SessionID != sessionID || record.Use != "model" {
			result.Refused = append(result.Refused, info.Name)
			continue
		}
		guard, err := registry.AcquireGuard(sessionID)
		if errors.Is(err, lease.ErrGuardHeld) {
			result.Kept = append(result.Kept, info.Name)
			continue
		}
		if err != nil {
			return result, fmt.Errorf("acquire cleanup guard for %s: %w", info.Name, err)
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

func ownedIdentity(info runtime.Info) (projectID, sessionID string, ok bool) {
	projectID = info.Labels["dev.sunaba.project"]
	sessionID = info.Labels["dev.sunaba.session"]
	mode := info.Labels["dev.sunaba.mode"]
	if info.Labels["dev.sunaba.owner"] != "sunaba-supervisor" || (mode != "secure" && mode != "dev") || projectID == "" || sessionID == "" {
		return "", "", false
	}
	if info.Name != "sunaba-"+projectID+"-"+sessionID {
		return "", "", false
	}
	return projectID, sessionID, true
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
	projectID, sessionID, owned := ownedIdentity(current)
	if !owned || projectID != record.ProjectID || sessionID != record.SessionID {
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
