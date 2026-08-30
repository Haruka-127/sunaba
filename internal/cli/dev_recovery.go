package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"sunaba/internal/audit"
	"sunaba/internal/devnetwork"
	"sunaba/internal/policy"
	"sunaba/internal/recovery"
	"sunaba/internal/runtime"
	"sunaba/internal/session"
	"sunaba/internal/workspace"
)

func (a *app) exportDevRecovery(ctx context.Context, projectPolicy policy.ProjectPolicy, projectState string, discardExternalGit bool) error {
	record, err := recovery.Load(projectState)
	if err != nil {
		return err
	}
	if err := removeRecoverySupervisorLocator(projectState); err != nil {
		return err
	}
	if record.ProjectID != projectPolicy.ProjectID || record.ProjectRoot != projectPolicy.ProjectRoot {
		return fmt.Errorf("dev recovery record does not match Project policy")
	}
	compiled, err := policy.CompileWorkspacePolicy(projectPolicy.Export, projectPolicy.ProtectedPaths, projectPolicy.Snapshot.Exclude, projectPolicy.Bulk)
	if err != nil {
		return err
	}
	if compiled.Digest != record.WorkspacePolicy.Digest || compiled.Core.Digest != record.ExportPolicyDigest {
		return fmt.Errorf("dev recovery workspace policy no longer matches Project policy")
	}
	recorder, err := audit.NewRecorder(filepath.Join(a.store.Root, "audit"))
	if err != nil {
		return err
	}
	if record.PendingExport != nil {
		return a.persistFrozenRecovery(ctx, projectState, record, compiled, recorder)
	}
	boundary, err := devnetwork.ActivateQuiesced(ctx, a.store.Root, record.ProjectID, record.VMID)
	if err != nil {
		return fmt.Errorf("create deny-all network for stopped dev recovery export: %w", err)
	}
	boundaryOwned := true
	defer func() {
		if boundaryOwned {
			_ = boundary.Close(context.Background())
		}
	}()
	active, err := session.AdoptRecovery(ctx, session.RecoveryConfig{
		Store: a.store, Runtime: a.runtime, Record: record, Audit: recorder,
		SnapshotPolicy: compiled.Core.Snapshot, ExportPolicy: compiled.Core.Export, ExportPolicyDigest: compiled.Core.Digest, WorkspacePolicy: compiled,
		DevNetworkName: boundary.Network.Name, DevNetworkQuiesce: boundary.Quiesce, DevNetworkClose: boundary.Close,
		DiscardExternalGit: discardExternalGit, GitGateway: record.GitGateway, WebGateway: record.WebGateway,
	})
	if err != nil {
		return err
	}
	boundaryOwned = false
	result, exportErr := active.StopAndExport(ctx)
	if exportErr != nil {
		return errors.Join(exportErr, active.RetainForRecovery(ctx))
	}
	if len(result.ChangeSet.Changes) > 0 || len(result.WorkSet.Bulk) > 0 {
		if _, err := persistPending(projectState, active, result); err != nil {
			return errors.Join(err, active.RetainForRecovery(ctx))
		}
	}
	if err := active.Destroy(ctx); err != nil {
		return err
	}
	if err := recovery.Remove(projectState, record); err != nil {
		return err
	}
	return nil
}

func (a *app) persistFrozenRecovery(ctx context.Context, projectState string, record recovery.State, compiled policy.CompiledWorkspacePolicy, recorder *audit.Recorder) error {
	pendingCommitted := false
	pendingPath := filepath.Join(projectState, "pending", "change.json")
	if _, statErr := os.Lstat(pendingPath); statErr == nil {
		existing, loadErr := loadPending(projectState, policy.ProjectPolicy{ProjectID: record.ProjectID, ProjectRoot: record.ProjectRoot})
		if loadErr != nil {
			return loadErr
		}
		if existing.Version != pendingChangeVersion || !workspace.SameWorkSetContent(existing.WorkSet, record.PendingExport.WorkSet) {
			return fmt.Errorf("existing pending Change Set does not match frozen export recovery")
		}
		pendingCommitted = true
		containerState, stateErr := a.runtime.ContainerState(ctx, record.Container)
		if stateErr != nil {
			return stateErr
		}
		if containerState == runtime.StateNotFound {
			return recovery.Remove(projectState, record)
		}
		if containerState != runtime.StateStopped {
			return fmt.Errorf("frozen export recovery VM has unexpected state %s", containerState)
		}
	} else if !errors.Is(statErr, os.ErrNotExist) {
		return statErr
	}
	var boundary *devnetwork.Boundary
	var err error
	if record.RuntimeMode() == "dev" {
		boundary, err = devnetwork.RecoverQuiesced(ctx, a.store.Root, record.ProjectID, record.VMID)
		if err != nil {
			return fmt.Errorf("recover deny-all network for frozen export: %w", err)
		}
		defer boundary.Close(context.Background())
	}
	var devNetworkName string
	var devNetworkClose func(context.Context) error
	if boundary != nil {
		devNetworkName, devNetworkClose = boundary.Network.Name, boundary.Close
	}
	active, err := session.AdoptRecovery(ctx, session.RecoveryConfig{
		Store: a.store, Runtime: a.runtime, Record: record, Audit: recorder,
		SnapshotPolicy: compiled.Core.Snapshot, ExportPolicy: compiled.Core.Export, ExportPolicyDigest: compiled.Core.Digest, WorkspacePolicy: compiled,
		DevNetworkName: devNetworkName, DevNetworkClose: devNetworkClose,
		GitGateway: record.GitGateway, WebGateway: record.WebGateway,
	})
	if err != nil {
		return err
	}
	result := session.ExportResult{
		MergedRoot: record.PendingExport.MergedRoot,
		Merged:     record.PendingExport.WorkSet.Result.Core,
		ChangeSet:  record.PendingExport.WorkSet.CoreChangeSet,
		WorkSet:    record.PendingExport.WorkSet,
	}
	if !pendingCommitted {
		if _, err := persistPending(projectState, active, result); err != nil {
			return errors.Join(err, active.DetachForRecovery(ctx))
		}
	}
	if destroyErr := active.Destroy(ctx); destroyErr != nil {
		state, stateErr := a.runtime.ContainerState(ctx, record.Container)
		if stateErr != nil || state != runtime.StateNotFound {
			return errors.Join(destroyErr, stateErr)
		}
		return errors.Join(destroyErr, recovery.Remove(projectState, record))
	}
	return recovery.Remove(projectState, record)
}

func (a *app) discardDevRecovery(ctx context.Context, projectID, projectState string) error {
	record, err := recovery.Load(projectState)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if record.ProjectID != projectID {
		return fmt.Errorf("dev recovery record does not match Project policy")
	}
	info, err := a.runtime.Inspect(ctx, record.Container)
	if err != nil {
		return err
	}
	if info.Name != record.Container || info.State != "stopped" || info.Labels["dev.sunaba.owner"] != "sunaba-supervisor" || info.Labels["dev.sunaba.project"] != record.ProjectID || info.Labels["dev.sunaba.vm"] != record.VMID || info.Labels["dev.sunaba.mode"] != record.RuntimeMode() {
		return fmt.Errorf("refusing to discard a VM whose runtime ownership does not match recovery metadata")
	}
	recorder, err := audit.NewRecorder(filepath.Join(a.store.Root, "audit"))
	if err != nil {
		return err
	}
	event := audit.BoundaryEvent{Category: "recovery", Action: "dev_recovery.discard", Outcome: "started", ProjectID: record.ProjectID, VMID: record.Container, SessionID: record.SessionID}
	if err := recorder.Append(event); err != nil {
		return err
	}
	if err := a.runtime.Remove(ctx, record.Container); err != nil {
		return err
	}
	if err := recovery.Remove(projectState, record); err != nil {
		return err
	}
	event.Outcome = "success"
	return recorder.Append(event)
}
