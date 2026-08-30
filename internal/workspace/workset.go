package workspace

import (
	"fmt"
	"reflect"
	"sort"
	"strings"
	"time"
)

// SameWorkSetContent compares the immutable captured result while deliberately
// ignoring private storage roots and the digests that are rebound with those
// roots during the pending commit.
func SameWorkSetContent(left, right PendingWorkSet) bool {
	return left.Version == right.Version && left.ProjectID == right.ProjectID && left.ProjectRoot == right.ProjectRoot && left.VMID == right.VMID && left.SessionID == right.SessionID && left.WorkspacePolicyDigest == right.WorkspacePolicyDigest && left.Baseline.Core.Digest == right.Baseline.Core.Digest && left.Result.Core.Digest == right.Result.Core.Digest && left.CoreChangeSet.Digest == right.CoreChangeSet.Digest && reflect.DeepEqual(left.Bulk, right.Bulk) && reflect.DeepEqual(left.NormalRoots, right.NormalRoots) && reflect.DeepEqual(left.ReviewedBulk, right.ReviewedBulk)
}

const (
	PendingWorkSetVersion = 5
	ResolutionVersion     = 1
	ApplyPlanVersion      = 1

	DispositionUnresolved     = "unresolved"
	DispositionKeepHost       = "keep_host"
	DispositionRetainArtifact = "retain_artifact"
	DispositionApplyDirectory = "apply_directory"
	DispositionDiscard        = "discard"

	RetentionDispositionReviewedNormal = "reviewed_normal_cleanup"
)

// PendingWorkSet is the immutable identity of one frozen VM result. Bulk
// choices live in a separately revisioned Resolution so changing a choice
// invalidates an already displayed Apply Plan without rewriting this record.
type PendingWorkSet struct {
	Version               int                   `json:"version"`
	ProjectID             string                `json:"project_id"`
	ProjectRoot           string                `json:"project_root"`
	VMID                  string                `json:"vm_id"`
	SessionID             string                `json:"session_id"`
	WorkspacePolicyDigest string                `json:"workspace_policy_digest"`
	Baseline              PartitionedManifest   `json:"baseline"`
	Result                PartitionedManifest   `json:"result"`
	CoreChangeSet         ChangeSet             `json:"core_change_set"`
	Bulk                  []BulkRecord          `json:"bulk"`
	NormalRoots           []string              `json:"normal_roots"`
	ReviewedBulk          []ReviewedBulkCapture `json:"reviewed_bulk"`
	CreatedAt             time.Time             `json:"created_at"`
	Digest                string                `json:"work_set_digest"`
}

// ReviewedBulkCapture keeps the exact source object bound to a Bulk path that
// was promoted into the Normal lane. The object remains durable until the
// single Apply Plan commits, then becomes an approval-bound cleanup operation.
type ReviewedBulkCapture struct {
	BulkID  string          `json:"bulk_id"`
	Root    string          `json:"root"`
	Result  BulkManifestRef `json:"result"`
	Capture BulkCapture     `json:"capture"`
}

type BulkResolution struct {
	BulkID      string `json:"bulk_id"`
	Disposition string `json:"disposition"`
}

type Resolution struct {
	Version       int              `json:"version"`
	WorkSetDigest string           `json:"work_set_digest"`
	Revision      uint64           `json:"revision"`
	Bulk          []BulkResolution `json:"bulk"`
	Digest        string           `json:"resolution_digest"`
}

type BulkOperation struct {
	BulkID       string `json:"bulk_id"`
	Root         string `json:"root"`
	Disposition  string `json:"disposition"`
	BeforeState  string `json:"before_state"`
	BeforeDigest string `json:"before_digest,omitempty"`
	AfterState   string `json:"after_state"`
	AfterDigest  string `json:"after_digest,omitempty"`
	ObjectID     string `json:"object_id,omitempty"`
	ObjectDigest string `json:"object_digest,omitempty"`
}

type RetentionOperation struct {
	BulkID       string `json:"bulk_id"`
	Disposition  string `json:"disposition"`
	ObjectID     string `json:"object_id,omitempty"`
	ObjectDigest string `json:"object_digest,omitempty"`
	EntryCount   int    `json:"entry_count"`
	LogicalBytes int64  `json:"logical_bytes"`
}

type ApplyPlan struct {
	Version                   int                  `json:"version"`
	ProjectID                 string               `json:"project_id"`
	WorkSetDigest             string               `json:"work_set_digest"`
	ResolutionDigest          string               `json:"resolution_digest"`
	WorkspacePolicyDigest     string               `json:"workspace_policy_digest"`
	CurrentCoreBaselineDigest string               `json:"current_core_baseline_digest"`
	CoreChangeSetDigest       string               `json:"core_change_set_digest"`
	BulkOperations            []BulkOperation      `json:"bulk_operations"`
	RetentionOperations       []RetentionOperation `json:"retention_operations"`
	NoTouchRoots              []string             `json:"no_touch_roots"`
	ExpectedCoreDigest        string               `json:"expected_core_digest"`
	BulkSelectionDigest       string               `json:"bulk_selection_digest"`
	Digest                    string               `json:"digest"`
}

// BuildPendingWorkSet constructs a new schema-v5 identity. It does not make
// frozen VM data durable and consequently never makes a Work Set ready to
// apply on its own.
func BuildPendingWorkSet(projectID, projectRoot, vmID, sessionID, workspacePolicyDigest string, baseline, result SnapshotManifest, snapshotPolicy SnapshotPolicy, bulkPolicy BulkPolicy, createdAt time.Time) (PendingWorkSet, error) {
	if projectID == "" || projectRoot == "" || vmID == "" || sessionID == "" || !validSHA256(workspacePolicyDigest) || createdAt.IsZero() {
		return PendingWorkSet{}, fmt.Errorf("Work Set identity is incomplete")
	}
	if err := validateCanonicalManifest(baseline, snapshotPolicy); err != nil {
		return PendingWorkSet{}, fmt.Errorf("invalid Work Set baseline: %w", err)
	}
	if err := validateCanonicalManifest(result, snapshotPolicy); err != nil {
		return PendingWorkSet{}, fmt.Errorf("invalid Work Set result: %w", err)
	}
	partitionedBaseline, partitionedResult, records, err := PartitionManifestPair(baseline, result, bulkPolicyWithSnapshotCeilings(bulkPolicy, snapshotPolicy), workspacePolicyDigest)
	if err != nil {
		return PendingWorkSet{}, err
	}
	core, err := BuildChangeSet(partitionedBaseline.Core, partitionedResult.Core, snapshotPolicy)
	if err != nil {
		return PendingWorkSet{}, fmt.Errorf("build Core Change Set: %w", err)
	}
	workSet := PendingWorkSet{
		Version: PendingWorkSetVersion, ProjectID: projectID, ProjectRoot: projectRoot, VMID: vmID, SessionID: sessionID,
		WorkspacePolicyDigest: workspacePolicyDigest, Baseline: partitionedBaseline, Result: partitionedResult,
		CoreChangeSet: core, Bulk: records, NormalRoots: []string{}, ReviewedBulk: []ReviewedBulkCapture{}, CreatedAt: createdAt.UTC(),
	}
	if workSet.Bulk == nil {
		workSet.Bulk = []BulkRecord{}
	}
	workSet.Digest, err = pendingWorkSetDigest(workSet)
	return workSet, err
}

func BuildPendingWorkSetFromPartitions(projectID, projectRoot, vmID, sessionID, workspacePolicyDigest string, baseline, result PartitionedManifest, records []BulkRecord, snapshotPolicy SnapshotPolicy, createdAt time.Time) (PendingWorkSet, error) {
	if projectID == "" || projectRoot == "" || vmID == "" || sessionID == "" || !validSHA256(workspacePolicyDigest) || createdAt.IsZero() {
		return PendingWorkSet{}, fmt.Errorf("Work Set identity is incomplete")
	}
	if err := validatePartitionedManifest(baseline, snapshotPolicy); err != nil {
		return PendingWorkSet{}, err
	}
	if err := validatePartitionedManifest(result, snapshotPolicy); err != nil {
		return PendingWorkSet{}, err
	}
	core, err := BuildChangeSet(baseline.Core, result.Core, snapshotPolicy)
	if err != nil {
		return PendingWorkSet{}, err
	}
	workSet := PendingWorkSet{
		Version: PendingWorkSetVersion, ProjectID: projectID, ProjectRoot: projectRoot, VMID: vmID, SessionID: sessionID,
		WorkspacePolicyDigest: workspacePolicyDigest, Baseline: baseline, Result: result, CoreChangeSet: core,
		Bulk: append([]BulkRecord(nil), records...), NormalRoots: []string{}, ReviewedBulk: []ReviewedBulkCapture{}, CreatedAt: createdAt.UTC(),
	}
	if workSet.Bulk == nil {
		workSet.Bulk = []BulkRecord{}
	}
	workSet.Digest, err = pendingWorkSetDigest(workSet)
	if err != nil {
		return PendingWorkSet{}, err
	}
	if err := ValidatePendingWorkSet(workSet, snapshotPolicy); err != nil {
		return PendingWorkSet{}, err
	}
	return workSet, nil
}

func RebindPendingWorkSetRoots(workSet PendingWorkSet, baselineRoot, resultRoot string, snapshotPolicy SnapshotPolicy) (PendingWorkSet, error) {
	if err := ValidatePendingWorkSet(workSet, snapshotPolicy); err != nil {
		return PendingWorkSet{}, err
	}
	if baselineRoot == "" || resultRoot == "" {
		return PendingWorkSet{}, fmt.Errorf("Work Set roots are incomplete")
	}
	workSet.Baseline.Root, workSet.Baseline.Core.Root = baselineRoot, baselineRoot
	workSet.Result.Root, workSet.Result.Core.Root = resultRoot, resultRoot
	var err error
	workSet.Baseline.Digest, err = partitionedManifestDigest(workSet.Baseline)
	if err != nil {
		return PendingWorkSet{}, err
	}
	workSet.Result.Digest, err = partitionedManifestDigest(workSet.Result)
	if err != nil {
		return PendingWorkSet{}, err
	}
	workSet.CoreChangeSet, err = BuildChangeSet(workSet.Baseline.Core, workSet.Result.Core, snapshotPolicy)
	if err != nil {
		return PendingWorkSet{}, err
	}
	workSet.Digest, err = pendingWorkSetDigest(workSet)
	if err != nil {
		return PendingWorkSet{}, err
	}
	return workSet, ValidatePendingWorkSet(workSet, snapshotPolicy)
}

func ValidatePendingWorkSet(workSet PendingWorkSet, snapshotPolicy SnapshotPolicy) error {
	if workSet.Version != PendingWorkSetVersion || workSet.ProjectID == "" || workSet.ProjectRoot == "" || workSet.VMID == "" || workSet.SessionID == "" || workSet.CreatedAt.IsZero() || !validSHA256(workSet.WorkspacePolicyDigest) || !validSHA256(workSet.Digest) {
		return fmt.Errorf("Work Set identity is incomplete")
	}
	if workSet.Bulk == nil || workSet.NormalRoots == nil || workSet.ReviewedBulk == nil {
		return fmt.Errorf("Work Set arrays must be canonical")
	}
	if workSet.Baseline.PolicyDigest != workSet.WorkspacePolicyDigest || workSet.Result.PolicyDigest != workSet.WorkspacePolicyDigest {
		return fmt.Errorf("Work Set policy identity does not match its manifests")
	}
	if err := validatePartitionedManifest(workSet.Baseline, snapshotPolicy); err != nil {
		return fmt.Errorf("invalid partitioned baseline: %w", err)
	}
	if err := validatePartitionedManifest(workSet.Result, snapshotPolicy); err != nil {
		return fmt.Errorf("invalid partitioned result: %w", err)
	}
	rebuiltCore, err := BuildChangeSet(workSet.Baseline.Core, workSet.Result.Core, snapshotPolicy)
	if err != nil || rebuiltCore.Digest != workSet.CoreChangeSet.Digest {
		return fmt.Errorf("Work Set Core Change Set is not canonical")
	}
	if len(workSet.Bulk) != len(workSet.Baseline.BulkRoots) || len(workSet.Bulk) != len(workSet.Result.BulkRoots) || len(workSet.Bulk) > MaximumBulkRoots {
		return fmt.Errorf("Work Set Bulk records do not match its manifests")
	}
	previousRoot := ""
	seenIDs := make(map[string]struct{}, len(workSet.Bulk))
	for i, record := range workSet.Bulk {
		if record.Root == "" || record.Root <= previousRoot || record.Baseline != workSet.Baseline.BulkRoots[i] || record.Result != workSet.Result.BulkRoots[i] || record.BulkID == "" || record.Disposition != DispositionUnresolved {
			return fmt.Errorf("Work Set Bulk record %d is not canonical", i)
		}
		if _, exists := seenIDs[record.BulkID]; exists {
			return fmt.Errorf("Work Set contains a duplicate Bulk ID")
		}
		if !validBulkDiscovery(record.Discovery) || !validCapture(record.Capture) {
			return fmt.Errorf("Work Set Bulk record %q is invalid", record.BulkID)
		}
		if record.Capture.State == "exact_managed" && (record.Result.State != "exact" || record.Capture.ObjectDigest != record.Result.ObjectDigest) {
			return fmt.Errorf("Work Set exact Bulk capture does not match its result")
		}
		if record.Capture.State == "exact_absence" && record.Result.State != "absent" {
			return fmt.Errorf("Work Set absence capture does not match its result")
		}
		seenIDs[record.BulkID] = struct{}{}
		previousRoot = record.Root
	}
	previousNormal := ""
	for _, root := range workSet.NormalRoots {
		if validateBulkPath(root) != nil || root <= previousNormal {
			return fmt.Errorf("Work Set normal overrides are not canonical")
		}
		for _, record := range workSet.Bulk {
			if overlapsPath(root, record.Root) {
				return fmt.Errorf("Work Set normal override overlaps a remaining Bulk root")
			}
		}
		previousNormal = root
	}
	if len(workSet.ReviewedBulk) != len(workSet.NormalRoots) {
		return fmt.Errorf("Work Set reviewed Bulk captures do not match normal overrides")
	}
	for index, reviewed := range workSet.ReviewedBulk {
		if reviewed.Root != workSet.NormalRoots[index] || reviewed.BulkID == "" || reviewed.Result.Root != reviewed.Root || reviewed.Result.State != "exact" || reviewed.Capture.State != "exact_managed" || reviewed.Capture.ObjectID == "" || reviewed.Capture.ObjectDigest != reviewed.Result.ObjectDigest {
			return fmt.Errorf("Work Set reviewed Bulk capture %d is not canonical", index)
		}
		if _, exists := seenIDs[reviewed.BulkID]; exists {
			return fmt.Errorf("Work Set contains a duplicate reviewed Bulk ID")
		}
		seenIDs[reviewed.BulkID] = struct{}{}
	}
	digest, err := pendingWorkSetDigest(workSet)
	if err != nil || digest != workSet.Digest {
		return fmt.Errorf("Work Set digest is not canonical")
	}
	return nil
}

func BuildResolution(workSet PendingWorkSet, snapshotPolicy SnapshotPolicy, revision uint64, choices []BulkResolution) (Resolution, error) {
	if err := ValidatePendingWorkSet(workSet, snapshotPolicy); err != nil {
		return Resolution{}, err
	}
	if revision == 0 || len(choices) > len(workSet.Bulk) {
		return Resolution{}, fmt.Errorf("Resolution revision or Bulk choice count is invalid")
	}
	choices = append([]BulkResolution(nil), choices...)
	sort.Slice(choices, func(i, j int) bool { return choices[i].BulkID < choices[j].BulkID })
	byID := make(map[string]BulkRecord, len(workSet.Bulk))
	for _, record := range workSet.Bulk {
		byID[record.BulkID] = record
	}
	decided := make(map[string]string, len(choices))
	for i, choice := range choices {
		if i > 0 && choices[i-1].BulkID >= choice.BulkID {
			return Resolution{}, fmt.Errorf("Resolution contains duplicate Bulk IDs")
		}
		record, exists := byID[choice.BulkID]
		if !exists || !allowedResolutionDisposition(record, choice.Disposition) {
			return Resolution{}, fmt.Errorf("Bulk disposition is not allowed for %q", choice.BulkID)
		}
		decided[choice.BulkID] = choice.Disposition
	}
	canonical := make([]BulkResolution, 0, len(workSet.Bulk))
	for _, record := range workSet.Bulk {
		disposition := decided[record.BulkID]
		if disposition == "" {
			disposition = DispositionUnresolved
		}
		canonical = append(canonical, BulkResolution{BulkID: record.BulkID, Disposition: disposition})
	}
	sort.Slice(canonical, func(i, j int) bool { return canonical[i].BulkID < canonical[j].BulkID })
	resolution := Resolution{Version: ResolutionVersion, WorkSetDigest: workSet.Digest, Revision: revision, Bulk: canonical}
	var err error
	resolution.Digest, err = resolutionDigest(resolution)
	return resolution, err
}

func ValidateResolution(workSet PendingWorkSet, resolution Resolution) error {
	if resolution.Version != ResolutionVersion || resolution.WorkSetDigest != workSet.Digest || resolution.Revision == 0 || !validSHA256(resolution.Digest) || len(resolution.Bulk) != len(workSet.Bulk) {
		return fmt.Errorf("Resolution identity does not match the Work Set")
	}
	byID := make(map[string]BulkRecord, len(workSet.Bulk))
	for _, record := range workSet.Bulk {
		byID[record.BulkID] = record
	}
	for i, choice := range resolution.Bulk {
		if i > 0 && resolution.Bulk[i-1].BulkID >= choice.BulkID {
			return fmt.Errorf("Resolution is not in canonical Bulk ID order")
		}
		if record, exists := byID[choice.BulkID]; !exists || !allowedResolutionDisposition(record, choice.Disposition) {
			return fmt.Errorf("Resolution contains an invalid Bulk disposition")
		}
	}
	digest, err := resolutionDigest(resolution)
	if err != nil || digest != resolution.Digest {
		return fmt.Errorf("Resolution digest is not canonical")
	}
	return nil
}

// BuildApplyPlan is fail-closed: retained data must already be durable, an
// applied directory must have exact capture and a safe before guard, and an
// exact loss inventory is required before discard can enter the plan.
func BuildApplyPlan(workSet PendingWorkSet, resolution Resolution, snapshotPolicy SnapshotPolicy, currentCoreBaselineDigest string) (ApplyPlan, error) {
	if err := ValidatePendingWorkSet(workSet, snapshotPolicy); err != nil {
		return ApplyPlan{}, err
	}
	if err := ValidateResolution(workSet, resolution); err != nil {
		return ApplyPlan{}, err
	}
	if currentCoreBaselineDigest != workSet.Baseline.Core.Digest {
		return ApplyPlan{}, fmt.Errorf("current Core baseline does not match the Work Set")
	}
	byID := make(map[string]BulkRecord, len(workSet.Bulk))
	for _, record := range workSet.Bulk {
		byID[record.BulkID] = record
	}
	operations := make([]BulkOperation, 0, len(resolution.Bulk))
	retention := make([]RetentionOperation, 0, len(resolution.Bulk))
	noTouch := make([]string, 0, len(resolution.Bulk))
	for _, choice := range resolution.Bulk {
		record := byID[choice.BulkID]
		operation := BulkOperation{
			BulkID: record.BulkID, Root: record.Root, Disposition: choice.Disposition,
			BeforeState: record.Baseline.State, BeforeDigest: record.Baseline.MerkleDigest,
			AfterState: record.Result.State, AfterDigest: record.Result.MerkleDigest,
			ObjectID: record.Capture.ObjectID, ObjectDigest: record.Capture.ObjectDigest,
		}
		switch choice.Disposition {
		case DispositionApplyDirectory:
			exactResult := (record.Result.State == "exact" && record.Capture.State == "exact_managed" && record.Capture.ObjectID != "") || (record.Result.State == "absent" && record.Capture.State == "exact_absence" && record.Capture.ObjectID == "")
			if !exactResult || !validSHA256(record.Capture.ObjectDigest) || (record.Baseline.State != "absent" && record.Baseline.State != "exact") {
				return ApplyPlan{}, fmt.Errorf("Bulk path %q is not eligible for entire-directory apply", record.Root)
			}
		case DispositionKeepHost, DispositionRetainArtifact:
			if !durableCapture(record.Capture) {
				return ApplyPlan{}, fmt.Errorf("Bulk path %q is not durably retained", record.Root)
			}
			noTouch = append(noTouch, record.Root)
		case DispositionDiscard:
			if record.Capture.State != "exact_managed" || record.Result.State != "exact" || !validSHA256(record.Capture.ObjectDigest) {
				return ApplyPlan{}, fmt.Errorf("Bulk path %q lacks an exact discard inventory", record.Root)
			}
			noTouch = append(noTouch, record.Root)
		default:
			return ApplyPlan{}, fmt.Errorf("Bulk path %q is unresolved", record.Root)
		}
		operations = append(operations, operation)
		retention = append(retention, RetentionOperation{
			BulkID: record.BulkID, Disposition: choice.Disposition, ObjectID: record.Capture.ObjectID,
			ObjectDigest: record.Capture.ObjectDigest,
			EntryCount:   record.Summary.Files + record.Summary.Directories + record.Summary.Symlinks,
			LogicalBytes: record.Summary.LogicalBytes,
		})
	}
	for _, reviewed := range workSet.ReviewedBulk {
		retention = append(retention, RetentionOperation{
			BulkID: reviewed.BulkID, Disposition: RetentionDispositionReviewedNormal,
			ObjectID: reviewed.Capture.ObjectID, ObjectDigest: reviewed.Capture.ObjectDigest,
			EntryCount:   reviewed.Result.Summary.Files + reviewed.Result.Summary.Directories + reviewed.Result.Summary.Symlinks,
			LogicalBytes: reviewed.Result.Summary.LogicalBytes,
		})
	}
	sort.Strings(noTouch)
	if err := validatePlanPathSeparation(workSet, noTouch); err != nil {
		return ApplyPlan{}, err
	}
	selectionDigest, err := canonicalJSONDigest("sunaba.bulk-selection.v1\x00", operations)
	if err != nil {
		return ApplyPlan{}, err
	}
	plan := ApplyPlan{
		Version: ApplyPlanVersion, ProjectID: workSet.ProjectID, WorkSetDigest: workSet.Digest,
		ResolutionDigest: resolution.Digest, WorkspacePolicyDigest: workSet.WorkspacePolicyDigest,
		CurrentCoreBaselineDigest: currentCoreBaselineDigest, CoreChangeSetDigest: workSet.CoreChangeSet.Digest,
		BulkOperations: operations, RetentionOperations: retention, NoTouchRoots: noTouch,
		ExpectedCoreDigest: workSet.Result.Core.Digest, BulkSelectionDigest: selectionDigest,
	}
	plan.Digest, err = applyPlanDigest(plan)
	return plan, err
}

func ValidateApplyPlan(workSet PendingWorkSet, resolution Resolution, snapshotPolicy SnapshotPolicy, plan ApplyPlan) error {
	rebuilt, err := BuildApplyPlan(workSet, resolution, snapshotPolicy, plan.CurrentCoreBaselineDigest)
	if err != nil || rebuilt.Digest != plan.Digest || rebuilt.BulkSelectionDigest != plan.BulkSelectionDigest {
		return fmt.Errorf("Apply Plan is stale or non-canonical")
	}
	return nil
}

func validatePartitionedManifest(manifest PartitionedManifest, policy SnapshotPolicy) error {
	if manifest.Version != BulkFormatVersion || manifest.Root == "" || !validSHA256(manifest.PolicyDigest) || !validSHA256(manifest.Digest) || manifest.Core.Root != manifest.Root {
		return fmt.Errorf("partitioned manifest identity is incomplete")
	}
	if err := validateCanonicalManifest(manifest.Core, policy); err != nil {
		return err
	}
	previous := ""
	for _, ref := range manifest.BulkRoots {
		if ref.Root <= previous || (ref.State != "absent" && ref.State != "exact" && ref.State != "present_untracked" && ref.State != "unsupported") {
			return fmt.Errorf("Bulk manifest references are not canonical")
		}
		if ref.State == "exact" && (!validSHA256(ref.ManifestDigest) || !validSHA256(ref.MerkleDigest) || !validSHA256(ref.ObjectDigest)) {
			return fmt.Errorf("exact Bulk manifest reference is incomplete")
		}
		if ref.State != "exact" && (ref.ManifestDigest != "" || ref.MerkleDigest != "" || ref.ObjectDigest != "") {
			return fmt.Errorf("non-exact Bulk manifest reference contains exact identity")
		}
		previous = ref.Root
	}
	digest, err := partitionedManifestDigest(manifest)
	if err != nil || digest != manifest.Digest {
		return fmt.Errorf("partitioned manifest digest is not canonical")
	}
	return nil
}

func validBulkDiscovery(discovery BulkDiscovery) bool {
	switch discovery.Reason {
	case "builtin-component-rule", "user-literal-rule", "user-component-rule", "structural-entry-overflow", "structural-byte-overflow", "core-admission-overflow":
		return true
	default:
		return false
	}
}

func validCapture(capture BulkCapture) bool {
	switch capture.State {
	case "frozen_vm", "capture_failed":
		return capture.ObjectID == "" && capture.ObjectDigest == ""
	case "exact_managed", "opaque_recovery_artifact":
		return capture.ObjectID != "" && validSHA256(capture.ObjectDigest)
	case "exact_absence":
		return capture.ObjectID == "" && validSHA256(capture.ObjectDigest)
	default:
		return false
	}
}

func durableCapture(capture BulkCapture) bool {
	return ((capture.State == "exact_managed" || capture.State == "opaque_recovery_artifact") && capture.ObjectID != "" && validSHA256(capture.ObjectDigest)) || (capture.State == "exact_absence" && capture.ObjectID == "" && validSHA256(capture.ObjectDigest))
}

func allowedDisposition(record BulkRecord, disposition string) bool {
	switch disposition {
	case DispositionKeepHost:
		return true
	case DispositionRetainArtifact:
		return record.Capture.State == "exact_managed" || record.Capture.State == "opaque_recovery_artifact"
	case DispositionApplyDirectory:
		exactResult := (record.Result.State == "exact" && record.Capture.State == "exact_managed") || (record.Result.State == "absent" && record.Capture.State == "exact_absence")
		return exactResult && (record.Baseline.State == "absent" || record.Baseline.State == "exact")
	case DispositionDiscard:
		return record.Capture.State == "exact_managed" && record.Result.State == "exact"
	default:
		return false
	}
}

func allowedResolutionDisposition(record BulkRecord, disposition string) bool {
	return disposition == DispositionUnresolved || allowedDisposition(record, disposition)
}

func AllowedBulkDispositions(record BulkRecord, directoryApplyEnabled ...bool) []string {
	result := []string{DispositionKeepHost}
	if allowedDisposition(record, DispositionRetainArtifact) {
		result = append(result, DispositionRetainArtifact)
	}
	if len(directoryApplyEnabled) > 0 && directoryApplyEnabled[0] && allowedDisposition(record, DispositionApplyDirectory) {
		result = append(result, DispositionApplyDirectory)
	}
	for _, disposition := range []string{DispositionDiscard} {
		if allowedDisposition(record, disposition) {
			result = append(result, disposition)
		}
	}
	return result
}

func BulkIdentity(record BulkRecord) string {
	if record.Capture.ObjectDigest != "" {
		return record.Capture.ObjectDigest
	}
	return record.Result.ObjectDigest
}

func CanReviewBulkNormally(record BulkRecord) bool {
	return record.Baseline.State == "absent" && record.Result.State == "exact" && record.Capture.State == "exact_managed" && record.Capture.ObjectID != ""
}

func EffectiveWorkSetBulkPolicy(base BulkPolicy, workSet PendingWorkSet) (BulkPolicy, error) {
	base.NormalRoots = append(append([]string(nil), base.NormalRoots...), workSet.NormalRoots...)
	sort.Strings(base.NormalRoots)
	if len(base.NormalRoots) > 0 {
		compacted := base.NormalRoots[:1]
		for _, root := range base.NormalRoots[1:] {
			if root != compacted[len(compacted)-1] {
				compacted = append(compacted, root)
			}
		}
		base.NormalRoots = compacted
	}
	return CanonicalBulkPolicy(base)
}

// DeriveWorkSetReviewNormally moves one exact, baseline-absent Bulk root into
// the Core lane after the caller materialized it in a new private result root.
func DeriveWorkSetReviewNormally(workSet PendingWorkSet, bulkID string, fullResult SnapshotManifest, snapshotPolicy SnapshotPolicy) (PendingWorkSet, error) {
	if err := ValidatePendingWorkSet(workSet, snapshotPolicy); err != nil {
		return PendingWorkSet{}, err
	}
	index := -1
	for candidate := range workSet.Bulk {
		if workSet.Bulk[candidate].BulkID == bulkID {
			index = candidate
			break
		}
	}
	if index < 0 || !CanReviewBulkNormally(workSet.Bulk[index]) {
		return PendingWorkSet{}, fmt.Errorf("Bulk path cannot be reviewed normally from its captured baseline")
	}
	record := workSet.Bulk[index]
	if err := validateCanonicalManifest(fullResult, snapshotPolicy); err != nil {
		return PendingWorkSet{}, fmt.Errorf("derived Normal result exceeds its hard limit: %w", err)
	}
	ref, err := ExactBulkRefFromManifest(fullResult, record.Root)
	if err != nil || ref.MerkleDigest != record.Result.MerkleDigest || ref.ObjectDigest != record.Result.ObjectDigest {
		return PendingWorkSet{}, fmt.Errorf("derived Normal result does not contain the exact Bulk object")
	}
	workSet.Result.Root, workSet.Result.Core = fullResult.Root, fullResult
	workSet.Baseline.BulkRoots = append(workSet.Baseline.BulkRoots[:index:index], workSet.Baseline.BulkRoots[index+1:]...)
	workSet.Result.BulkRoots = append(workSet.Result.BulkRoots[:index:index], workSet.Result.BulkRoots[index+1:]...)
	workSet.Bulk = append(workSet.Bulk[:index:index], workSet.Bulk[index+1:]...)
	workSet.ReviewedBulk = append(workSet.ReviewedBulk, ReviewedBulkCapture{
		BulkID: record.BulkID, Root: record.Root, Result: record.Result, Capture: record.Capture,
	})
	sort.Slice(workSet.ReviewedBulk, func(i, j int) bool { return workSet.ReviewedBulk[i].Root < workSet.ReviewedBulk[j].Root })
	workSet.NormalRoots = workSet.NormalRoots[:0]
	for _, reviewed := range workSet.ReviewedBulk {
		workSet.NormalRoots = append(workSet.NormalRoots, reviewed.Root)
	}
	workSet.Baseline.Digest, err = partitionedManifestDigest(workSet.Baseline)
	if err != nil {
		return PendingWorkSet{}, err
	}
	workSet.Result.Digest, err = partitionedManifestDigest(workSet.Result)
	if err != nil {
		return PendingWorkSet{}, err
	}
	workSet.CoreChangeSet, err = BuildChangeSet(workSet.Baseline.Core, workSet.Result.Core, snapshotPolicy)
	if err != nil {
		return PendingWorkSet{}, err
	}
	workSet.Digest, err = pendingWorkSetDigest(workSet)
	if err != nil {
		return PendingWorkSet{}, err
	}
	return workSet, ValidatePendingWorkSet(workSet, snapshotPolicy)
}

func validatePlanPathSeparation(workSet PendingWorkSet, noTouch []string) error {
	allBulk := make([]string, 0, len(workSet.Bulk))
	for _, record := range workSet.Bulk {
		allBulk = append(allBulk, record.Root)
	}
	for _, change := range workSet.CoreChangeSet.Changes {
		paths := []string{change.Path}
		if change.From != "" {
			paths = append(paths, change.From)
		}
		for _, changedPath := range paths {
			for _, root := range allBulk {
				if overlapsPath(changedPath, root) {
					return fmt.Errorf("Core change %q overlaps Bulk root %q", changedPath, root)
				}
			}
		}
	}
	return nil
}

func overlapsPath(left, right string) bool {
	return left == right || strings.HasPrefix(left, right+"/") || strings.HasPrefix(right, left+"/")
}

func pendingWorkSetDigest(workSet PendingWorkSet) (string, error) {
	workSet.Digest = ""
	return canonicalJSONDigest("sunaba.pending-work-set.v5\x00", workSet)
}

func resolutionDigest(resolution Resolution) (string, error) {
	resolution.Digest = ""
	return canonicalJSONDigest("sunaba.bulk-resolution.v1\x00", resolution)
}

func applyPlanDigest(plan ApplyPlan) (string, error) {
	plan.Digest = ""
	return canonicalJSONDigest("sunaba.apply-plan.v1\x00", plan)
}
