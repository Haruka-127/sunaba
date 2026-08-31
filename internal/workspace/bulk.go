package workspace

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"path"
	"sort"
	"strings"
)

const (
	BulkFormatVersion             = 1
	BulkDefaultsVersion           = 1
	BulkComponentMatchingVersion  = 1
	BulkPartitionAlgorithmVersion = 1
	BulkMetadataProfile           = "mode-permissions;uid-gid-times-omitted;hardlinks-flattened;xattrs-acls-special-rejected"

	MaximumBulkRules                  = 4096
	MaximumBulkRoots                  = 1024
	MaximumBulkEntriesPerRoot         = 250_000
	MaximumBulkEntriesPerWorkSet      = 500_000
	MaximumBulkLogicalBytesPerRoot    = int64(4 << 30)
	MaximumBulkLogicalBytesPerWorkSet = int64(8 << 30)
	MaximumBulkManifestBytes          = 64 << 20
	MaximumBulkDirectChildren         = 100_000
	MaximumBulkChildNameBytes         = 16 << 20
)

type BulkSelector struct {
	Kind  string `json:"kind"`
	Value string `json:"value"`
}

type BulkRule struct {
	ID       string       `json:"id"`
	Selector BulkSelector `json:"selector"`
	Review   string       `json:"review"`
	VMInput  string       `json:"vm_input"`
	Hint     string       `json:"hint"`
}

// BulkPolicy classifies review lanes. It never decides whether captured data
// is disposable or may be installed into the host Project.
type BulkPolicy struct {
	DefaultsVersion           int        `json:"defaults_version"`
	Rules                     []BulkRule `json:"rules"`
	NormalRoots               []string   `json:"normal_roots"`
	ComponentMatchingVersion  int        `json:"component_matching_version"`
	PartitionAlgorithmVersion int        `json:"partition_algorithm_version"`
	MetadataProfile           string     `json:"metadata_profile"`
	CoreSoftEntries           int        `json:"core_soft_entries"`
	CoreSoftBytes             int64      `json:"core_soft_bytes"`
	CoreHardEntries           int        `json:"core_hard_entries"`
	CoreHardBytes             int64      `json:"core_hard_bytes"`
}

func DisabledBulkPolicy() BulkPolicy {
	return BulkPolicy{Rules: []BulkRule{}, NormalRoots: []string{}}
}

func DefaultBulkPolicyV1() BulkPolicy {
	return BulkPolicy{
		DefaultsVersion: BulkDefaultsVersion,
		Rules: []BulkRule{{
			ID: "builtin.node-modules", Selector: BulkSelector{Kind: "component", Value: "node_modules"},
			Review: "summary", VMInput: "omit", Hint: "dependency-tree",
		}},
		NormalRoots: []string{}, ComponentMatchingVersion: BulkComponentMatchingVersion,
		PartitionAlgorithmVersion: BulkPartitionAlgorithmVersion, MetadataProfile: BulkMetadataProfile,
		CoreSoftEntries: 10_000, CoreSoftBytes: 256 << 20,
		CoreHardEntries: 100_000, CoreHardBytes: 2 << 30,
	}
}

func ValidateBulkPolicy(policy BulkPolicy) error {
	if policy.DefaultsVersion == 0 {
		if len(policy.Rules) != 0 || len(policy.NormalRoots) != 0 || policy.ComponentMatchingVersion != 0 || policy.PartitionAlgorithmVersion != 0 || policy.MetadataProfile != "" || policy.CoreSoftEntries != 0 || policy.CoreSoftBytes != 0 || policy.CoreHardEntries != 0 || policy.CoreHardBytes != 0 {
			return fmt.Errorf("disabled bulk policy must not retain active rules or limits")
		}
		return nil
	}
	if policy.DefaultsVersion != BulkDefaultsVersion || policy.ComponentMatchingVersion != BulkComponentMatchingVersion || policy.PartitionAlgorithmVersion != BulkPartitionAlgorithmVersion || policy.MetadataProfile != BulkMetadataProfile {
		return fmt.Errorf("bulk policy version or metadata profile is invalid")
	}
	if len(policy.Rules) == 0 || len(policy.Rules) > MaximumBulkRules || len(policy.NormalRoots) > MaximumBulkRules || policy.CoreSoftEntries <= 0 || policy.CoreHardEntries < policy.CoreSoftEntries || policy.CoreHardEntries > MaximumBulkEntriesPerWorkSet || policy.CoreSoftBytes <= 0 || policy.CoreHardBytes < policy.CoreSoftBytes || policy.CoreHardBytes > MaximumBulkLogicalBytesPerWorkSet {
		return fmt.Errorf("bulk policy bounds are invalid")
	}
	seenIDs := make(map[string]struct{}, len(policy.Rules))
	seenSelectors := make(map[string]struct{}, len(policy.Rules))
	previousRule := ""
	for _, rule := range policy.Rules {
		if !validBulkToken(rule.ID, 128) || rule.Review != "summary" || rule.VMInput != "omit" || !validBulkToken(rule.Hint, 64) {
			return fmt.Errorf("bulk rule %q is invalid", rule.ID)
		}
		selectorKey, err := validateBulkSelector(rule.Selector)
		if err != nil {
			return fmt.Errorf("bulk rule %q: %w", rule.ID, err)
		}
		if previousRule != "" && previousRule >= rule.ID {
			return fmt.Errorf("bulk rules are not in canonical ID order")
		}
		previousRule = rule.ID
		if _, exists := seenIDs[rule.ID]; exists {
			return fmt.Errorf("duplicate bulk rule ID %q", rule.ID)
		}
		if _, exists := seenSelectors[selectorKey]; exists {
			return fmt.Errorf("duplicate bulk selector %q", selectorKey)
		}
		seenIDs[rule.ID], seenSelectors[selectorKey] = struct{}{}, struct{}{}
	}
	previousRoot := ""
	for _, root := range policy.NormalRoots {
		if err := validateBulkPath(root); err != nil {
			return fmt.Errorf("invalid normal root %q: %w", root, err)
		}
		if previousRoot != "" && previousRoot >= root {
			return fmt.Errorf("normal roots are not in canonical path order")
		}
		previousRoot = root
	}
	return nil
}

func CanonicalBulkPolicy(policy BulkPolicy) (BulkPolicy, error) {
	policy.Rules = append([]BulkRule(nil), policy.Rules...)
	policy.NormalRoots = append([]string(nil), policy.NormalRoots...)
	sort.Slice(policy.Rules, func(i, j int) bool { return policy.Rules[i].ID < policy.Rules[j].ID })
	sort.Strings(policy.NormalRoots)
	if len(policy.Rules) == 0 {
		policy.Rules = []BulkRule{}
	}
	if len(policy.NormalRoots) == 0 {
		policy.NormalRoots = []string{}
	}
	if err := ValidateBulkPolicy(policy); err != nil {
		return BulkPolicy{}, err
	}
	return policy, nil
}

func validBulkToken(value string, maximum int) bool {
	if value == "" || len(value) > maximum || strings.ContainsAny(value, "\x00\r\n/\\") {
		return false
	}
	for _, r := range value {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}

func validateBulkSelector(selector BulkSelector) (string, error) {
	switch selector.Kind {
	case "literal":
		if err := validateBulkPath(selector.Value); err != nil {
			return "", err
		}
	case "component":
		if !validBulkToken(selector.Value, 255) || selector.Value == "." || selector.Value == ".." {
			return "", fmt.Errorf("component selector is invalid")
		}
	default:
		return "", fmt.Errorf("selector kind is invalid")
	}
	return selector.Kind + "\x00" + selector.Value, nil
}

func validateBulkPath(value string) error {
	if value == "" || value == "." || path.IsAbs(value) || path.Clean(value) != value || value == ".." || strings.HasPrefix(value, "../") || len(value) > 4096 || strings.ContainsAny(value, "\\\x00") {
		return fmt.Errorf("path must be a root-relative canonical literal")
	}
	for _, component := range strings.Split(value, "/") {
		if !validBulkToken(component, 255) || component == "." || component == ".." {
			return fmt.Errorf("path component is invalid")
		}
	}
	return nil
}

type BulkSummary struct {
	Files              int   `json:"files"`
	Directories        int   `json:"directories"`
	Symlinks           int   `json:"symlinks"`
	LogicalBytes       int64 `json:"logical_bytes"`
	Executables        int   `json:"executables"`
	HardlinksFlattened int   `json:"hardlinks_flattened"`
	Added              int   `json:"added"`
	Modified           int   `json:"modified"`
	Deleted            int   `json:"deleted"`
}

type BulkManifestRef struct {
	Root           string      `json:"root"`
	State          string      `json:"state"`
	ManifestDigest string      `json:"manifest_digest,omitempty"`
	MerkleDigest   string      `json:"merkle_digest,omitempty"`
	ObjectDigest   string      `json:"object_digest,omitempty"`
	Summary        BulkSummary `json:"summary"`
}

type PartitionedManifest struct {
	Version      int               `json:"version"`
	Root         string            `json:"root"`
	Core         SnapshotManifest  `json:"core"`
	BulkRoots    []BulkManifestRef `json:"bulk_roots"`
	PolicyDigest string            `json:"policy_digest"`
	Digest       string            `json:"digest"`
}

type BulkDiscovery struct {
	Reason string `json:"reason"`
	RuleID string `json:"rule_id,omitempty"`
	Hint   string `json:"hint,omitempty"`
}

type BulkCapture struct {
	State        string `json:"state"`
	ObjectID     string `json:"object_id,omitempty"`
	ObjectDigest string `json:"object_digest,omitempty"`
}

type BulkRecord struct {
	BulkID      string          `json:"bulk_id"`
	Root        string          `json:"root"`
	Discovery   BulkDiscovery   `json:"discovery"`
	Baseline    BulkManifestRef `json:"baseline"`
	Result      BulkManifestRef `json:"result"`
	Capture     BulkCapture     `json:"capture"`
	Summary     BulkSummary     `json:"summary"`
	Disposition string          `json:"disposition"`
}

type bulkCandidate struct {
	root      string
	discovery BulkDiscovery
}

// PartitionManifestPair produces a shared Core/Bulk partition for a trusted
// baseline/result manifest pair. It is read-only and does not capture bytes.
func PartitionManifestPair(baseline, result SnapshotManifest, policy BulkPolicy, policyDigest string) (PartitionedManifest, PartitionedManifest, []BulkRecord, error) {
	if err := ValidateBulkPolicy(policy); err != nil {
		return PartitionedManifest{}, PartitionedManifest{}, nil, err
	}
	if baseline.Root == "" || result.Root == "" || !validSHA256(policyDigest) {
		return PartitionedManifest{}, PartitionedManifest{}, nil, fmt.Errorf("partition identity is invalid")
	}
	if policy.DefaultsVersion == 0 {
		left, err := makePartitionedManifest(baseline, nil, nil, policyDigest)
		if err != nil {
			return PartitionedManifest{}, PartitionedManifest{}, nil, err
		}
		right, err := makePartitionedManifest(result, nil, nil, policyDigest)
		return left, right, []BulkRecord{}, err
	}
	candidates, err := classifyBulkRoots(baseline, result, policy)
	if err != nil {
		return PartitionedManifest{}, PartitionedManifest{}, nil, err
	}
	roots := make([]string, len(candidates))
	for i := range candidates {
		roots[i] = candidates[i].root
	}
	leftRefs, err := bulkRefs(baseline, roots)
	if err != nil {
		return PartitionedManifest{}, PartitionedManifest{}, nil, err
	}
	rightRefs, err := bulkRefs(result, roots)
	if err != nil {
		return PartitionedManifest{}, PartitionedManifest{}, nil, err
	}
	left, err := makePartitionedManifest(baseline, roots, leftRefs, policyDigest)
	if err != nil {
		return PartitionedManifest{}, PartitionedManifest{}, nil, err
	}
	right, err := makePartitionedManifest(result, roots, rightRefs, policyDigest)
	if err != nil {
		return PartitionedManifest{}, PartitionedManifest{}, nil, err
	}
	records := make([]BulkRecord, len(roots))
	for i, root := range roots {
		summary := diffBulkSummary(entriesUnderRoot(baseline.Entries, root), entriesUnderRoot(result.Entries, root), rightRefs[i].Summary)
		bulkID := digestStrings("sunaba.bulk.id.v1\x00", policyDigest, root, leftRefs[i].ObjectDigest, rightRefs[i].ObjectDigest)
		records[i] = BulkRecord{
			BulkID: bulkID, Root: root, Discovery: candidates[i].discovery, Baseline: leftRefs[i], Result: rightRefs[i],
			Capture: BulkCapture{State: "frozen_vm"}, Summary: summary, Disposition: "unresolved",
		}
	}
	return left, right, records, nil
}

// PartitionResultManifest applies the baseline's already approved Bulk roots
// to a frozen result and adds deterministic result-only roots. This prevents a
// path from appearing in both Core and Bulk even when it exists on only one
// side of the session.
func PartitionResultManifest(baseline PartitionedManifest, baselineRecords []BulkRecord, result SnapshotManifest, snapshotPolicy SnapshotPolicy, policy BulkPolicy, policyDigest string) (PartitionedManifest, PartitionedManifest, []BulkRecord, error) {
	if err := validatePartitionedManifest(baseline, snapshotPolicy); err != nil {
		return PartitionedManifest{}, PartitionedManifest{}, nil, fmt.Errorf("invalid approved partitioned baseline: %w", err)
	}
	if baseline.PolicyDigest != policyDigest || !validSHA256(policyDigest) {
		return PartitionedManifest{}, PartitionedManifest{}, nil, fmt.Errorf("partition policy identity changed")
	}
	policy = bulkPolicyWithSnapshotCeilings(policy, snapshotPolicy)
	if err := validateCanonicalManifest(result, bulkScanSnapshotPolicy(snapshotPolicy)); err != nil {
		return PartitionedManifest{}, PartitionedManifest{}, nil, fmt.Errorf("invalid frozen result: %w", err)
	}
	empty, err := finalizeSnapshotManifest(result.Root, nil, 0)
	if err != nil {
		return PartitionedManifest{}, PartitionedManifest{}, nil, err
	}
	_, _, resultRecords, err := PartitionManifestPair(empty, result, policy, policyDigest)
	if err != nil {
		return PartitionedManifest{}, PartitionedManifest{}, nil, err
	}
	discovery := make(map[string]BulkDiscovery, len(baselineRecords)+len(resultRecords))
	for _, record := range baselineRecords {
		discovery[record.Root] = record.Discovery
	}
	for _, record := range resultRecords {
		conflict := false
		for root := range discovery {
			if overlapsPath(root, record.Root) && root != record.Root {
				conflict = true
				break
			}
		}
		if !conflict {
			discovery[record.Root] = record.Discovery
		}
	}
	roots := make([]string, 0, len(discovery))
	for root := range discovery {
		roots = append(roots, root)
	}
	sort.Strings(roots)
	if len(roots) > MaximumBulkRoots {
		return PartitionedManifest{}, PartitionedManifest{}, nil, fmt.Errorf("bulk root count exceeds %d", MaximumBulkRoots)
	}
	baselineByRoot := make(map[string]BulkManifestRef, len(baseline.BulkRoots))
	for _, ref := range baseline.BulkRoots {
		baselineByRoot[ref.Root] = ref
	}
	baselineRefs := make([]BulkManifestRef, len(roots))
	for i, root := range roots {
		if ref, exists := baselineByRoot[root]; exists {
			baselineRefs[i] = ref
		} else {
			baselineRefs[i] = BulkManifestRef{Root: root, State: "absent"}
		}
	}
	resultRefs, err := bulkRefs(result, roots)
	if err != nil {
		return PartitionedManifest{}, PartitionedManifest{}, nil, err
	}
	partitionedBaseline := baseline
	partitionedBaseline.BulkRoots = baselineRefs
	partitionedBaseline.Digest, err = partitionedManifestDigest(partitionedBaseline)
	if err != nil {
		return PartitionedManifest{}, PartitionedManifest{}, nil, err
	}
	partitionedResult, err := makePartitionedManifest(result, roots, resultRefs, policyDigest)
	if err != nil {
		return PartitionedManifest{}, PartitionedManifest{}, nil, err
	}
	if err := validateCanonicalManifest(partitionedResult.Core, snapshotPolicy); err != nil {
		return PartitionedManifest{}, PartitionedManifest{}, nil, fmt.Errorf("Core result exceeds its admission limits after Bulk partition: %w", err)
	}
	records := make([]BulkRecord, len(roots))
	for i, root := range roots {
		summary := resultRefs[i].Summary
		if baselineRefs[i].State == "absent" {
			summary.Added = summary.Files + summary.Directories + summary.Symlinks
		} else if resultRefs[i].State == "absent" && baselineRefs[i].State == "exact" {
			summary.Deleted = baselineRefs[i].Summary.Files + baselineRefs[i].Summary.Directories + baselineRefs[i].Summary.Symlinks
		}
		bulkID := digestStrings("sunaba.bulk.id.v1\x00", policyDigest, root, baselineRefs[i].ObjectDigest, resultRefs[i].ObjectDigest, baselineRefs[i].State, resultRefs[i].State)
		records[i] = BulkRecord{
			BulkID: bulkID, Root: root, Discovery: discovery[root], Baseline: baselineRefs[i], Result: resultRefs[i],
			Capture: BulkCapture{State: "frozen_vm"}, Summary: summary, Disposition: DispositionUnresolved,
		}
	}
	coreChanges, err := BuildChangeSet(partitionedBaseline.Core, partitionedResult.Core, snapshotPolicy)
	if err != nil {
		return PartitionedManifest{}, PartitionedManifest{}, nil, err
	}
	filteredBaseline := make([]BulkManifestRef, 0, len(records))
	filteredResult := make([]BulkManifestRef, 0, len(records))
	filteredRecords := make([]BulkRecord, 0, len(records))
	for index, record := range records {
		if record.Baseline.State == "present_untracked" && record.Result.State == "absent" && !changeSetOverlapsRoot(coreChanges, record.Root) {
			continue
		}
		filteredBaseline = append(filteredBaseline, partitionedBaseline.BulkRoots[index])
		filteredResult = append(filteredResult, partitionedResult.BulkRoots[index])
		filteredRecords = append(filteredRecords, record)
	}
	partitionedBaseline.BulkRoots = filteredBaseline
	partitionedResult.BulkRoots = filteredResult
	partitionedBaseline.Digest, err = partitionedManifestDigest(partitionedBaseline)
	if err != nil {
		return PartitionedManifest{}, PartitionedManifest{}, nil, err
	}
	partitionedResult.Digest, err = partitionedManifestDigest(partitionedResult)
	if err != nil {
		return PartitionedManifest{}, PartitionedManifest{}, nil, err
	}
	records = filteredRecords
	return partitionedBaseline, partitionedResult, records, nil
}

func changeSetOverlapsRoot(changeSet ChangeSet, root string) bool {
	for _, change := range changeSet.Changes {
		if overlapsPath(change.Path, root) || (change.From != "" && overlapsPath(change.From, root)) {
			return true
		}
	}
	return false
}

func bulkScanSnapshotPolicy(policy SnapshotPolicy) SnapshotPolicy {
	policy.MaxEntries = MaximumBulkEntriesPerWorkSet
	policy.MaxTotalSize = MaximumBulkLogicalBytesPerWorkSet
	if policy.MaxFileSize < MaximumBulkLogicalBytesPerRoot {
		policy.MaxFileSize = MaximumBulkLogicalBytesPerRoot
	}
	return policy
}

func BulkCaptureSnapshotPolicy(policy SnapshotPolicy) SnapshotPolicy {
	policy = bulkScanSnapshotPolicy(policy)
	// Bulk capture reads a frozen, private host materialization and flattens
	// hardlinks into independent content-addressed blobs. Normal Project
	// snapshots keep rejecting hardlinks so they cannot import host content
	// through an inode shared outside the Project.
	policy.allowHardlinks = true
	return policy
}

func ExactAbsentBulkCapture(root string) BulkCapture {
	return BulkCapture{State: "exact_absence", ObjectDigest: digestStrings("sunaba.bulk.absent.v1\x00", root)}
}

func BulkRecordID(policyDigest, root string, baseline, result BulkManifestRef) string {
	return digestStrings("sunaba.bulk.id.v1\x00", policyDigest, root, baseline.ObjectDigest, result.ObjectDigest, baseline.State, result.State)
}

func RebuildPartitionedManifestDigest(manifest PartitionedManifest) (PartitionedManifest, error) {
	var err error
	manifest.Digest, err = partitionedManifestDigest(manifest)
	return manifest, err
}

func ExactBulkRefFromManifest(manifest SnapshotManifest, root string) (BulkManifestRef, error) {
	refs, err := bulkRefs(manifest, []string{root})
	if err != nil {
		return BulkManifestRef{}, err
	}
	if len(refs) != 1 || refs[0].State != "exact" {
		return BulkManifestRef{}, fmt.Errorf("Bulk root %q is not an exact directory", root)
	}
	return refs[0], nil
}

func classifyBulkRoots(baseline, result SnapshotManifest, policy BulkPolicy) ([]bulkCandidate, error) {
	entries := append(append([]SnapshotEntry(nil), baseline.Entries...), result.Entries...)
	sort.Slice(entries, func(i, j int) bool { return entries[i].Path < entries[j].Path })
	normal := make(map[string]struct{}, len(policy.NormalRoots))
	for _, root := range policy.NormalRoots {
		normal[root] = struct{}{}
	}
	selected := make(map[string]BulkDiscovery)
	for _, entry := range entries {
		if entry.Type != TypeDirectory || coveredByBulkRoot(entry.Path, selected) || containsBulkRoot(entry.Path, selected) {
			continue
		}
		if _, overridden := normal[entry.Path]; overridden {
			continue
		}
		for _, rule := range policy.Rules {
			matched := rule.Selector.Kind == "literal" && entry.Path == rule.Selector.Value
			if rule.Selector.Kind == "component" && path.Base(entry.Path) == rule.Selector.Value {
				matched = true
			}
			if matched {
				reason := "user-" + rule.Selector.Kind + "-rule"
				if strings.HasPrefix(rule.ID, "builtin.") {
					reason = "builtin-component-rule"
				}
				selected[entry.Path] = BulkDiscovery{Reason: reason, RuleID: rule.ID, Hint: rule.Hint}
				break
			}
		}
	}
	type admissionCandidate struct {
		root    string
		entries int
		bytes   int64
	}
	coreEntries, coreBytes := remainingCoreCost(baseline, result, selected)
	if coreEntries > policy.CoreHardEntries || coreBytes > policy.CoreHardBytes {
		candidates := make([]admissionCandidate, 0)
		seen := make(map[string]struct{})
		for _, entry := range entries {
			if entry.Type != TypeDirectory || strings.Contains(entry.Path, "/") || coveredByBulkRoot(entry.Path, selected) || containsBulkRoot(entry.Path, selected) {
				continue
			}
			if _, overridden := normal[entry.Path]; overridden {
				continue
			}
			if _, duplicate := seen[entry.Path]; duplicate {
				continue
			}
			seen[entry.Path] = struct{}{}
			summary := summarizeBulkEntries(unionEntriesUnderRoot(baseline.Entries, result.Entries, entry.Path))
			candidates = append(candidates, admissionCandidate{root: entry.Path, entries: summary.Files + summary.Directories + summary.Symlinks, bytes: summary.LogicalBytes})
		}
		sort.Slice(candidates, func(i, j int) bool {
			leftCost, rightCost := candidates[i].entries, candidates[j].entries
			if coreBytes > policy.CoreHardBytes {
				if candidates[i].bytes != candidates[j].bytes {
					return candidates[i].bytes > candidates[j].bytes
				}
			} else if leftCost != rightCost {
				return leftCost > rightCost
			}
			return candidates[i].root < candidates[j].root
		})
		for _, candidate := range candidates {
			if coreEntries <= policy.CoreHardEntries && coreBytes <= policy.CoreHardBytes {
				break
			}
			selected[candidate.root] = BulkDiscovery{Reason: "core-admission-overflow"}
			coreEntries -= candidate.entries
			coreBytes -= candidate.bytes
		}
		if coreEntries > policy.CoreHardEntries || coreBytes > policy.CoreHardBytes {
			return nil, fmt.Errorf("Core review exceeds its hard ceiling and cannot be partitioned by directory")
		}
	}
	// Structural overflow is deterministic and only applies when no ancestor
	// was selected by an explicit rule. The first canonical directory whose
	// subtree crosses a soft bound becomes the root.
	for _, entry := range entries {
		if entry.Type != TypeDirectory || coveredByBulkRoot(entry.Path, selected) || containsBulkRoot(entry.Path, selected) {
			continue
		}
		if _, overridden := normal[entry.Path]; overridden {
			continue
		}
		summary := summarizeBulkEntries(unionEntriesUnderRoot(baseline.Entries, result.Entries, entry.Path))
		if summary.Files+summary.Directories+summary.Symlinks > policy.CoreSoftEntries || summary.LogicalBytes > policy.CoreSoftBytes {
			reason := "structural-entry-overflow"
			if summary.LogicalBytes > policy.CoreSoftBytes {
				reason = "structural-byte-overflow"
			}
			selected[entry.Path] = BulkDiscovery{Reason: reason}
		}
	}
	resultCandidates := make([]bulkCandidate, 0, len(selected))
	for root, discovery := range selected {
		resultCandidates = append(resultCandidates, bulkCandidate{root: root, discovery: discovery})
	}
	sort.Slice(resultCandidates, func(i, j int) bool { return resultCandidates[i].root < resultCandidates[j].root })
	if len(resultCandidates) > MaximumBulkRoots {
		return nil, fmt.Errorf("bulk root count exceeds %d", MaximumBulkRoots)
	}
	return resultCandidates, nil
}

func remainingCoreCost(baseline, result SnapshotManifest, selected map[string]BulkDiscovery) (int, int64) {
	byPath := make(map[string]SnapshotEntry, len(baseline.Entries)+len(result.Entries))
	for _, entry := range append(append([]SnapshotEntry(nil), baseline.Entries...), result.Entries...) {
		byPath[entry.Path] = entry
	}
	count := 0
	var logicalBytes int64
	for _, entry := range byPath {
		if coveredByBulkRoot(entry.Path, selected) {
			continue
		}
		count++
		if entry.Type == TypeFile {
			logicalBytes += entry.Size
		}
	}
	return count, logicalBytes
}

func bulkPolicyWithSnapshotCeilings(policy BulkPolicy, snapshot SnapshotPolicy) BulkPolicy {
	if policy.DefaultsVersion == 0 {
		return policy
	}
	if snapshot.MaxEntries < policy.CoreHardEntries {
		policy.CoreHardEntries = snapshot.MaxEntries
	}
	if snapshot.MaxTotalSize < policy.CoreHardBytes {
		policy.CoreHardBytes = snapshot.MaxTotalSize
	}
	if policy.CoreSoftEntries > policy.CoreHardEntries {
		policy.CoreSoftEntries = policy.CoreHardEntries
	}
	if policy.CoreSoftBytes > policy.CoreHardBytes {
		policy.CoreSoftBytes = policy.CoreHardBytes
	}
	return policy
}

func coveredByBulkRoot(entryPath string, selected map[string]BulkDiscovery) bool {
	for root := range selected {
		if entryPath == root || strings.HasPrefix(entryPath, root+"/") {
			return true
		}
	}
	return false
}

func containsBulkRoot(entryPath string, selected map[string]BulkDiscovery) bool {
	for root := range selected {
		if strings.HasPrefix(root, entryPath+"/") {
			return true
		}
	}
	return false
}

func makePartitionedManifest(source SnapshotManifest, roots []string, refs []BulkManifestRef, policyDigest string) (PartitionedManifest, error) {
	coreEntries := make([]SnapshotEntry, 0, len(source.Entries))
	for _, entry := range source.Entries {
		excluded := false
		for _, root := range roots {
			if entry.Path == root || strings.HasPrefix(entry.Path, root+"/") {
				excluded = true
				break
			}
		}
		if !excluded {
			coreEntries = append(coreEntries, entry)
		}
	}
	var total int64
	for _, entry := range coreEntries {
		if entry.Type == TypeFile {
			total += entry.Size
		}
	}
	core, err := finalizeSnapshotManifest(source.Root, coreEntries, total)
	if err != nil {
		return PartitionedManifest{}, err
	}
	manifest := PartitionedManifest{Version: BulkFormatVersion, Root: source.Root, Core: core, BulkRoots: append([]BulkManifestRef(nil), refs...), PolicyDigest: policyDigest}
	if manifest.BulkRoots == nil {
		manifest.BulkRoots = []BulkManifestRef{}
	}
	manifest.Digest, err = partitionedManifestDigest(manifest)
	return manifest, err
}

func partitionedManifestDigest(manifest PartitionedManifest) (string, error) {
	return canonicalJSONDigest("sunaba.partitioned-manifest.v1\x00", struct {
		Version      int
		Root         string
		CoreDigest   string
		BulkRoots    []BulkManifestRef
		PolicyDigest string
	}{manifest.Version, manifest.Root, manifest.Core.Digest, manifest.BulkRoots, manifest.PolicyDigest})
}

func bulkRefs(manifest SnapshotManifest, roots []string) ([]BulkManifestRef, error) {
	refs := make([]BulkManifestRef, len(roots))
	totalEntries := 0
	var totalBytes int64
	for i, root := range roots {
		entries := entriesUnderRoot(manifest.Entries, root)
		if len(entries) == 0 {
			refs[i] = BulkManifestRef{Root: root, State: "absent"}
			continue
		}
		rootEntry := entries[0]
		if rootEntry.Path != root || rootEntry.Type != TypeDirectory {
			refs[i] = BulkManifestRef{Root: root, State: "unsupported"}
			continue
		}
		summary := summarizeBulkEntries(entries)
		entryCount := summary.Files + summary.Directories + summary.Symlinks
		totalEntries += entryCount
		totalBytes += summary.LogicalBytes
		if entryCount > MaximumBulkEntriesPerRoot || summary.LogicalBytes > MaximumBulkLogicalBytesPerRoot || totalEntries > MaximumBulkEntriesPerWorkSet || totalBytes > MaximumBulkLogicalBytesPerWorkSet {
			return nil, fmt.Errorf("bulk capture inventory exceeds its hard ceiling at %q", root)
		}
		manifestDigest, merkleDigest, objectDigest, err := bulkDigests(root, entries, summary)
		if err != nil {
			return nil, err
		}
		refs[i] = BulkManifestRef{Root: root, State: "exact", ManifestDigest: manifestDigest, MerkleDigest: merkleDigest, ObjectDigest: objectDigest, Summary: summary}
	}
	return refs, nil
}

func entriesUnderRoot(entries []SnapshotEntry, root string) []SnapshotEntry {
	result := make([]SnapshotEntry, 0)
	for _, entry := range entries {
		if entry.Path == root || strings.HasPrefix(entry.Path, root+"/") {
			result = append(result, entry)
		}
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Path < result[j].Path })
	return result
}

func unionEntriesUnderRoot(left, right []SnapshotEntry, root string) []SnapshotEntry {
	byPath := make(map[string]SnapshotEntry)
	for _, entry := range append(entriesUnderRoot(left, root), entriesUnderRoot(right, root)...) {
		byPath[entry.Path] = entry
	}
	result := make([]SnapshotEntry, 0, len(byPath))
	for _, entry := range byPath {
		result = append(result, entry)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Path < result[j].Path })
	return result
}

func summarizeBulkEntries(entries []SnapshotEntry) BulkSummary {
	var summary BulkSummary
	for _, entry := range entries {
		switch entry.Type {
		case TypeFile:
			summary.Files++
			summary.LogicalBytes += entry.Size
			if entry.Mode&0111 != 0 {
				summary.Executables++
			}
		case TypeDirectory:
			summary.Directories++
		case TypeSymlink:
			summary.Symlinks++
		}
	}
	return summary
}

func diffBulkSummary(before, after []SnapshotEntry, result BulkSummary) BulkSummary {
	result.Added, result.Modified, result.Deleted = 0, 0, 0
	left := make(map[string]SnapshotEntry, len(before))
	right := make(map[string]SnapshotEntry, len(after))
	for _, entry := range before {
		left[entry.Path] = entry
	}
	for _, entry := range after {
		right[entry.Path] = entry
	}
	for entryPath, entry := range left {
		other, exists := right[entryPath]
		if !exists {
			result.Deleted++
		} else if !sameSnapshotEntry(entry, other) {
			result.Modified++
		}
	}
	for entryPath := range right {
		if _, exists := left[entryPath]; !exists {
			result.Added++
		}
	}
	return result
}

func bulkDigests(root string, entries []SnapshotEntry, summary BulkSummary) (string, string, string, error) {
	entries = append([]SnapshotEntry(nil), entries...)
	sort.Slice(entries, func(i, j int) bool { return entries[i].Path < entries[j].Path })
	manifest, err := encodeBulkManifest(entries)
	if err != nil {
		return "", "", "", err
	}
	manifestSum := sha256.Sum256(manifest)
	manifestDigest := hex.EncodeToString(manifestSum[:])
	merkleDigest, err := bulkMerkle(root, entries)
	if err != nil {
		return "", "", "", err
	}
	summaryDigest, err := canonicalJSONDigest("sunaba.bulk.summary.v1\x00", summary)
	if err != nil {
		return "", "", "", err
	}
	objectDigest := digestStrings("sunaba.bulk.object.v1\x00", BulkMetadataProfile, root, "directory", merkleDigest, manifestDigest, summaryDigest)
	return manifestDigest, merkleDigest, objectDigest, nil
}

func encodeBulkManifest(entries []SnapshotEntry) ([]byte, error) {
	manifest := &bytes.Buffer{}
	manifest.WriteString("sunaba.bulk.manifest.v1\x00")
	writeUint32(manifest, uint32(len(entries)))
	for _, entry := range entries {
		writeBytes(manifest, []byte(entry.Path))
		writeBytes(manifest, []byte(entry.Type))
		writeUint32(manifest, entry.Mode&0777)
		writeUint64(manifest, uint64(entry.Size))
		writeBytes(manifest, []byte(entry.SHA256))
		writeBytes(manifest, []byte(entry.LinkTarget))
		if manifest.Len() > MaximumBulkManifestBytes {
			return nil, fmt.Errorf("bulk manifest exceeds %d bytes", MaximumBulkManifestBytes)
		}
	}
	return manifest.Bytes(), nil
}

func bulkMerkle(root string, entries []SnapshotEntry) (string, error) {
	byPath := make(map[string]SnapshotEntry, len(entries))
	children := make(map[string][]string)
	if !validRawBulkPath(root) {
		return "", fmt.Errorf("bulk root path is invalid")
	}
	previous := ""
	for index, entry := range entries {
		if !validRawBulkPath(entry.Path) || (entry.Path != root && !strings.HasPrefix(entry.Path, root+"/")) || (index > 0 && previous >= entry.Path) {
			return "", fmt.Errorf("bulk manifest path %q is outside its root or non-canonical", entry.Path)
		}
		previous = entry.Path
		byPath[entry.Path] = entry
		if entry.Path != root {
			parent := path.Dir(entry.Path)
			children[parent] = append(children[parent], entry.Path)
		}
	}
	rootEntry, exists := byPath[root]
	if !exists || rootEntry.Type != TypeDirectory {
		return "", fmt.Errorf("bulk root %q is not an exact directory", root)
	}
	for entryPath := range byPath {
		if entryPath == root {
			continue
		}
		parentEntry, exists := byPath[path.Dir(entryPath)]
		if !exists || parentEntry.Type != TypeDirectory {
			return "", fmt.Errorf("bulk manifest path %q has a missing or non-directory parent", entryPath)
		}
	}
	var digestEntry func(string) ([]byte, error)
	digestEntry = func(entryPath string) ([]byte, error) {
		entry, exists := byPath[entryPath]
		if !exists {
			return nil, fmt.Errorf("bulk manifest is missing %q", entryPath)
		}
		buffer := &bytes.Buffer{}
		switch entry.Type {
		case TypeFile:
			buffer.WriteString("sunaba.bulk.file.v1\x00")
			writeUint32(buffer, entry.Mode&0777)
			writeUint64(buffer, uint64(entry.Size))
			content, err := hex.DecodeString(entry.SHA256)
			if err != nil || len(content) != sha256.Size {
				return nil, fmt.Errorf("bulk file %q has an invalid content digest", entryPath)
			}
			buffer.Write(content)
		case TypeSymlink:
			buffer.WriteString("sunaba.bulk.symlink.v1\x00")
			writeBytes(buffer, []byte(entry.LinkTarget))
		case TypeDirectory:
			buffer.WriteString("sunaba.bulk.dir.v1\x00")
			writeUint32(buffer, entry.Mode&0777)
			childPaths := append([]string(nil), children[entryPath]...)
			sort.Slice(childPaths, func(i, j int) bool { return path.Base(childPaths[i]) < path.Base(childPaths[j]) })
			if len(childPaths) > MaximumBulkDirectChildren {
				return nil, fmt.Errorf("bulk directory %q exceeds direct child limit", entryPath)
			}
			writeUint32(buffer, uint32(len(childPaths)))
			nameBytes := 0
			for _, childPath := range childPaths {
				name := []byte(path.Base(childPath))
				nameBytes += len(name)
				if nameBytes > MaximumBulkChildNameBytes {
					return nil, fmt.Errorf("bulk directory %q exceeds child-name byte limit", entryPath)
				}
				childDigest, err := digestEntry(childPath)
				if err != nil {
					return nil, err
				}
				writeBytes(buffer, name)
				writeBytes(buffer, []byte(byPath[childPath].Type))
				buffer.Write(childDigest)
			}
		default:
			return nil, fmt.Errorf("bulk entry %q has unsupported type %q", entryPath, entry.Type)
		}
		digest := sha256.Sum256(buffer.Bytes())
		return digest[:], nil
	}
	digest, err := digestEntry(root)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(digest), nil
}

func validRawBulkPath(value string) bool {
	if value == "" || value == "." || path.IsAbs(value) || path.Clean(value) != value || value == ".." || strings.HasPrefix(value, "../") || len(value) > 4096 || strings.ContainsAny(value, "\\\x00") {
		return false
	}
	for _, component := range strings.Split(value, "/") {
		if component == "" || component == "." || component == ".." || len(component) > 255 {
			return false
		}
	}
	return true
}

func writeUint32(buffer *bytes.Buffer, value uint32) {
	_ = binary.Write(buffer, binary.BigEndian, value)
}
func writeUint64(buffer *bytes.Buffer, value uint64) {
	_ = binary.Write(buffer, binary.BigEndian, value)
}
func writeBytes(buffer *bytes.Buffer, value []byte) {
	writeUint32(buffer, uint32(len(value)))
	buffer.Write(value)
}

func digestStrings(domain string, values ...string) string {
	hash := sha256.New()
	hash.Write([]byte(domain))
	for _, value := range values {
		var length [4]byte
		binary.BigEndian.PutUint32(length[:], uint32(len(value)))
		hash.Write(length[:])
		hash.Write([]byte(value))
	}
	return hex.EncodeToString(hash.Sum(nil))
}

func canonicalJSONDigest(domain string, value any) (string, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(append([]byte(domain), encoded...))
	return hex.EncodeToString(digest[:]), nil
}

func validSHA256(value string) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == sha256.Size && value == strings.ToLower(value)
}
