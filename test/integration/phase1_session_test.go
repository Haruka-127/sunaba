//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	hostapply "sunaba/internal/apply"
	"sunaba/internal/approval"
	"sunaba/internal/audit"
	"sunaba/internal/dependency"
	"sunaba/internal/modelgateway"
	"sunaba/internal/opencode"
	sunabaruntime "sunaba/internal/runtime"
	"sunaba/internal/session"
	"sunaba/internal/state"
	"sunaba/internal/workspace"
)

func TestPhase1SecureSessionVerticalSlice(t *testing.T) {
	if os.Getenv("SUNABA_PHASE1_INTEGRATION") != "1" {
		t.Skip("set SUNABA_PHASE1_INTEGRATION=1 on the pinned macOS/Apple Container host")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Minute)
	defer cancel()
	runID := randomID(t)
	runtimeBase, err := os.MkdirTemp("/private/tmp", "sunaba-runtime-phase1-")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(runtimeBase, 0700); err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(runtimeBase)
	projectRoot := filepath.Join(runtimeBase, "project")
	if err := os.Mkdir(projectRoot, 0700); err != nil {
		t.Fatal(err)
	}
	writeIntegrationFile(t, filepath.Join(projectRoot, "modify.txt"), "before\n")
	writeIntegrationFile(t, filepath.Join(projectRoot, "delete.txt"), "delete\n")
	writeIntegrationFile(t, filepath.Join(projectRoot, ".git", "config"), "host-only\n")
	hostBefore, err := workspace.BuildSnapshotManifest(projectRoot, workspace.DefaultSnapshotPolicy())
	if err != nil {
		t.Fatal(err)
	}
	relay := buildLinuxBinary(t, ctx, runtimeBase, "sunaba-guest-relay", "./cmd/sunaba-guest-relay")
	modelID := "gpt-sunaba-test"
	upstreamKey := "upstream-" + runID
	firstSessionID := "p1a" + runID
	modelEditPath := "/workspace/sunaba-" + firstSessionID + "/model-edit.txt"
	toolCalled := make(chan struct{}, 1)
	toolCompleted := make(chan struct{}, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/responses" || r.Header.Get("Authorization") != "Bearer "+upstreamKey {
			http.Error(w, "rejected", http.StatusUnauthorized)
			return
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "read request", http.StatusBadRequest)
			return
		}
		if strings.Contains(string(body), `"type":"function_call_output"`) || strings.Contains(string(body), `"type": "function_call_output"`) {
			select {
			case toolCompleted <- struct{}{}:
			default:
			}
			writeResponsesTextStream(w, modelID, "phase1 tool complete")
			return
		}
		var request map[string]any
		_ = json.Unmarshal(body, &request)
		if request["tools"] == nil {
			writeResponsesTextStream(w, modelID, "sunaba phase1")
			return
		}
		if !strings.Contains(string(body), `"name":"apply_patch"`) && !strings.Contains(string(body), `"name": "apply_patch"`) {
			http.Error(w, "OpenCode apply_patch tool missing", http.StatusBadRequest)
			return
		}
		select {
		case toolCalled <- struct{}{}:
		default:
		}
		patchText := "*** Begin Patch\n*** Add File: model-edit.txt\n+created by model\n*** End Patch"
		writeResponsesFunctionCallStream(w, modelID, "apply_patch", `{"patchText":`+fmt.Sprintf("%q", patchText)+`}`)
	}))
	defer upstream.Close()
	auditErrors := make(chan error, 16)
	newConfig := func(sessionID string) session.Config {
		modelToken, err := session.NewSecret()
		if err != nil {
			t.Fatal(err)
		}
		password, err := session.NewSecret()
		if err != nil {
			t.Fatal(err)
		}
		projectID := state.ProjectID(projectRoot)
		capability, err := modelgateway.NewCapability(modelToken, projectID, "sunaba-"+projectID+"-"+sessionID, sessionID, modelID, time.Now().Add(3*time.Minute))
		if err != nil {
			t.Fatal(err)
		}
		auditRecorder, err := audit.NewRecorder(filepath.Join(runtimeBase, "state", "audit"))
		if err != nil {
			t.Fatal(err)
		}
		gateway, err := modelgateway.New(modelgateway.Config{
			UpstreamBaseURL: upstream.URL, UpstreamAPIKey: upstreamKey, Capability: capability,
			Audit: func(event modelgateway.AuditEvent) {
				outcome := "allowed"
				if event.Status < 200 || event.Status >= 300 {
					outcome = "rejected"
				}
				if err := auditRecorder.Append(audit.BoundaryEvent{
					At: event.At, Category: "gateway", Action: "model.request", Outcome: outcome,
					ProjectID: event.ProjectID, VMID: event.VMID, SessionID: event.SessionID,
					Details: map[string]string{"model": event.Model, "status": strconv.Itoa(event.Status), "request_bytes": strconv.FormatInt(event.RequestBytes, 10), "response_bytes": strconv.FormatInt(event.ResponseBytes, 10), "reason": event.Reason},
				}); err != nil {
					auditErrors <- err
				}
			},
		})
		if err != nil {
			t.Fatal(err)
		}
		provider, err := opencode.BuildModelGatewayConfig(opencode.ModelGatewayProviderConfig{
			BaseURL: "http://127.0.0.1:4141/v1", Model: modelID, TokenEnv: "SUNABA_MODEL_GATEWAY_TOKEN",
			ContextLimit: 200_000, OutputLimit: 32_000,
		})
		if err != nil {
			t.Fatal(err)
		}
		return session.Config{
			Store: &state.Store{Root: filepath.Join(runtimeBase, "state")}, Runtime: sunabaruntime.NewAppleContainer(false),
			ProjectRoot: projectRoot, RuntimeBase: runtimeBase, SessionID: sessionID,
			Image: dependency.MustPinned().AgentImage.Tag, CPUs: 1, Memory: "2G", GuestRelayBinary: relay,
			ProviderConfig: provider, ModelGateway: gateway, ModelToken: modelToken, ServerPassword: password,
			LeaseTTL: 3 * time.Minute, Audit: auditRecorder,
			OnEvent: func(session.Event) {},
		}
	}

	first := newConfig(firstSessionID)
	active, err := session.Start(ctx, first)
	if err != nil {
		t.Fatal(err)
	}
	defer active.Destroy(context.Background())
	prePauseURL := active.AttachURL
	if err := active.Pause(ctx); err != nil {
		t.Fatal(err)
	}
	pausedRequest, _ := http.NewRequestWithContext(ctx, http.MethodGet, prePauseURL+"/global/health", nil)
	pausedRequest.SetBasicAuth("opencode", first.ServerPassword)
	if response, err := (&http.Client{Timeout: time.Second}).Do(pausedRequest); err == nil {
		_ = response.Body.Close()
		t.Fatal("paused session retained an attach capability")
	}
	pausedModelRequest, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://sunaba/v1/responses", strings.NewReader(`{"model":"`+modelID+`","stream":false}`))
	if err != nil {
		t.Fatal(err)
	}
	pausedModelRequest.Header.Set("Authorization", "Bearer "+first.ModelToken)
	pausedModelRequest.Header.Set("Content-Type", "application/json")
	pausedModelResponse, err := unixHTTPClient(filepath.Join(active.Root, "model-gateway.sock")).Do(pausedModelRequest)
	if err != nil {
		t.Fatal(err)
	}
	_ = pausedModelResponse.Body.Close()
	if pausedModelResponse.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("paused Model Gateway status=%d", pausedModelResponse.StatusCode)
	}
	if err := active.Resume(ctx); err != nil {
		t.Fatal(err)
	}
	message := exerciseOpenCodeResponses(t, ctx, filepath.Join(active.Root, "attach.sock"), first.ServerPassword, modelID)
	if !strings.Contains(message, "phase1 tool complete") {
		t.Fatalf("OpenCode did not use Model Gateway: %s", message)
	}
	select {
	case <-toolCalled:
	case <-time.After(5 * time.Second):
		t.Fatal("mock model did not issue the write tool call")
	}
	select {
	case <-toolCompleted:
	case <-time.After(5 * time.Second):
		t.Fatal("OpenCode did not return function_call_output to the model")
	}
	if out, err := first.Runtime.ExecOutput(ctx, active.Container, []string{"cat", modelEditPath}); err != nil || out != "created by model\n" {
		t.Fatalf("model tool did not edit merged workspace: %v %q", err, out)
	}
	credentialProbe := "! grep -R --binary-files=without-match -- " + upstreamKey + " /run/sunaba /var/lib/sunaba " + active.WorkspacePath
	if out, err := first.Runtime.ExecOutput(ctx, active.Container, []string{"/bin/bash", "-lc", credentialProbe}); err != nil {
		t.Fatalf("upstream credential was visible in guest: %v: %s", err, out)
	}
	edit := "printf 'after\\n' > " + active.WorkspacePath + "/modify.txt; rm " + active.WorkspacePath + "/delete.txt; sync"
	if out, err := first.Runtime.ExecOutput(ctx, active.Container, []string{"/bin/bash", "-lc", edit}); err != nil {
		t.Fatalf("edit merged workspace: %v: %s", err, out)
	}
	hostDuring, err := workspace.BuildSnapshotManifest(projectRoot, workspace.DefaultSnapshotPolicy())
	if err != nil || hostDuring.Digest != hostBefore.Digest {
		t.Fatalf("guest edit changed host Project: %v %s != %s", err, hostDuring.Digest, hostBefore.Digest)
	}
	attachURL := active.AttachURL
	result, err := active.StopAndExport(ctx)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]workspace.ChangeKind{"model-edit.txt": workspace.ChangeAdd, "modify.txt": workspace.ChangeModify, "delete.txt": workspace.ChangeDelete}
	if len(result.ChangeSet.Changes) != len(want) {
		t.Fatalf("Change Set=%+v", result.ChangeSet)
	}
	for _, change := range result.ChangeSet.Changes {
		if want[change.Path] != change.Kind {
			t.Fatalf("unexpected change=%+v", change)
		}
	}
	revokedClient := &http.Client{Timeout: time.Second}
	revokedRequest, _ := http.NewRequestWithContext(ctx, http.MethodGet, attachURL+"/global/health", nil)
	revokedRequest.SetBasicAuth("opencode", first.ServerPassword)
	if response, err := revokedClient.Do(revokedRequest); err == nil {
		_ = response.Body.Close()
		t.Fatal("session endpoint remained reachable after capability shutdown")
	}
	if err := active.Destroy(ctx); err != nil {
		t.Fatal(err)
	}

	second := newConfig("p1b" + runID)
	clean, err := session.Start(ctx, second)
	if err != nil {
		t.Fatal(err)
	}
	defer clean.Destroy(context.Background())
	out, err := second.Runtime.ExecOutput(ctx, clean.Container, []string{"/bin/bash", "-lc", "cat " + clean.WorkspacePath + "/modify.txt; test ! -e " + clean.WorkspacePath + "/model-edit.txt; test -e " + clean.WorkspacePath + "/delete.txt"})
	if err != nil || strings.TrimSpace(out) != "before" {
		t.Fatalf("clean regeneration reused unapproved state: %v %q", err, out)
	}
	if err := clean.Destroy(ctx); err != nil {
		t.Fatal(err)
	}
	if current, err := workspace.BuildSnapshotManifest(projectRoot, workspace.DefaultSnapshotPolicy()); err != nil || current.Digest != hostBefore.Digest {
		t.Fatalf("host Project changed after clean regeneration: %v", err)
	}
	binding := approval.Binding{ProjectID: active.ProjectID, BaselineDigest: active.Baseline.Digest, MergedDigest: result.Merged.Digest, ChangeSetDigest: result.ChangeSet.Digest}
	approvals, err := approval.NewAuditedManager(nil, first.Audit, active.ProjectID, active.Container, active.SessionID)
	if err != nil {
		t.Fatal(err)
	}
	approvalRequest, err := approvals.NewRequest(binding, "model summary\x1b]52;c;fake\a\n", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if strings.ContainsAny(approvalRequest.Display, "\x1b\a") || !strings.Contains(approvalRequest.Display, "<U+001B>") {
		t.Fatalf("unsafe Trusted Approval display=%q", approvalRequest.Display)
	}
	grant, err := approvals.Confirm(approvalRequest.Nonce, binding)
	if err != nil {
		t.Fatal(err)
	}
	applied, err := hostapply.Apply(hostapply.Config{
		Store: first.Store, ProjectRoot: projectRoot, ProjectID: active.ProjectID, MergedRoot: result.MergedRoot,
		Baseline: active.Baseline, Merged: result.Merged, ChangeSet: result.ChangeSet,
		Approvals: approvals, Grant: grant, Audit: first.Audit,
	})
	if err != nil || applied.Digest != result.Merged.Digest {
		t.Fatalf("approved actual apply digest=%s error=%v", applied.Digest, err)
	}
	assertIntegrationFile(t, filepath.Join(projectRoot, "modify.txt"), "after\n")
	assertIntegrationFile(t, filepath.Join(projectRoot, "model-edit.txt"), "created by model\n")
	assertIntegrationFile(t, filepath.Join(projectRoot, ".git", "config"), "host-only\n")
	if _, err := os.Lstat(filepath.Join(projectRoot, "delete.txt")); !os.IsNotExist(err) {
		t.Fatalf("approved delete was not applied: %v", err)
	}
	auditLogs, err := filepath.Glob(filepath.Join(runtimeBase, "state", "audit", state.ProjectID(projectRoot), "audit-*.jsonl"))
	if err != nil || len(auditLogs) != 1 {
		t.Fatalf("host audit logs=%v error=%v", auditLogs, err)
	}
	auditBytes, err := os.ReadFile(auditLogs[0])
	if err != nil {
		t.Fatal(err)
	}
	for _, action := range []string{"capability.issued", "session.paused", "session.resumed", "model.request", "changeset.created", "capability.revoked", "vm.destroyed", "approval.request", "approval.confirm", "approval.consume", "changeset.apply"} {
		if !strings.Contains(string(auditBytes), `"action":"`+action+`"`) {
			t.Fatalf("actual host audit missing %q", action)
		}
	}
	if strings.Contains(string(auditBytes), upstreamKey) || strings.Contains(string(auditBytes), first.ModelToken) || strings.Contains(string(auditBytes), first.ServerPassword) {
		t.Fatal("actual host audit contained a session or upstream secret")
	}
	select {
	case err := <-auditErrors:
		t.Fatalf("Model Gateway audit append failed: %v", err)
	default:
	}
}

func writeResponsesFunctionCallStream(w http.ResponseWriter, modelID, name, arguments string) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	item := map[string]any{
		"id": "fc_sunaba", "type": "function_call", "status": "completed",
		"call_id": "call_sunaba", "name": name, "arguments": arguments,
	}
	response := map[string]any{
		"id": "resp_tool_sunaba", "object": "response", "created_at": time.Now().Unix(), "status": "completed",
		"background": false, "error": nil, "incomplete_details": nil, "instructions": nil,
		"max_output_tokens": nil, "max_tool_calls": nil, "model": modelID, "output": []any{item},
		"parallel_tool_calls": true, "previous_response_id": nil, "prompt_cache_key": nil,
		"reasoning": map[string]any{"effort": nil, "summary": nil}, "safety_identifier": nil,
		"service_tier": "default", "store": false, "temperature": 1,
		"text":        map[string]any{"format": map[string]any{"type": "text"}, "verbosity": "medium"},
		"tool_choice": "auto", "tools": []any{}, "top_logprobs": 0, "top_p": 1, "truncation": "disabled",
		"usage": map[string]any{
			"input_tokens": 8, "input_tokens_details": map[string]any{"cached_tokens": 0},
			"output_tokens": 4, "output_tokens_details": map[string]any{"reasoning_tokens": 0}, "total_tokens": 12,
		},
	}
	inProgress := map[string]any{"id": "fc_sunaba", "type": "function_call", "status": "in_progress", "call_id": "call_sunaba", "name": name, "arguments": ""}
	events := []map[string]any{
		{"type": "response.created", "sequence_number": 0, "response": map[string]any{
			"id": "resp_tool_sunaba", "object": "response", "created_at": time.Now().Unix(), "status": "in_progress",
			"error": nil, "incomplete_details": nil, "instructions": nil, "model": modelID, "output": []any{},
			"parallel_tool_calls": true, "reasoning": map[string]any{"effort": nil, "summary": nil}, "store": false,
			"temperature": 1, "text": map[string]any{"format": map[string]any{"type": "text"}}, "tool_choice": "auto",
			"tools": []any{}, "top_p": 1, "truncation": "disabled", "usage": nil,
		}},
		{"type": "response.output_item.added", "sequence_number": 1, "output_index": 0, "item": inProgress},
		{"type": "response.function_call_arguments.delta", "sequence_number": 2, "item_id": "fc_sunaba", "output_index": 0, "delta": arguments},
		{"type": "response.function_call_arguments.done", "sequence_number": 3, "item_id": "fc_sunaba", "output_index": 0, "name": name, "arguments": arguments},
		{"type": "response.output_item.done", "sequence_number": 4, "output_index": 0, "item": item},
		{"type": "response.completed", "sequence_number": 5, "response": response},
	}
	flusher, _ := w.(http.Flusher)
	for _, event := range events {
		_, _ = fmt.Fprintf(w, "event: %s\n", event["type"])
		_, _ = io.WriteString(w, "data: ")
		_ = json.NewEncoder(w).Encode(event)
		_, _ = io.WriteString(w, "\n")
		if flusher != nil {
			flusher.Flush()
		}
	}
}

func assertIntegrationFile(t *testing.T, filename, expected string) {
	t.Helper()
	content, err := os.ReadFile(filename)
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != expected {
		t.Fatalf("%s=%q, want %q", filename, content, expected)
	}
}
