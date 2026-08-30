package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"text/tabwriter"
	"time"

	"golang.org/x/sys/unix"

	"sunaba/internal/policy"
	"sunaba/internal/runtime"
	"sunaba/internal/state"
	"sunaba/internal/trustedui"
)

type projectListRecord struct {
	ProjectID  string `json:"project_id"`
	Mode       string `json:"mode"`
	Supervisor string `json:"supervisor"`
	VM         string `json:"vm"`
	Pending    string `json:"pending"`
	Project    string `json:"project"`
	Detail     string `json:"detail,omitempty"`
	active     bool
}

func (a *app) projectList(ctx context.Context, activeOnly, jsonOutput bool) error {
	states, err := a.store.ListProjectStates()
	if err != nil {
		return err
	}
	if len(states) == 0 {
		return writeProjectList(a.output, nil, jsonOutput)
	}
	containers, runtimeErr := a.runtime.List(ctx)
	if runtimeErr != nil {
		fmt.Fprintf(a.errors, "WARNING: owned VM inventory is unavailable; VM state may be unknown: %s\n", trustedui.SanitizeTerminal(runtimeErr.Error()))
	}
	owned := ownedProjectVMs(containers)
	records := make([]projectListRecord, len(states))
	jobs := make(chan int)
	workerCount := min(12, len(states))
	var workers sync.WaitGroup
	workers.Add(workerCount)
	for range workerCount {
		go func() {
			defer workers.Done()
			for index := range jobs {
				records[index] = a.projectListRecord(ctx, states[index], owned, runtimeErr)
			}
		}()
	}
	for index := range states {
		jobs <- index
	}
	close(jobs)
	workers.Wait()
	if activeOnly {
		filtered := records[:0]
		for _, record := range records {
			if record.active {
				filtered = append(filtered, record)
			}
		}
		records = filtered
	}
	sort.Slice(records, func(i, j int) bool {
		if records[i].Project == records[j].Project {
			return records[i].ProjectID < records[j].ProjectID
		}
		return records[i].Project < records[j].Project
	})
	return writeProjectList(a.output, records, jsonOutput)
}

func (a *app) projectListRecord(ctx context.Context, projectState state.ProjectState, owned map[string][]runtime.Info, runtimeErr error) projectListRecord {
	record := projectListRecord{
		ProjectID: projectState.ProjectID, Mode: "unknown", Supervisor: "none",
		VM: "none", Pending: "no", Project: "unknown",
	}
	if runtimeErr != nil {
		record.VM = "unknown"
	}
	if projectState.Err != nil {
		record.Supervisor = "invalid"
		record.Pending = "invalid"
		record.Detail = projectState.Err.Error()
		return record
	}
	loaded, _, loadErr := policy.LoadReadOnly(filepath.Join(projectState.Path, "policy.json"), time.Now())
	if loadErr != nil || loaded.ProjectID != projectState.ProjectID {
		record.Supervisor = "invalid"
		record.Pending = "invalid"
		record.Detail = "Project policy is invalid"
		return record
	}
	record.Mode = loaded.Mode
	record.Project = loaded.ProjectRoot
	record.Pending = pendingInventoryState(projectState.Path, loaded.ProjectID)
	projectVMs := owned[loaded.ProjectID]
	if runtimeErr == nil {
		record.VM, record.Detail = summarizeOwnedVMs(projectVMs)
	}
	client, clientErr := openSupervisorClient(projectState.Path)
	switch {
	case clientErr == nil:
		queryCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
		info, infoErr := client.info(queryCtx)
		cancel()
		client.close()
		if infoErr != nil {
			record.Supervisor = "unavailable"
			record.Detail = appendInventoryDetail(record.Detail, "Supervisor did not answer")
		} else if info.ProjectID != loaded.ProjectID {
			record.Supervisor = "invalid"
			record.Detail = appendInventoryDetail(record.Detail, "Supervisor Project identity does not match")
		} else {
			record.Supervisor = "active"
			switch info.State {
			case "running", "paused", "failed", "exported", "destroyed":
				record.VM = info.State
			default:
				record.VM = "unknown"
				record.Detail = appendInventoryDetail(record.Detail, "Supervisor returned an unknown VM state")
			}
			record.active = true
		}
	case errors.Is(clientErr, errNoSupervisor):
		record.Supervisor = "none"
	case errors.Is(clientErr, errStaleSupervisor):
		record.Supervisor = "stale"
	default:
		record.Supervisor = "invalid"
		record.Detail = appendInventoryDetail(record.Detail, "Supervisor locator is unsafe")
	}
	for _, item := range projectVMs {
		if item.State == runtime.StateRunning {
			record.active = true
		}
	}
	return record
}

func ownedProjectVMs(containers []runtime.Info) map[string][]runtime.Info {
	owned := make(map[string][]runtime.Info)
	for _, item := range containers {
		projectID := item.Labels["dev.sunaba.project"]
		vmID := item.Labels["dev.sunaba.vm"]
		if item.Labels["dev.sunaba.owner"] != "sunaba-supervisor" || projectID == "" || vmID == "" || item.Name != "sunaba-"+projectID+"-"+vmID {
			continue
		}
		owned[projectID] = append(owned[projectID], item)
	}
	return owned
}

func summarizeOwnedVMs(items []runtime.Info) (string, string) {
	switch len(items) {
	case 0:
		return "none", ""
	case 1:
		state := string(items[0].State)
		if state == "" {
			state = string(runtime.StateUnknown)
		}
		return state, ""
	default:
		return "multiple", "multiple owned VMs require recovery"
	}
}

func pendingInventoryState(projectState, projectID string) string {
	path := filepath.Join(projectState, "pending", "change.json")
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "no"
		}
		return "invalid"
	}
	var stat unix.Stat_t
	if unix.Fstat(fd, &stat) != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Mode&0777 != 0600 || stat.Uid != uint32(os.Geteuid()) || stat.Size <= 0 || stat.Size > 16<<20 {
		_ = unix.Close(fd)
		return "invalid"
	}
	var identity struct {
		Version int `json:"version"`
		WorkSet struct {
			ProjectID string `json:"project_id"`
		} `json:"work_set"`
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		_ = unix.Close(fd)
		return "invalid"
	}
	defer file.Close()
	decoder := json.NewDecoder(io.LimitReader(file, 16<<20))
	if decoder.Decode(&identity) != nil || identity.Version != pendingChangeVersion || identity.WorkSet.ProjectID != projectID {
		return "invalid"
	}
	return "yes"
}

func appendInventoryDetail(existing, addition string) string {
	if existing == "" {
		return addition
	}
	return existing + "; " + addition
}

func writeProjectList(output io.Writer, records []projectListRecord, jsonOutput bool) error {
	if jsonOutput {
		if records == nil {
			records = []projectListRecord{}
		}
		encoder := json.NewEncoder(output)
		encoder.SetEscapeHTML(true)
		return encoder.Encode(records)
	}
	writer := tabwriter.NewWriter(output, 0, 4, 2, ' ', 0)
	if _, err := fmt.Fprintln(writer, "PROJECT ID\tMODE\tSUPERVISOR\tVM\tPENDING\tPROJECT\tDETAIL"); err != nil {
		return err
	}
	for _, record := range records {
		detail := record.Detail
		if detail == "" {
			detail = "-"
		}
		fields := []string{record.ProjectID, record.Mode, record.Supervisor, record.VM, record.Pending, record.Project, detail}
		for index := range fields {
			fields[index] = strings.ReplaceAll(trustedui.SanitizeTerminal(fields[index]), "\n", "<U+000A>")
		}
		if _, err := fmt.Fprintln(writer, strings.Join(fields, "\t")); err != nil {
			return err
		}
	}
	return writer.Flush()
}
