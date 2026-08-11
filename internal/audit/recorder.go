package audit

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"golang.org/x/sys/unix"
)

const maxRecordBytes = 64 << 10

var auditFieldPattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}$`)

var forbiddenDetailKeys = map[string]struct{}{
	"api_key": {}, "authorization": {}, "body": {}, "content": {}, "password": {}, "prompt": {}, "token": {},
}

type BoundaryEvent struct {
	Version   int               `json:"version"`
	At        time.Time         `json:"at"`
	Category  string            `json:"category"`
	Action    string            `json:"action"`
	Outcome   string            `json:"outcome"`
	ProjectID string            `json:"project_id"`
	VMID      string            `json:"vm_id,omitempty"`
	SessionID string            `json:"session_id,omitempty"`
	Details   map[string]string `json:"details,omitempty"`
}

type Recorder struct {
	Root string
	Now  func() time.Time
}

func NewRecorder(root string) (*Recorder, error) {
	recorder := &Recorder{Root: root}
	if err := recorder.ensureRoot(); err != nil {
		return nil, err
	}
	return recorder, nil
}

func (r *Recorder) Append(event BoundaryEvent) error {
	if err := r.ensureRoot(); err != nil {
		return err
	}
	if err := validateBoundaryEvent(event); err != nil {
		return err
	}
	if event.At.IsZero() {
		event.At = r.now().UTC()
	} else {
		event.At = event.At.UTC()
	}
	event.Version = 1
	if len(event.Details) > 0 {
		sanitized := make(map[string]string, len(event.Details))
		for key, value := range event.Details {
			if _, forbidden := forbiddenDetailKeys[strings.ToLower(key)]; forbidden {
				return fmt.Errorf("audit detail key %q may contain sensitive content", key)
			}
			value = sanitizeText(value)
			if len(value) > 4096 {
				value = value[:4096] + "<TRUNCATED>"
			}
			sanitized[key] = value
		}
		event.Details = sanitized
	}
	encoded, err := json.Marshal(event)
	if err != nil {
		return err
	}
	if len(encoded) > maxRecordBytes {
		return fmt.Errorf("audit record exceeds size limit")
	}
	projectDir := filepath.Join(r.Root, event.ProjectID)
	if err := ensurePrivateDirectory(projectDir); err != nil {
		return err
	}
	filename := filepath.Join(projectDir, "audit-"+event.At.Format("20060102")+".jsonl")
	return appendDurable(filename, append(encoded, '\n'))
}

func sanitizeText(value string) string {
	var output strings.Builder
	for len(value) > 0 {
		r, size := utf8.DecodeRuneInString(value)
		if r == utf8.RuneError && size == 1 {
			output.WriteString("<INVALID-UTF8>")
			value = value[1:]
			continue
		}
		if r == '\n' || r == '\r' || r == '\t' || r == 0x1b || r == 0x7f || (r >= 0 && r < 0x20) || (r >= 0x80 && r <= 0x9f) || r == 0x200e || r == 0x200f || (r >= 0x202a && r <= 0x202e) || (r >= 0x2066 && r <= 0x2069) {
			fmt.Fprintf(&output, "<U+%04X>", r)
		} else {
			output.WriteRune(r)
		}
		value = value[size:]
	}
	return output.String()
}

func (r *Recorder) ensureRoot() error {
	if r == nil || !filepath.IsAbs(r.Root) {
		return fmt.Errorf("audit root must be absolute")
	}
	return ensurePrivateDirectory(r.Root)
}

func (r *Recorder) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now()
}

func validateBoundaryEvent(event BoundaryEvent) error {
	if !auditFieldPattern.MatchString(event.Category) || !auditFieldPattern.MatchString(event.Action) || !auditFieldPattern.MatchString(event.Outcome) || !auditFieldPattern.MatchString(event.ProjectID) {
		return fmt.Errorf("audit event has an invalid required field")
	}
	if event.VMID != "" && !auditFieldPattern.MatchString(event.VMID) {
		return fmt.Errorf("audit event has an invalid VM identity")
	}
	if event.SessionID != "" && !auditFieldPattern.MatchString(event.SessionID) {
		return fmt.Errorf("audit event has an invalid session identity")
	}
	if len(event.Details) > 32 {
		return fmt.Errorf("audit event has too many details")
	}
	for key := range event.Details {
		if !auditFieldPattern.MatchString(key) {
			return fmt.Errorf("audit event has an invalid detail key")
		}
	}
	return nil
}

func ensurePrivateDirectory(path string) error {
	if err := os.MkdirAll(path, 0700); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	var stat unix.Stat_t
	statErr := unix.Lstat(path, &stat)
	if err != nil || statErr != nil || !info.IsDir() || info.Mode().Perm() != 0700 || stat.Uid != uint32(os.Geteuid()) {
		return fmt.Errorf("audit directory must be mode 0700 and owned by the current user")
	}
	return nil
}

func appendDurable(filename string, encoded []byte) error {
	fd, err := unix.Open(filename, unix.O_WRONLY|unix.O_APPEND|unix.O_CREAT|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0600)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return err
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Mode&0777 != 0600 || stat.Uid != uint32(os.Geteuid()) {
		return fmt.Errorf("audit log must be a mode 0600 regular file owned by the current user")
	}
	if err := unix.Flock(fd, unix.LOCK_EX); err != nil {
		return err
	}
	defer unix.Flock(fd, unix.LOCK_UN)
	for len(encoded) > 0 {
		written, err := unix.Write(fd, encoded)
		if err != nil {
			return err
		}
		if written == 0 {
			return errors.New("audit append made no progress")
		}
		encoded = encoded[written:]
	}
	return unix.Fsync(fd)
}
