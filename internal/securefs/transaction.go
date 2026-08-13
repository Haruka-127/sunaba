package securefs

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const maxTransactionJournalBytes = 1 << 20

type Replacement struct {
	Path         string
	Data         []byte
	MaximumBytes int64
}

type TransactionOptions struct {
	BeforeReplace func(index int, path string) error
}

type transactionJournal struct {
	Version      int                      `json:"version"`
	State        string                   `json:"state"`
	Replacements []transactionReplacement `json:"replacements"`
}

type transactionReplacement struct {
	Path         string `json:"path"`
	Temporary    string `json:"temporary"`
	Backup       string `json:"backup,omitempty"`
	Existed      bool   `json:"existed"`
	OldSHA256    string `json:"old_sha256,omitempty"`
	NewSHA256    string `json:"new_sha256"`
	MaximumBytes int64  `json:"maximum_bytes"`
}

func WriteTransaction(journalPath string, replacements []Replacement, options TransactionOptions) error {
	if len(replacements) < 2 || len(replacements) > 16 || !isCleanAbsolute(journalPath) {
		return fmt.Errorf("private file transaction is invalid")
	}
	if err := RecoverTransaction(journalPath); err != nil {
		return err
	}
	journal := transactionJournal{Version: 1, State: "committing", Replacements: make([]transactionReplacement, len(replacements))}
	failPrepare := func(err error) error { return errors.Join(err, cleanupTransactionArtifacts(journal)) }
	seen := make(map[string]struct{}, len(replacements))
	for index, replacement := range replacements {
		if !isCleanAbsolute(replacement.Path) || replacement.MaximumBytes <= 0 || int64(len(replacement.Data)) > replacement.MaximumBytes || replacement.Path == journalPath {
			return failPrepare(fmt.Errorf("private file transaction replacement is invalid"))
		}
		if _, exists := seen[replacement.Path]; exists {
			return failPrepare(fmt.Errorf("private file transaction contains duplicate targets"))
		}
		seen[replacement.Path] = struct{}{}
		parent := filepath.Dir(replacement.Path)
		if err := CheckOwnedDir(parent); err != nil {
			return failPrepare(err)
		}
		temporary, err := transactionArtifactName(parent, "new")
		if err != nil {
			return failPrepare(err)
		}
		if err := AtomicWriteOwned(temporary, replacement.Data); err != nil {
			return failPrepare(err)
		}
		item := transactionReplacement{
			Path: replacement.Path, Temporary: temporary, NewSHA256: digestBytes(replacement.Data), MaximumBytes: replacement.MaximumBytes,
		}
		journal.Replacements[index] = item
		old, err := ReadOwnedRegular(replacement.Path, replacement.MaximumBytes)
		switch {
		case err == nil:
			item.Existed = true
			item.OldSHA256 = digestBytes(old)
			item.Backup, err = transactionArtifactName(parent, "old")
			if err == nil {
				err = AtomicWriteOwned(item.Backup, old)
			}
		case errors.Is(err, os.ErrNotExist):
			err = nil
		default:
		}
		if err != nil {
			return failPrepare(err)
		}
		journal.Replacements[index] = item
	}
	if err := writeTransactionJournal(journalPath, journal); err != nil {
		return errors.Join(err, cleanupTransactionArtifacts(journal))
	}
	for index, item := range journal.Replacements {
		if options.BeforeReplace != nil {
			if err := options.BeforeReplace(index, item.Path); err != nil {
				return rollbackTransaction(journalPath, journal, err)
			}
		}
		if err := os.Rename(item.Temporary, item.Path); err != nil {
			return rollbackTransaction(journalPath, journal, err)
		}
		if err := SyncDir(filepath.Dir(item.Path)); err != nil {
			return rollbackTransaction(journalPath, journal, err)
		}
	}
	return finishTransaction(journalPath, journal)
}

func RecoverTransaction(journalPath string) error {
	data, err := ReadOwnedRegular(journalPath, maxTransactionJournalBytes)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	var journal transactionJournal
	if DecodeStrictJSON(data, &journal) != nil || validateTransactionJournal(journalPath, journal) != nil {
		return fmt.Errorf("private file transaction journal is invalid")
	}
	if journal.State == "rollback" {
		if err := recoverRollback(journal); err != nil {
			return err
		}
	} else {
		if err := recoverCommit(journal); err != nil {
			return err
		}
	}
	return finishTransaction(journalPath, journal)
}

func rollbackTransaction(journalPath string, journal transactionJournal, cause error) error {
	journal.State = "rollback"
	if err := writeTransactionJournal(journalPath, journal); err != nil {
		return errors.Join(cause, err)
	}
	return errors.Join(cause, RecoverTransaction(journalPath))
}

func recoverCommit(journal transactionJournal) error {
	for _, item := range journal.Replacements {
		if _, err := os.Lstat(item.Temporary); err == nil {
			data, readErr := ReadOwnedRegular(item.Temporary, item.MaximumBytes)
			if readErr != nil || digestBytes(data) != item.NewSHA256 {
				return fmt.Errorf("private file transaction staged content is invalid")
			}
			if err := verifyTransactionTargetBeforeCommit(item); err != nil {
				return err
			}
			if err := os.Rename(item.Temporary, item.Path); err != nil {
				return err
			}
			if err := SyncDir(filepath.Dir(item.Path)); err != nil {
				return err
			}
			continue
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		data, err := ReadOwnedRegular(item.Path, item.MaximumBytes)
		if err != nil || digestBytes(data) != item.NewSHA256 {
			return fmt.Errorf("private file transaction cannot verify committed target")
		}
	}
	return nil
}

func recoverRollback(journal transactionJournal) error {
	for index := len(journal.Replacements) - 1; index >= 0; index-- {
		item := journal.Replacements[index]
		if !item.Existed {
			data, err := ReadOwnedRegular(item.Path, item.MaximumBytes)
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			if err != nil || digestBytes(data) != item.NewSHA256 {
				return fmt.Errorf("private file transaction cannot verify rollback target")
			}
			if err := os.Remove(item.Path); err != nil {
				return err
			}
			if err := SyncDir(filepath.Dir(item.Path)); err != nil {
				return err
			}
			continue
		}
		if _, err := os.Lstat(item.Backup); err == nil {
			data, readErr := ReadOwnedRegular(item.Backup, item.MaximumBytes)
			if readErr != nil || digestBytes(data) != item.OldSHA256 {
				return fmt.Errorf("private file transaction backup is invalid")
			}
			current, readErr := ReadOwnedRegular(item.Path, item.MaximumBytes)
			currentDigest := digestBytes(current)
			if readErr != nil || (currentDigest != item.OldSHA256 && currentDigest != item.NewSHA256) {
				return fmt.Errorf("private file transaction target changed before rollback")
			}
			if err := os.Rename(item.Backup, item.Path); err != nil {
				return err
			}
			if err := SyncDir(filepath.Dir(item.Path)); err != nil {
				return err
			}
			continue
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		data, err := ReadOwnedRegular(item.Path, item.MaximumBytes)
		if err != nil || digestBytes(data) != item.OldSHA256 {
			return fmt.Errorf("private file transaction cannot verify restored target")
		}
	}
	return nil
}

func verifyTransactionTargetBeforeCommit(item transactionReplacement) error {
	data, err := ReadOwnedRegular(item.Path, item.MaximumBytes)
	if !item.Existed && errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil || !item.Existed || digestBytes(data) != item.OldSHA256 {
		return fmt.Errorf("private file transaction target changed before commit")
	}
	return nil
}

func finishTransaction(journalPath string, journal transactionJournal) error {
	cleanupErr := cleanupTransactionArtifacts(journal)
	removeErr := os.Remove(journalPath)
	if errors.Is(removeErr, os.ErrNotExist) {
		removeErr = nil
	}
	directories := map[string]struct{}{filepath.Dir(journalPath): {}}
	for _, item := range journal.Replacements {
		directories[filepath.Dir(item.Path)] = struct{}{}
	}
	var syncErr error
	for directory := range directories {
		syncErr = errors.Join(syncErr, SyncDir(directory))
	}
	return errors.Join(cleanupErr, removeErr, syncErr)
}

func cleanupTransactionArtifacts(journal transactionJournal) error {
	var result error
	for _, item := range journal.Replacements {
		for _, path := range []string{item.Temporary, item.Backup} {
			if path == "" {
				continue
			}
			if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
				result = errors.Join(result, err)
			}
		}
	}
	return result
}

func writeTransactionJournal(path string, journal transactionJournal) error {
	encoded, err := json.Marshal(journal)
	if err != nil || len(encoded) > maxTransactionJournalBytes {
		return fmt.Errorf("encode private file transaction journal")
	}
	return AtomicWriteOwned(path, append(encoded, '\n'))
}

func validateTransactionJournal(journalPath string, journal transactionJournal) error {
	if journal.Version != 1 || (journal.State != "committing" && journal.State != "rollback") || len(journal.Replacements) < 2 || len(journal.Replacements) > 16 {
		return fmt.Errorf("invalid transaction metadata")
	}
	seenTargets := make(map[string]struct{}, len(journal.Replacements))
	seenArtifacts := make(map[string]struct{}, len(journal.Replacements)*2)
	for _, item := range journal.Replacements {
		parent := filepath.Dir(item.Path)
		if !isCleanAbsolute(item.Path) || item.Path == journalPath || item.MaximumBytes <= 0 || !validDigest(item.NewSHA256) || !validTransactionArtifact(item.Temporary, parent, "new") || item.Temporary == item.Path || item.Temporary == journalPath || item.Existed && (!validTransactionArtifact(item.Backup, parent, "old") || !validDigest(item.OldSHA256)) || !item.Existed && (item.Backup != "" || item.OldSHA256 != "") {
			return fmt.Errorf("invalid transaction replacement")
		}
		if _, exists := seenTargets[item.Path]; exists {
			return fmt.Errorf("duplicate transaction target")
		}
		seenTargets[item.Path] = struct{}{}
		for _, artifact := range []string{item.Temporary, item.Backup} {
			if artifact == "" {
				continue
			}
			if _, exists := seenArtifacts[artifact]; exists {
				return fmt.Errorf("duplicate transaction artifact")
			}
			seenArtifacts[artifact] = struct{}{}
		}
	}
	return nil
}

func validTransactionArtifact(path, parent, role string) bool {
	return isCleanAbsolute(path) && filepath.Dir(path) == parent && strings.HasPrefix(filepath.Base(path), ".sunaba-transaction-"+role+"-")
}

func validDigest(value string) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == sha256.Size
}

func transactionArtifactName(parent, role string) (string, error) {
	random := make([]byte, 16)
	if _, err := rand.Read(random); err != nil {
		return "", err
	}
	return filepath.Join(parent, ".sunaba-transaction-"+role+"-"+hex.EncodeToString(random)), nil
}

func digestBytes(data []byte) string {
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:])
}
