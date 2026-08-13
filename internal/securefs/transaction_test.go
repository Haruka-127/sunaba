package securefs

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestWriteTransactionRollsBackEveryReplaceBoundary(t *testing.T) {
	for failAt := 0; failAt < 3; failAt++ {
		t.Run(string(rune('0'+failAt)), func(t *testing.T) {
			root := privateTempDir(t)
			journal := filepath.Join(root, "transaction.json")
			replacements := make([]Replacement, 3)
			for index := range replacements {
				path := filepath.Join(root, string(rune('a'+index))+".json")
				if err := os.WriteFile(path, []byte("old"), 0600); err != nil {
					t.Fatal(err)
				}
				replacements[index] = Replacement{Path: path, Data: []byte("new"), MaximumBytes: 16}
			}
			err := WriteTransaction(journal, replacements, TransactionOptions{BeforeReplace: func(index int, _ string) error {
				if index == failAt {
					return errors.New("injected replace failure")
				}
				return nil
			}})
			if err == nil {
				t.Fatal("injected transaction failure was ignored")
			}
			for _, replacement := range replacements {
				data, readErr := os.ReadFile(replacement.Path)
				if readErr != nil || string(data) != "old" {
					t.Fatalf("rollback target %s=%q error=%v", replacement.Path, data, readErr)
				}
			}
			if _, err := os.Lstat(journal); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("transaction journal survived rollback: %v", err)
			}
		})
	}
}

func TestWriteTransactionRemovesNewTargetsAtEveryReplaceBoundary(t *testing.T) {
	for failAt := 0; failAt < 3; failAt++ {
		t.Run(string(rune('0'+failAt)), func(t *testing.T) {
			root := privateTempDir(t)
			journal := filepath.Join(root, "transaction.json")
			replacements := make([]Replacement, 3)
			for index := range replacements {
				replacements[index] = Replacement{Path: filepath.Join(root, string(rune('a'+index))+".json"), Data: []byte("new"), MaximumBytes: 16}
			}
			err := WriteTransaction(journal, replacements, TransactionOptions{BeforeReplace: func(index int, _ string) error {
				if index == failAt {
					return errors.New("injected replace failure")
				}
				return nil
			}})
			if err == nil {
				t.Fatal("injected transaction failure was ignored")
			}
			for _, replacement := range replacements {
				if _, err := os.Lstat(replacement.Path); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("new transaction target survived rollback: %s error=%v", replacement.Path, err)
				}
			}
		})
	}
}

func TestRecoverTransactionFinishesInterruptedCommit(t *testing.T) {
	root := privateTempDir(t)
	journalPath := filepath.Join(root, "transaction.json")
	targets := []string{filepath.Join(root, "a"), filepath.Join(root, "b")}
	journal := transactionJournal{Version: 1, State: "committing"}
	for index, target := range targets {
		if err := os.WriteFile(target, []byte("old"), 0600); err != nil {
			t.Fatal(err)
		}
		temporary := filepath.Join(root, ".sunaba-transaction-new-"+string(rune('a'+index)))
		backup := filepath.Join(root, ".sunaba-transaction-old-"+string(rune('a'+index)))
		if err := os.WriteFile(temporary, []byte("new"), 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(backup, []byte("old"), 0600); err != nil {
			t.Fatal(err)
		}
		journal.Replacements = append(journal.Replacements, transactionReplacement{
			Path: target, Temporary: temporary, Backup: backup, Existed: true,
			OldSHA256: digestBytes([]byte("old")), NewSHA256: digestBytes([]byte("new")), MaximumBytes: 16,
		})
	}
	if err := os.Rename(journal.Replacements[0].Temporary, journal.Replacements[0].Path); err != nil {
		t.Fatal(err)
	}
	if err := writeTransactionJournal(journalPath, journal); err != nil {
		t.Fatal(err)
	}
	if err := RecoverTransaction(journalPath); err != nil {
		t.Fatal(err)
	}
	for _, target := range targets {
		data, err := os.ReadFile(target)
		if err != nil || string(data) != "new" {
			t.Fatalf("recovered target %s=%q error=%v", target, data, err)
		}
	}
}
