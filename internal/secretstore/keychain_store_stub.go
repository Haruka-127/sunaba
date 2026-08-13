//go:build !darwin || !cgo

package secretstore

import "fmt"

func platformLoadGenericPassword(_, _, _ string) ([]byte, error) {
	return nil, fmt.Errorf("native macOS Keychain storage is unavailable")
}

func platformStoreGenericPassword(_, _, _ string, _ []byte) error {
	return fmt.Errorf("native macOS Keychain storage is unavailable")
}

func platformGenericPasswordExists(_, _, _ string) error {
	return fmt.Errorf("native macOS Keychain storage is unavailable")
}

func platformDeleteGenericPassword(_, _, _ string) error {
	return fmt.Errorf("native macOS Keychain storage is unavailable")
}
