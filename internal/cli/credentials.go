package cli

import (
	"context"
	"fmt"

	"sunaba/internal/openauth"
	"sunaba/internal/secretstore"
)

func (a *app) credentials(ctx context.Context, auth, action string) error {
	switch auth + "/" + action {
	case "api-key/set":
		fmt.Fprintln(a.errors, "Enter the OpenAI API key at the macOS Keychain prompt. The value is not passed in argv or stored by sunaba.")
		if err := secretstore.StoreOpenAIKeyInteractively(ctx, a.input, a.output, a.errors); err != nil {
			return err
		}
		fmt.Fprintln(a.output, "Stored the OpenAI credential in the macOS Keychain for the host Model Gateway.")
		return nil
	case "api-key/status":
		if err := secretstore.OpenAIKeyExists(ctx); err != nil {
			return err
		}
		fmt.Fprintln(a.output, "OpenAI credential is configured in the macOS Keychain.")
		return nil
	case "api-key/delete":
		if err := secretstore.DeleteOpenAIKey(ctx); err != nil {
			return err
		}
		fmt.Fprintln(a.output, "Deleted the OpenAI credential from the macOS Keychain.")
		fmt.Fprintln(a.errors, "Existing Project supervisors may retain an already loaded credential until changes export or destroy ends them.")
		return nil
	case "oauth/login":
		manager := openauth.NewManager()
		if err := manager.Login(ctx, a.output); err != nil {
			return err
		}
		fmt.Fprintln(a.output, "Stored the Codex OAuth credential in the macOS Keychain for the host Model Gateway.")
		return nil
	case "oauth/status":
		if err := secretstore.CodexOAuthExists(ctx); err != nil {
			return err
		}
		fmt.Fprintln(a.output, "Codex OAuth credential is configured in the macOS Keychain.")
		return nil
	case "oauth/delete":
		if err := secretstore.DeleteCodexOAuth(ctx); err != nil {
			return err
		}
		fmt.Fprintln(a.output, "Deleted the Codex OAuth credential from the macOS Keychain.")
		fmt.Fprintln(a.errors, "Existing Project supervisors may retain an already loaded access token until changes export or destroy ends them.")
		return nil
	default:
		return fmt.Errorf("unknown OpenAI credential action %q for %q authentication", action, auth)
	}
}
