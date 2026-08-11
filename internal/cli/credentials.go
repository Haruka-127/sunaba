package cli

import (
	"context"
	"fmt"

	"sunaba/internal/secretstore"
)

func (a *app) credentials(ctx context.Context, args []string) error {
	if len(args) != 2 || args[0] != "openai" {
		return fmt.Errorf("usage: sunaba credentials openai set|status|delete")
	}
	switch args[1] {
	case "set":
		fmt.Fprintln(a.errors, "Enter the OpenAI API key at the macOS Keychain prompt. The value is not passed in argv or stored by sunaba.")
		if err := secretstore.StoreOpenAIKeyInteractively(ctx, a.input, a.output, a.errors); err != nil {
			return err
		}
		fmt.Fprintln(a.output, "Stored the OpenAI credential in the macOS Keychain for the host Model Gateway.")
		return nil
	case "status":
		if err := secretstore.OpenAIKeyExists(ctx); err != nil {
			return err
		}
		fmt.Fprintln(a.output, "OpenAI credential is configured in the macOS Keychain.")
		return nil
	case "delete":
		if err := secretstore.DeleteOpenAIKey(ctx); err != nil {
			return err
		}
		fmt.Fprintln(a.output, "Deleted the OpenAI credential from the macOS Keychain.")
		fmt.Fprintln(a.errors, "Existing Project supervisors may retain an already loaded credential until changes export or destroy ends them.")
		return nil
	default:
		return fmt.Errorf("usage: sunaba credentials openai set|status|delete")
	}
}
