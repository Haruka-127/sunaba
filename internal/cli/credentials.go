package cli

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"

	"golang.org/x/sys/unix"

	"sunaba/internal/openauth"
	"sunaba/internal/secretstore"
)

const maximumAPIKeyInputBytes = 32 << 10

func (a *app) credentials(ctx context.Context, auth, action string) error {
	switch auth + "/" + action {
	case "api-key/set":
		key, err := readOpenAIKey(a.input, a.errors)
		if err != nil {
			return err
		}
		if err := secretstore.StoreOpenAIKey(ctx, key); err != nil {
			return err
		}
		fmt.Fprintln(a.output, "Stored the OpenAI API key in the host credential file for the Model Gateway.")
		return nil
	case "api-key/status":
		if err := secretstore.OpenAIKeyExists(ctx); err != nil {
			return err
		}
		fmt.Fprintln(a.output, "OpenAI API key is configured.")
		return nil
	case "api-key/delete":
		if err := secretstore.DeleteOpenAIKey(ctx); err != nil {
			return err
		}
		fmt.Fprintln(a.output, "Deleted the OpenAI API key from the host credential file.")
		fmt.Fprintln(a.errors, "Existing Project supervisors may retain an already loaded credential until changes export or destroy ends them.")
		return nil
	case "oauth/login":
		manager := openauth.NewManager()
		if err := manager.Login(ctx, a.output); err != nil {
			return err
		}
		fmt.Fprintln(a.output, "Stored the Codex OAuth credential in the host credential file for the Model Gateway.")
		return nil
	case "oauth/status":
		if err := secretstore.CodexOAuthExists(ctx); err != nil {
			return err
		}
		fmt.Fprintln(a.output, "Codex OAuth credential is configured.")
		return nil
	case "oauth/delete":
		if err := secretstore.DeleteCodexOAuth(ctx); err != nil {
			return err
		}
		fmt.Fprintln(a.output, "Deleted the Codex OAuth credential from the host credential file.")
		fmt.Fprintln(a.errors, "Existing Project supervisors may retain an already loaded access token until changes export or destroy ends them.")
		return nil
	default:
		return fmt.Errorf("unknown OpenAI credential action %q for %q authentication", action, auth)
	}
}

func readOpenAIKey(input io.Reader, prompt io.Writer) (string, error) {
	fmt.Fprint(prompt, "Enter the OpenAI API key: ")
	if file, ok := input.(*os.File); ok {
		termios, err := unix.IoctlGetTermios(int(file.Fd()), unix.TIOCGETA)
		if err == nil {
			withoutEcho := *termios
			withoutEcho.Lflag &^= unix.ECHO
			if err := unix.IoctlSetTermios(int(file.Fd()), unix.TIOCSETA, &withoutEcho); err != nil {
				return "", fmt.Errorf("disable terminal echo for OpenAI API key input")
			}
			line, readErr := readSingleLine(file)
			restoreErr := unix.IoctlSetTermios(int(file.Fd()), unix.TIOCSETA, termios)
			fmt.Fprintln(prompt)
			if readErr != nil {
				return "", readErr
			}
			if restoreErr != nil {
				return "", fmt.Errorf("restore terminal after OpenAI API key input")
			}
			return validateOpenAIKeyInput(line)
		}
	}
	data, err := io.ReadAll(io.LimitReader(input, maximumAPIKeyInputBytes+2))
	if err != nil {
		return "", fmt.Errorf("read OpenAI API key input")
	}
	if len(data) > maximumAPIKeyInputBytes+1 {
		return "", fmt.Errorf("OpenAI API key input exceeds its size limit")
	}
	if len(data) > 0 && data[len(data)-1] == '\n' {
		data = data[:len(data)-1]
	}
	if bytes.ContainsRune(data, '\n') {
		return "", fmt.Errorf("OpenAI API key input must contain exactly one line")
	}
	return validateOpenAIKeyInput(data)
}

func readSingleLine(reader io.Reader) ([]byte, error) {
	line := make([]byte, 0, 128)
	buffer := make([]byte, 1)
	for {
		read, err := reader.Read(buffer)
		if read == 1 {
			if buffer[0] == '\n' {
				return line, nil
			}
			line = append(line, buffer[0])
			if len(line) > maximumAPIKeyInputBytes {
				return nil, fmt.Errorf("OpenAI API key input exceeds its size limit")
			}
		}
		if err != nil {
			if errors.Is(err, io.EOF) && len(line) > 0 {
				return line, nil
			}
			return nil, fmt.Errorf("read OpenAI API key input")
		}
		if read == 0 {
			return nil, fmt.Errorf("read OpenAI API key input")
		}
	}
}

func validateOpenAIKeyInput(data []byte) (string, error) {
	if len(data) < 20 || len(data) > maximumAPIKeyInputBytes {
		return "", fmt.Errorf("OpenAI API key input is invalid")
	}
	for _, value := range data {
		if value < 0x21 || value > 0x7e {
			return "", fmt.Errorf("OpenAI API key input is invalid")
		}
	}
	return string(data), nil
}
