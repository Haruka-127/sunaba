package main

import (
	"fmt"
	"os"

	"sunaba/internal/gitgateway"
)

func main() {
	err := gitgateway.RunPreReceiveHook(
		os.Getenv("SUNABA_GIT_HOOK_SOCKET"),
		os.Getenv("SUNABA_GIT_HOOK_TOKEN"),
		os.Getenv("GIT_OBJECT_DIRECTORY"),
		os.Stdin,
		os.Stderr,
	)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
