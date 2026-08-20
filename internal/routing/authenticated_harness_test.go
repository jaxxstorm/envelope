package routing

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestAuthenticatedHarnessRequiresSecretFiles(t *testing.T) {
	repository, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(filepath.Join(repository, "scripts", "integration_tailscale_two_peer.sh"))
	cmd.Dir = repository
	for _, entry := range os.Environ() {
		if strings.HasPrefix(entry, "TAILSCALE_AUTH_KEY_A_FILE=") ||
			strings.HasPrefix(entry, "TAILSCALE_AUTH_KEY_B_FILE=") ||
			strings.HasPrefix(entry, "ENVELOPE_TAILNET_ROUTES_PREAPPROVED=") {
			continue
		}
		cmd.Env = append(cmd.Env, entry)
	}
	_, err = cmd.CombinedOutput()
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) || exitErr.ExitCode() != 77 {
		t.Fatalf("credential gate exit error=%v, want status 77", err)
	}
}
