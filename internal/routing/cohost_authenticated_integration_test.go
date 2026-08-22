//go:build linux && integration

package routing

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestCohostSymmetricSites(t *testing.T) {
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("requires Docker")
	}
	repository, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatalf("resolve repository root: %v", err)
	}
	script := filepath.Join(repository, "scripts", "integration_headscale_two_peer.sh")
	cmd := exec.Command("bash", script)
	cmd.Dir = repository
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("Headscale symmetric integration: %v\n%s", err, output)
	}
}

func TestSaaSCohostSymmetricSites(t *testing.T) {
	if os.Getenv("TAILSCALE_AUTH_KEY_A_FILE") == "" || os.Getenv("TAILSCALE_AUTH_KEY_B_FILE") == "" || os.Getenv("ENVELOPE_TAILNET_ROUTES_PREAPPROVED") != "1" {
		t.Skip("optional SaaS compatibility test requires two auth-key files and pre-approved routes")
	}
	repository, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatalf("resolve repository root: %v", err)
	}
	cmd := exec.Command("bash", filepath.Join(repository, "scripts", "integration_tailscale_two_peer.sh"))
	cmd.Dir = repository
	for _, entry := range os.Environ() {
		if strings.HasPrefix(entry, "TAILSCALE_AUTH_KEY_A_FILE=") || strings.HasPrefix(entry, "TAILSCALE_AUTH_KEY_B_FILE=") {
			continue
		}
		cmd.Env = append(cmd.Env, entry)
	}
	for _, name := range []string{"TAILSCALE_AUTH_KEY_A_FILE", "TAILSCALE_AUTH_KEY_B_FILE"} {
		path, err := filepath.Abs(os.Getenv(name))
		if err != nil {
			t.Fatalf("resolve %s path: %v", name, err)
		}
		cmd.Env = append(cmd.Env, name+"="+path)
	}
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("optional SaaS symmetric integration: %v\n%s", err, output)
	}
}
