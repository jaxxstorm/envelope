package tailnet

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jaxxstorm/envelope/internal/controller/config"
	"github.com/jaxxstorm/envelope/internal/controller/model"
)

func TestTSNetNodeUsesPrivatePersistentIdentityConfiguration(t *testing.T) {
	stateDir := "/var/lib/envelope-controller/controller-a"
	authKey := "fixture-embedded-auth-secret"
	controlURL := "https://control.example.com"
	node := newTSNetNode(stateDir, "controller-a", authKey, controlURL)
	server := node.server
	if server.Dir != stateDir || server.Hostname != "controller-a" || server.ControlURL != controlURL || server.AuthKey != authKey {
		t.Fatalf("tsnet server configuration = Dir %q, Hostname %q, ControlURL %q", server.Dir, server.Hostname, server.ControlURL)
	}
	if server.Ephemeral || server.RunWebClient {
		t.Fatal("tsnet observer must use persistent state without the web client")
	}
	if server.UserLogf == nil || server.Logf == nil {
		t.Fatal("tsnet log functions must be explicitly silenced")
	}
	server.UserLogf("secret: %s", authKey)
	server.Logf("secret: %s", authKey)

	withoutControl := newTSNetNode(stateDir, "controller-a", authKey, "")
	if withoutControl.server.ControlURL != "" {
		t.Fatalf("optional control URL = %q, want empty", withoutControl.server.ControlURL)
	}
}

func TestPreparePrivateStateDir(t *testing.T) {
	baseDir := t.TempDir()
	stateDir := filepath.Join(baseDir, "controller-a")
	if err := os.Mkdir(stateDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := preparePrivateStateDir(stateDir); err != nil {
		t.Fatalf("preparePrivateStateDir() error = %v", err)
	}
	info, err := os.Stat(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o700 {
		t.Fatalf("state directory permissions = %o, want 700", info.Mode().Perm())
	}

	nested := filepath.Join(baseDir, "nested", "controller-b")
	if err := preparePrivateStateDir(nested); err != nil {
		t.Fatalf("preparePrivateStateDir(nested) error = %v", err)
	}
	info, err = os.Stat(nested)
	if err != nil || info.Mode().Perm() != 0o700 {
		t.Fatalf("nested state directory = %#v, %v", info, err)
	}
}

func TestPreparePrivateStateDirRejectsNonDirectoryAndSymlink(t *testing.T) {
	baseDir := t.TempDir()
	filePath := filepath.Join(baseDir, "state-file")
	if err := os.WriteFile(filePath, []byte("not state"), 0o600); err != nil {
		t.Fatal(err)
	}
	requireErrorIs(t, preparePrivateStateDir(filePath), ErrStateDirectory)

	target := filepath.Join(baseDir, "target")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	symlink := filepath.Join(baseDir, "state-link")
	if err := os.Symlink(target, symlink); err != nil {
		t.Fatal(err)
	}
	requireErrorIs(t, preparePrivateStateDir(symlink), ErrStateDirectory)
}

func TestTailnetConfigProducesDistinctControllerStateDirectories(t *testing.T) {
	tailnetConfig := testTailnetConfig(t)
	first, err := tailnetConfig.StateDirForController("controller-a")
	if err != nil {
		t.Fatal(err)
	}
	second, err := tailnetConfig.StateDirForController("controller-b")
	if err != nil {
		t.Fatal(err)
	}
	if first == second || filepath.Dir(first) != tailnetConfig.StateBaseDir || filepath.Dir(second) != tailnetConfig.StateBaseDir {
		t.Fatalf("controller state directories = %q and %q", first, second)
	}
}

func TestNewRejectsResolvedKeyAndAuthorityErrorsWithoutReturningSecrets(t *testing.T) {
	tsnetSecret := "fixture-constructor-auth-secret"
	adminSecret := "fixture-constructor-api-secret"
	tests := []struct {
		name        string
		tsnetKey    string
		adminKey    string
		authorities func() []model.DomainAuthority
	}{
		{name: "empty tsnet key", adminKey: adminSecret, authorities: testAuthorities},
		{name: "whitespace tsnet key", tsnetKey: " " + tsnetSecret, adminKey: adminSecret, authorities: testAuthorities},
		{name: "empty admin key", tsnetKey: tsnetSecret, authorities: testAuthorities},
		{name: "whitespace admin key", tsnetKey: tsnetSecret, adminKey: adminSecret + " ", authorities: testAuthorities},
		{name: "invalid authority", tsnetKey: tsnetSecret, adminKey: adminSecret, authorities: func() []model.DomainAuthority {
			authorities := testAuthorities()
			authorities[0].TopologyHash = "invalid"
			return authorities
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			tailnetConfig := testTailnetConfig(t)
			observer, err := New(context.Background(), tailnetConfig, "controller-a", test.authorities(), test.tsnetKey, test.adminKey, testOptions())
			if observer != nil || !errors.Is(err, ErrInvalidConfiguration) {
				t.Fatalf("New() = %#v, %v", observer, err)
			}
			if strings.Contains(err.Error(), tsnetSecret) || strings.Contains(err.Error(), adminSecret) {
				t.Fatal("New() returned a resolved secret")
			}
			if _, statErr := os.Stat(filepath.Join(tailnetConfig.StateBaseDir, "controller-a")); !os.IsNotExist(statErr) {
				t.Fatalf("New() touched state before validating inputs: %v", statErr)
			}
		})
	}
}

func testTailnetConfig(t *testing.T) config.TailnetConfig {
	t.Helper()
	return config.TailnetConfig{
		Name:            "example.com",
		ControlURL:      "https://control.example.com",
		TSNetAuthKeyEnv: "ENVELOPE_TS_AUTH_KEY",
		AdminAPIKeyEnv:  "ENVELOPE_TS_ADMIN_API_KEY",
		StateBaseDir:    t.TempDir(),
	}
}
