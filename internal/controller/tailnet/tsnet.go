package tailnet

import (
	"context"
	"os"
	"time"

	"github.com/jaxxstorm/envelope/internal/controller/config"
	"github.com/jaxxstorm/envelope/internal/controller/model"
	"tailscale.com/tsnet"
)

type tsnetNode struct {
	server *tsnet.Server
}

func newTSNetNode(stateDir, controllerID, authKey, controlURL string) *tsnetNode {
	discardLog := func(string, ...any) {}
	return &tsnetNode{server: &tsnet.Server{
		Dir:        stateDir,
		Hostname:   controllerID,
		AuthKey:    authKey,
		ControlURL: controlURL,
		Ephemeral:  false,
		UserLogf:   discardLog,
		Logf:       discardLog,
	}}
}

func (n *tsnetNode) start(ctx context.Context) (localStatusClient, error) {
	if _, err := n.server.Up(ctx); err != nil {
		return nil, err
	}
	return n.server.LocalClient()
}

func (n *tsnetNode) close() error {
	return n.server.Close()
}

// New starts a persistent embedded tsnet observer. The two key arguments must
// already be resolved from TailnetConfig's environment references; New never
// resolves, logs, or includes either value in an error.
func New(
	ctx context.Context,
	tailnetConfig config.TailnetConfig,
	controllerID string,
	authorities []model.DomainAuthority,
	tsnetAuthKey string,
	adminAPIKey string,
	options Options,
) (*Observer, error) {
	if ctx == nil || tailnetConfig.Validate() != nil || options.validate() != nil || !validSecretArgument(tsnetAuthKey) || !validSecretArgument(adminAPIKey) {
		return nil, ErrInvalidConfiguration
	}
	plan, err := buildObservationPlan(controllerID, tailnetConfig.Name, authorities)
	if err != nil {
		return nil, err
	}
	stateDir, err := tailnetConfig.StateDirForController(controllerID)
	if err != nil {
		return nil, ErrInvalidConfiguration
	}
	if err := preparePrivateStateDir(stateDir); err != nil {
		return nil, err
	}

	node := newTSNetNode(stateDir, controllerID, tsnetAuthKey, tailnetConfig.ControlURL)
	httpClient := boundedAdminHTTPClient(options.SnapshotTimeout)
	admin, err := newAdminHTTPClient(defaultAdminAPIBase, tailnetConfig.Name, adminAPIKey, httpClient)
	if err != nil {
		return nil, err
	}
	return newStartedObserver(ctx, plan, options, node, admin, time.Now)
}

func preparePrivateStateDir(stateDir string) error {
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return ErrStateDirectory
	}
	info, err := os.Lstat(stateDir)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return ErrStateDirectory
	}
	if err := os.Chmod(stateDir, 0o700); err != nil {
		return ErrStateDirectory
	}
	info, err = os.Stat(stateDir)
	if err != nil || info.Mode().Perm() != 0o700 {
		return ErrStateDirectory
	}
	return nil
}
