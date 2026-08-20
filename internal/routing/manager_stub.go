//go:build !linux

package routing

import (
	"context"
	"errors"
)

type unsupportedOps struct{}

func newSystemOps() systemOps { return &unsupportedOps{} }
func unsupported() error      { return errors.New("routing operations are only supported on linux") }

func (*unsupportedOps) InterfaceInfo(string) (interfaceInfo, error) {
	return interfaceInfo{}, unsupported()
}
func (*unsupportedOps) SysctlValue(string) (int, error)   { return 0, unsupported() }
func (*unsupportedOps) AcquireLock() (routingLock, error) { return nil, unsupported() }
func (*unsupportedOps) RuleState(context.Context, string, int, string, string, int, int) (objectState, error) {
	return stateAbsent, unsupported()
}
func (*unsupportedOps) AddRule(context.Context, string, int, string, string, int, int) error {
	return unsupported()
}
func (*unsupportedOps) DeleteRule(context.Context, string, int, string, string, int, int) error {
	return unsupported()
}
func (*unsupportedOps) RouteState(context.Context, string, int, string, string, int) (objectState, error) {
	return stateAbsent, unsupported()
}
func (*unsupportedOps) AddRoute(context.Context, string, int, string, string, int) error {
	return unsupported()
}
func (*unsupportedOps) DeleteRoute(context.Context, string, int, string, string, int) error {
	return unsupported()
}
func (*unsupportedOps) RouteLookup(context.Context, routeQuery) (routeResult, error) {
	return routeResult{}, unsupported()
}
func (*unsupportedOps) Rules(context.Context, string) ([]policyRule, error) {
	return nil, unsupported()
}
func (*unsupportedOps) Routes(context.Context, string, int) ([]routeEntry, error) {
	return nil, unsupported()
}
func (*unsupportedOps) TailscaleStatus(context.Context) (tailscaleStatus, error) {
	return tailscaleStatus{}, unsupported()
}
func (*unsupportedOps) TailscalePing(context.Context, string) error { return unsupported() }
func (*unsupportedOps) ValidateFirewall(context.Context, []forwardingPathContract) error {
	return unsupported()
}
