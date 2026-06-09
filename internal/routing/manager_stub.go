//go:build !linux

package routing

import (
	"context"
	"errors"
)

type unsupportedOps struct{}

func newSystemOps() systemOps {
	return &unsupportedOps{}
}

func (u *unsupportedOps) InterfaceExists(string) (bool, error) {
	return false, errors.New("routing operations are only supported on linux")
}

func (u *unsupportedOps) SysctlEnabled(string) (bool, error) {
	return false, errors.New("routing operations are only supported on linux")
}

func (u *unsupportedOps) RuleExists(context.Context, string, int, string, string, int) (bool, error) {
	return false, errors.New("routing operations are only supported on linux")
}

func (u *unsupportedOps) AddRule(context.Context, string, int, string, string, int) error {
	return errors.New("routing operations are only supported on linux")
}

func (u *unsupportedOps) DeleteRule(context.Context, string, int, string, string, int) error {
	return errors.New("routing operations are only supported on linux")
}

func (u *unsupportedOps) RouteExists(context.Context, string, int, string, string) (bool, error) {
	return false, errors.New("routing operations are only supported on linux")
}

func (u *unsupportedOps) AddRoute(context.Context, string, int, string, string) error {
	return errors.New("routing operations are only supported on linux")
}

func (u *unsupportedOps) DeleteRoute(context.Context, string, int, string, string) error {
	return errors.New("routing operations are only supported on linux")
}
