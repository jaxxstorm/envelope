//go:build !linux

package tun

import "errors"

type Device struct{}

func Open(name string, mtu int) (*Device, error) {
	return nil, errors.New("tun is only supported on linux")
}

func (d *Device) Close() error {
	return nil
}

func (d *Device) Read(_ []byte) (int, error) {
	return 0, errors.New("tun is only supported on linux")
}

func (d *Device) Write(_ []byte) (int, error) {
	return 0, errors.New("tun is only supported on linux")
}
