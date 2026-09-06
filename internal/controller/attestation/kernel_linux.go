//go:build linux

package attestation

import (
	"context"
	"net"
	"net/netip"
	"os"
	"reflect"
	"sort"
	"strings"

	"github.com/godbus/dbus/v5"
)

type kernelSnapshot struct {
	Rules                                        []policyRule
	Routes                                       []hostRoute
	Firewall                                     map[string]firewallTable
	UnderlayIndex, TunIndex, UnderlayMTU, TunMTU int
}

func inspectKernel(ctx context.Context, local, remote []string, underlayName string, gateway netip.Addr, maximum int) (kernelSnapshot, error) {
	var snapshot kernelSnapshot
	underlay, err := net.InterfaceByName(underlayName)
	if err != nil || underlay.Flags&net.FlagUp == 0 {
		return snapshot, ErrRejected
	}
	tun, err := net.InterfaceByName("tailscale0")
	if err != nil || tun.Flags&net.FlagUp == 0 {
		return snapshot, ErrRejected
	}
	for path, value := range map[string]string{
		"/proc/sys/net/ipv4/ip_forward": "1", "/proc/sys/net/ipv6/conf/all/forwarding": "0", "/proc/sys/net/ipv6/conf/default/forwarding": "0",
		"/proc/sys/net/ipv4/conf/all/rp_filter": "0", "/proc/sys/net/ipv4/conf/default/rp_filter": "0", "/proc/sys/net/ipv4/conf/" + underlayName + "/rp_filter": "0", "/proc/sys/net/ipv4/conf/tailscale0/rp_filter": "0",
	} {
		if !kernelValue(path, value) {
			return snapshot, ErrRejected
		}
	}
	snapshot.Rules, snapshot.Routes, err = readHostRoutes(ctx)
	if err != nil {
		return snapshot, err
	}
	if validateHostRoutes(snapshot.Rules, snapshot.Routes, local, remote, uint32(underlay.Index), uint32(tun.Index), gateway) != nil {
		return snapshot, ErrRejected
	}
	snapshot.Firewall, err = readFirewall(ctx)
	if err != nil {
		return snapshot, err
	}
	if validateFirewall(snapshot.Firewall, local, remote, underlayName, underlay.MTU, tun.MTU, maximum) != nil {
		return snapshot, ErrRejected
	}
	snapshot.UnderlayIndex, snapshot.TunIndex, snapshot.UnderlayMTU, snapshot.TunMTU = underlay.Index, tun.Index, underlay.MTU, tun.MTU
	sort.Slice(snapshot.Rules, func(i, j int) bool { return snapshot.Rules[i].Priority < snapshot.Rules[j].Priority })
	sort.Slice(snapshot.Routes, func(i, j int) bool {
		a, b := snapshot.Routes[i], snapshot.Routes[j]
		if a.Table != b.Table {
			return a.Table < b.Table
		}
		if a.Destination != b.Destination {
			return a.Destination.String() < b.Destination.String()
		}
		if a.Interface != b.Interface {
			return a.Interface < b.Interface
		}
		if a.Gateway != b.Gateway {
			return a.Gateway.String() < b.Gateway.String()
		}
		if a.Type != b.Type {
			return a.Type < b.Type
		}
		return a.Flags < b.Flags
	})
	return snapshot, ctx.Err()
}

func networkServiceReady(ctx context.Context) error {
	connection, err := dbus.ConnectSystemBus(dbus.WithContext(ctx))
	if err != nil {
		return ErrRejected
	}
	defer connection.Close()
	var path dbus.ObjectPath
	if connection.Object("org.freedesktop.systemd1", "/org/freedesktop/systemd1").CallWithContext(ctx, "org.freedesktop.systemd1.Manager.GetUnit", 0, "envelope-transport-router-network.service").Store(&path) != nil {
		return ErrRejected
	}
	unit := connection.Object("org.freedesktop.systemd1", path)
	for property, expected := range map[string]string{"ActiveState": "active", "SubState": "exited", "UnitFileState": "enabled"} {
		var value dbus.Variant
		if unit.CallWithContext(ctx, "org.freedesktop.DBus.Properties.Get", 0, "org.freedesktop.systemd1.Unit", property).Store(&value) != nil || !reflect.DeepEqual(value.Value(), expected) {
			return ErrRejected
		}
	}
	for _, name := range []string{"/var/lib/envelope/transport-router-network.ready", "/var/lib/envelope/transport-router-network.state.json", "/var/lib/envelope/transport-router-network.configured"} {
		info, err := os.Lstat(name)
		if err != nil || !info.Mode().IsRegular() {
			return ErrRejected
		}
	}
	return nil
}

func resolverReady(expected netip.Addr) bool {
	file, err := os.Open("/etc/resolv.conf")
	if err != nil {
		return false
	}
	defer file.Close()
	data, err := readBounded(file, 4096)
	if err != nil {
		return false
	}
	found := false
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 || fields[0] != "nameserver" {
			continue
		}
		if len(fields) != 2 || (fields[1] != expected.String() && fields[1] != "169.254.169.253") {
			return false
		}
		found = true
	}
	return found
}
