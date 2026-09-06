//go:build linux && attestorintegration

package attestation

import (
	"context"
	"net/netip"
	"os"
	"os/exec"
	"runtime"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// This is actual Linux kernel inspection with synthetic interfaces/control
// state, not live AWS or Tailscale evidence. Setup commands exist only in tests.
func TestNativeKernelReadiness(t *testing.T) {
	self, err := os.Readlink("/proc/self/ns/net")
	if err != nil {
		t.Fatal(err)
	}
	initial, err := os.Readlink("/proc/1/ns/net")
	if err != nil {
		t.Fatal(err)
	}
	if os.Geteuid() != 0 || os.Getenv("ENVELOPE_ATTESTOR_KERNEL_TEST") != "1" || self == initial {
		t.Fatal("requires explicit root execution in an isolated network namespace")
	}
	command := func(name string, args ...string) {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		output, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
		if err != nil {
			t.Fatalf("fixture %s %v: %v: %s", name, args, err, output)
		}
	}
	command("ip", "link", "set", "lo", "up")
	command("ip", "link", "add", "enva0", "type", "dummy")
	command("ip", "addr", "add", "10.9.0.2/24", "dev", "enva0")
	command("ip", "link", "set", "enva0", "mtu", "9001", "up")
	command("ip", "link", "add", "tailscale0", "type", "dummy")
	command("ip", "link", "set", "tailscale0", "mtu", "1280", "up")
	command("ip", "route", "add", "default", "via", "10.9.0.1", "dev", "enva0")
	command("ip", "route", "add", "10.1.0.0/24", "dev", "tailscale0", "table", "52")
	command("ip", "rule", "add", "priority", "100", "to", "10.0.0.0/24", "lookup", "main")
	for _, rule := range [][]string{{"5210", "lookup", "main"}, {"5230", "lookup", "default"}, {"5250", "unreachable"}} {
		command("ip", append([]string{"rule", "add", "priority", rule[0], "fwmark", "0x80000/0xff0000"}, rule[1:]...)...)
	}
	command("ip", "rule", "add", "priority", "5270", "lookup", "52")
	for _, setting := range []string{"net.ipv4.ip_forward=1", "net.ipv6.conf.all.forwarding=0", "net.ipv6.conf.default.forwarding=0", "net.ipv4.conf.all.rp_filter=0", "net.ipv4.conf.default.rp_filter=0", "net.ipv4.conf.enva0.rp_filter=0", "net.ipv4.conf.tailscale0.rp_filter=0"} {
		command("sysctl", "-qw", setting)
	}
	for _, binary := range []string{"iptables-legacy", "ip6tables-legacy"} {
		command(binary, "-t", "nat", "-S")
		command(binary, "-t", "mangle", "-P", "FORWARD", "ACCEPT")
		command(binary, "-P", "FORWARD", "DROP")
		command(binary, "-N", forwardChain)
		command(binary, "-A", "FORWARD", "-j", forwardChain)
	}
	command("iptables-legacy", "-t", "mangle", "-N", mssChain)
	command("iptables-legacy", "-t", "mangle", "-A", "FORWARD", "-j", mssChain)
	directions := [][]string{{"-i", "enva0", "-o", "tailscale0", "-s", "10.0.0.0/24", "-d", "10.1.0.0/24"}, {"-i", "tailscale0", "-o", "enva0", "-s", "10.1.0.0/24", "-d", "10.0.0.0/24"}}
	for _, direction := range directions {
		command("iptables-legacy", append(append([]string{"-A", forwardChain}, direction...), "-j", "ACCEPT")...)
		command("iptables-legacy", append(append([]string{"-t", "mangle", "-A", mssChain}, direction...), "-p", "tcp", "-m", "tcp", "--tcp-flags", "SYN,RST", "SYN", "-j", "TCPMSS", "--set-mss", "1240")...)
	}
	command("iptables-legacy", "-t", "mangle", "-A", mssChain, "-j", "RETURN")
	command("nft", "list", "ruleset")
	inspect := func(want bool) {
		t.Helper()
		// Prove the inspector itself needs no packet-raw capability. Fixture
		// iptables commands above need NET_RAW; native datagram getsockopt does not.
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		header := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
		var original [2]unix.CapUserData
		if err := unix.Capget(&header, &original[0]); err != nil {
			t.Fatal(err)
		}
		reduced := original
		reduced[0].Effective &^= 1 << unix.CAP_NET_RAW
		if err := unix.Capset(&header, &reduced[0]); err != nil {
			t.Fatal(err)
		}
		defer func() {
			if err := unix.Capset(&header, &original[0]); err != nil {
				t.Fatal(err)
			}
		}()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, err := inspectKernel(ctx, []string{"10.0.0.0/24"}, []string{"10.1.0.0/24"}, "enva0", netip.MustParseAddr("10.9.0.1"), 1240)
		if (err == nil) != want {
			t.Fatalf("native kernel valid=%t: %v", want, err)
		}
	}
	inspect(true)
	command("ip", "route", "add", "blackhole", "10.0.0.64/28")
	inspect(false)
	command("ip", "route", "del", "blackhole", "10.0.0.64/28")
	inspect(true)
	command("ip", "rule", "add", "priority", "90", "from", "10.1.0.0/24", "lookup", "52")
	inspect(false)
	command("ip", "rule", "del", "priority", "90")
	inspect(true)
	command("ip", "route", "replace", "10.1.0.0/24", "dev", "enva0", "table", "52")
	inspect(false)
	command("ip", "route", "replace", "10.1.0.0/24", "dev", "tailscale0", "table", "52")
	inspect(true)
	command("iptables-legacy", "-t", "nat", "-A", "POSTROUTING", "-j", "MASQUERADE")
	inspect(false)
	command("iptables-legacy", "-t", "nat", "-D", "POSTROUTING", "-j", "MASQUERADE")
	inspect(true)
	command("ip6tables-legacy", "-P", "FORWARD", "ACCEPT")
	inspect(false)
	command("ip6tables-legacy", "-P", "FORWARD", "DROP")
	inspect(true)
	command("iptables-legacy", "-A", "FORWARD", "-j", "ACCEPT")
	inspect(false)
	command("iptables-legacy", "-D", "FORWARD", "-j", "ACCEPT")
	inspect(true)
	command("nft", "add", "table", "inet", "attestor_probe")
	inspect(false)
	command("nft", "delete", "table", "inet", "attestor_probe")
	inspect(true)
	command("ip", "link", "set", "tailscale0", "mtu", "1200")
	inspect(false)
}
