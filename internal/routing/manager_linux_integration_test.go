//go:build linux && integration

package routing

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jaxxstorm/envelope/internal/config"
	"github.com/jaxxstorm/envelope/internal/metrics"
	"github.com/jaxxstorm/envelope/internal/tun"
	"github.com/prometheus/client_golang/prometheus"
	"go.uber.org/zap"
	"golang.org/x/sys/unix"
)

const routingNamespaceHelperEnv = "ENVELOPE_ROUTING_NAMESPACE_HELPER"

const (
	routingTestIPEnv            = "ENVELOPE_TEST_IP"
	routingTestIPTablesEnv      = "ENVELOPE_TEST_IPTABLES"
	routingTestIP6TablesEnv     = "ENVELOPE_TEST_IP6TABLES"
	routingTestIPTablesSaveEnv  = "ENVELOPE_TEST_IPTABLES_SAVE"
	routingTestIP6TablesSaveEnv = "ENVELOPE_TEST_IP6TABLES_SAVE"
	routingTestNFTEnv           = "ENVELOPE_TEST_NFT"
	routingTestTailscaleEnv     = "ENVELOPE_TEST_TAILSCALE"
	routingTestLockPathEnv      = "ENVELOPE_TEST_LOCK_PATH"
)

type integrationNamespaceRunner struct {
	ipPath    string
	namespace string
}

func (r integrationNamespaceRunner) Run(ctx context.Context, path string, args ...string) ([]byte, error) {
	namespaceArgs := []string{"netns", "exec", r.namespace, path}
	namespaceArgs = append(namespaceArgs, args...)
	return (execCommandRunner{}).Run(ctx, r.ipPath, namespaceArgs...)
}

func TestRoutingNamespaceIPv6SourceSpecificRouteRejection(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root")
	}
	ipPath, err := exec.LookPath("ip")
	if err != nil {
		t.Skip("requires iproute2")
	}

	namespace := "env-src-" + strconv.Itoa(os.Getpid())
	runIntegrationCommand(t, ipPath, "netns", "add", namespace)
	t.Cleanup(func() { _ = exec.Command(ipPath, "netns", "del", namespace).Run() })
	runIntegrationCommand(t, ipPath, "-n", namespace, "link", "set", "lo", "up")
	runIntegrationCommand(t, ipPath, "-n", namespace, "-6", "route", "add", "2001:db8:20::/64", "dev", "lo", "metric", "100")

	probeArgs := []string{"-n", namespace, "-6", "route", "add", "2001:db8:20::/64", "from", "2001:db8:30:0:8000::/65", "dev", "lo", "metric", "50"}
	if output, err := exec.Command(ipPath, probeArgs...).CombinedOutput(); err != nil {
		message := strings.ToLower(string(output))
		if strings.Contains(message, "invalid argument") || strings.Contains(message, "operation not supported") || strings.Contains(message, "not supported") || strings.Contains(message, "ipv6_subtrees") {
			t.Skipf("kernel does not support CONFIG_IPV6_SUBTREES; privileged source-specific route reproduction is not applicable: %s", strings.TrimSpace(string(output)))
		}
		t.Fatalf("probe IPv6 source-specific route support: %v: %s", err, output)
	}

	ops := newSystemOps().(*systemOpsLinux)
	ops.paths.ip = ipPath
	ops.runner = integrationNamespaceRunner{ipPath: ipPath, namespace: namespace}
	routes, err := ops.Routes(context.Background(), "-6", mainRouteTable)
	if err != nil {
		t.Fatalf("decode source-specific route: %v", err)
	}
	found := false
	for _, route := range routes {
		if route.Prefix == "2001:db8:20::/64" && route.Source == "2001:db8:30:0:8000::/65" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("live route decoder omitted source selector: %+v", routes)
	}

	audit := newPolicyAuditor(context.Background(), ops)
	err = audit.auditPath(
		targetRoute{family: "-6", cidr: "2001:db8:30::/64"},
		targetRoute{family: "-6", cidr: "2001:db8:20::/64"},
		"tailscale0",
		"lo",
		mainRouteTable,
		metrics.RoutingFailureReasonDeliveryRoute,
	)
	if err == nil || !strings.Contains(err.Error(), "source-specific route") {
		t.Fatalf("live source-specific route was not rejected by full-prefix audit: %v", err)
	}
}

func TestRoutingNamespaceDisabledRPFilterTUNLookup(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root")
	}
	tools := make(map[string]string)
	for _, command := range []string{"ip", "sysctl", "tcpdump"} {
		path, err := exec.LookPath(command)
		if err != nil {
			t.Skipf("requires %s", command)
		}
		tools[command] = path
	}

	suffix := strconv.Itoa(os.Getpid())
	routerNS := "env-ar-" + suffix
	destinationNS := "env-ad-" + suffix
	underlayNS := "env-au-" + suffix
	for _, namespace := range []string{routerNS, destinationNS, underlayNS} {
		runIntegrationCommand(t, tools["ip"], "netns", "add", namespace)
		namespace := namespace
		t.Cleanup(func() { _ = exec.Command(tools["ip"], "netns", "del", namespace).Run() })
		runIntegrationCommand(t, tools["ip"], "-n", namespace, "link", "set", "lo", "up")
	}

	createVethPair(t, routerNS, destinationNS, "tailscale0", "destination0")
	createVethPair(t, routerNS, underlayNS, "underlay0", "underlay-peer0")
	for _, address := range [][3]string{
		{routerNS, "tailscale0", "10.30.0.254/24"},
		{destinationNS, "destination0", "10.30.0.1/24"},
		{routerNS, "underlay0", "192.0.2.1/24"},
		{underlayNS, "underlay-peer0", "192.0.2.2/24"},
	} {
		runIntegrationCommand(t, tools["ip"], "-n", address[0], "addr", "add", address[2], "dev", address[1])
	}
	device, err := inIntegrationNetworkNamespace(routerNS, func() (*tun.Device, error) {
		return tun.Open("envelope0", 1280)
	})
	if err != nil {
		t.Fatalf("open namespaced TUN: %v", err)
	}
	t.Cleanup(func() { _ = device.Close() })

	runIntegrationCommand(t, tools["ip"], "-n", routerNS, "route", "add", "10.10.0.0/24", "via", "192.0.2.2", "dev", "underlay0")
	runIntegrationCommand(t, tools["ip"], "-n", routerNS, "route", "add", "table", "52", "10.30.0.0/24", "dev", "tailscale0")
	runIntegrationCommand(t, tools["ip"], "-n", routerNS, "rule", "add", "priority", "5200", "iif", "envelope0", "table", "52")
	for _, setting := range []string{
		"net.ipv4.ip_forward=1",
		"net.ipv4.conf.all.rp_filter=0",
		"net.ipv4.conf.envelope0.rp_filter=0",
		"net.ipv4.conf.tailscale0.rp_filter=0",
		"net.ipv4.conf.underlay0.rp_filter=0",
	} {
		runIntegrationCommand(t, tools["ip"], "netns", "exec", routerNS, tools["sysctl"], "-q", "-w", setting)
	}

	ops := newSystemOps().(*systemOpsLinux)
	ops.paths.ip = tools["ip"]
	ops.runner = integrationNamespaceRunner{ipPath: tools["ip"], namespace: routerNS}
	result, err := ops.RouteLookup(context.Background(), routeQuery{
		Family: "-4", Destination: "10.30.0.1", Source: "10.10.0.1", Input: "envelope0",
	})
	if err != nil && !errors.Is(err, errSupplementaryRouteLookupUnavailable) {
		t.Fatalf("asymmetric route lookup error=%v", err)
	}
	if err == nil && (result.Device != "tailscale0" || result.Table != config.TailscaleRouteTableID || normalizedRouteType(result.Type) != "unicast") {
		t.Fatalf("asymmetric route lookup result=%+v, want tailscale0 table 52 unicast", result)
	}

	payload := []byte("asymmetric-tun-packet")
	packet := integrationIPv4UDPPacket(net.ParseIP("10.10.0.1"), net.ParseIP("10.30.0.1"), 18083, 18084, payload)
	captureCtx, cancelCapture := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancelCapture()
	capture := exec.CommandContext(captureCtx, tools["ip"], "netns", "exec", destinationNS, tools["tcpdump"], "-l", "-nn", "-i", "destination0", "-c", "1", "src host 10.10.0.1 and dst host 10.30.0.1")
	var captureOutput bytes.Buffer
	capture.Stdout = &captureOutput
	capture.Stderr = &captureOutput
	if err := capture.Start(); err != nil {
		t.Fatalf("start asymmetric packet capture: %v", err)
	}
	time.Sleep(100 * time.Millisecond)
	for range 5 {
		if _, err := device.Write(packet); err != nil {
			t.Fatalf("inject TUN packet: %v", err)
		}
		time.Sleep(50 * time.Millisecond)
	}
	if err := capture.Wait(); err != nil {
		routerLinks := integrationCommandOutput(t, tools["ip"], "-n", routerNS, "-s", "link", "show")
		destinationLinks := integrationCommandOutput(t, tools["ip"], "-n", destinationNS, "-s", "link", "show")
		t.Fatalf("disabled reverse-path TUN packet was dropped: %v: %s\nrouter:\n%s\ndestination:\n%s", err, captureOutput.String(), routerLinks, destinationLinks)
	}
	if !strings.Contains(captureOutput.String(), "10.10.0.1.18083 > 10.30.0.1.18084") {
		t.Fatalf("unexpected asymmetric packet capture: %s", captureOutput.String())
	}
}

func TestRoutingNamespaceDirectionalRoles(t *testing.T) {
	if os.Getenv(routingNamespaceHelperEnv) == "1" {
		runRoutingNamespaceHelper(t)
		return
	}
	if os.Geteuid() != 0 {
		t.Skip("requires root")
	}
	tools := make(map[string]string)
	for _, command := range []string{"ip", "nft", "tcpdump", "python3"} {
		if _, err := exec.LookPath(command); err != nil {
			t.Skipf("requires %s", command)
		}
		tools[command], _ = exec.LookPath(command)
	}
	iptablesPath, iptablesSavePath := integrationLegacyTables(t, "iptables")
	ip6tablesPath, ip6tablesSavePath := integrationLegacyTables(t, "ip6tables")

	suffix := strconv.Itoa(os.Getpid())
	routerNS := "env-r-" + suffix
	deliveryNS := "env-d-" + suffix
	remoteNS := "env-p-" + suffix
	returnNS := "env-e-" + suffix
	for _, namespace := range []string{routerNS, deliveryNS, remoteNS, returnNS} {
		runIntegrationCommand(t, "ip", "netns", "add", namespace)
		namespace := namespace
		t.Cleanup(func() { _ = exec.Command("ip", "netns", "del", namespace).Run() })
		runIntegrationCommand(t, "ip", "-n", namespace, "link", "set", "lo", "up")
		runIntegrationCommand(t, "ip", "netns", "exec", namespace, "sysctl", "-q", "-w", "net.ipv6.conf.default.accept_dad=0")
	}

	createVethPair(t, routerNS, deliveryNS, "underlay0", "delivery0")
	createVethPair(t, routerNS, remoteNS, "tailscale0", "tailpeer0")
	createVethPair(t, routerNS, returnNS, "envelope0", "return0")
	configureNamespaceAddresses(t, routerNS, deliveryNS, remoteNS, returnNS)
	configureRouterHostPolicy(t, routerNS, iptablesPath, ip6tablesPath)

	commandDir := t.TempDir()
	statusPath := filepath.Join(commandDir, "status.json")
	writeIntegrationStatus(t, statusPath, "Running", true, true)
	tailscalePath := filepath.Join(commandDir, "tailscale")
	tailscaleScript := "#!/bin/sh\nif [ \"$1\" = status ]; then exec /bin/cat " + strconv.Quote(statusPath) + "; fi\nif [ \"$1\" = ping ]; then exit 0; fi\nexit 2\n"
	if err := os.WriteFile(tailscalePath, []byte(tailscaleScript), 0o755); err != nil {
		t.Fatalf("write tailscale adapter: %v", err)
	}

	args := []string{
		"netns", "exec", routerNS,
		"env",
		routingNamespaceHelperEnv + "=1",
		"ENVELOPE_TEST_TAILSCALE_STATUS=" + statusPath,
		"ENVELOPE_TEST_DELIVERY_NS=" + deliveryNS,
		"ENVELOPE_TEST_REMOTE_NS=" + remoteNS,
		"ENVELOPE_TEST_RETURN_NS=" + returnNS,
		routingTestIPEnv + "=" + tools["ip"],
		routingTestIPTablesEnv + "=" + iptablesPath,
		routingTestIP6TablesEnv + "=" + ip6tablesPath,
		routingTestIPTablesSaveEnv + "=" + iptablesSavePath,
		routingTestIP6TablesSaveEnv + "=" + ip6tablesSavePath,
		routingTestNFTEnv + "=" + tools["nft"],
		routingTestTailscaleEnv + "=" + tailscalePath,
		routingTestLockPathEnv + "=" + filepath.Join(commandDir, "routing.lock"),
		"PATH=" + os.Getenv("PATH"),
		os.Args[0], "-test.run=^TestRoutingNamespaceDirectionalRoles$", "-test.v",
	}
	cmd := exec.Command("ip", args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("routing namespace helper: %v\n%s", err, out)
	}
}

func runRoutingNamespaceHelper(t *testing.T) {
	statusPath := os.Getenv("ENVELOPE_TEST_TAILSCALE_STATUS")
	deliveryNS := os.Getenv("ENVELOPE_TEST_DELIVERY_NS")
	remoteNS := os.Getenv("ENVELOPE_TEST_REMOTE_NS")
	returnNS := os.Getenv("ENVELOPE_TEST_RETURN_NS")
	cfg, err := config.Parse([]string{
		"--udp-bind=:6081",
		"--metrics-addr=:9090",
		"--routing-mode=manage",
		"--underlay-interface=underlay0",
		"--tailscale-iface=tailscale0",
		"--tun-name=envelope0",
		"--tun-mtu=1280",
		"--gwlb-return-cidrs=10.10.0.0/24,2001:db8:10::/64",
		"--local-delivery-cidrs=10.20.0.0/24,2001:db8:20::/64",
		"--remote-tailnet-cidrs=10.30.0.0/24,2001:db8:30::/64",
	})
	if err != nil {
		t.Fatalf("parse helper config: %v", err)
	}
	metricSet := metrics.New(prometheus.NewRegistry())
	ops := newSystemOps().(*systemOpsLinux)
	ops.paths.ip = os.Getenv(routingTestIPEnv)
	ops.paths.iptables = os.Getenv(routingTestIPTablesEnv)
	ops.paths.ip6tables = os.Getenv(routingTestIP6TablesEnv)
	ops.paths.iptablesSave = os.Getenv(routingTestIPTablesSaveEnv)
	ops.paths.ip6tablesSave = os.Getenv(routingTestIP6TablesSaveEnv)
	ops.paths.tailscale = os.Getenv(routingTestTailscaleEnv)
	ops.paths.nft = os.Getenv(routingTestNFTEnv)
	ops.lockPath = os.Getenv(routingTestLockPathEnv)
	rm, err := newManager(cfg, zap.NewNop(), metricSet, ops, 10*time.Millisecond)
	if err != nil {
		t.Fatalf("manager: %v", err)
	}
	mgr := rm.(*manager)
	if err := mgr.Initialize(context.Background()); err != nil || !mgr.Ready() {
		rules, _ := exec.Command(ops.paths.ip, "-j", "-details", "-4", "rule", "show").CombinedOutput()
		fib, _ := exec.Command(ops.paths.ip, "-j", "-details", "-N", "-4", "route", "show", "table", strconv.Itoa(config.TailscaleRouteTableID)).CombinedOutput()
		t.Fatalf("initialize ready=%v reason=%s err=%v rules=%s fib=%s", mgr.Ready(), mgr.HealthReason(), err, rules, fib)
	}
	writeIntegrationStatus(t, statusPath, "Running", true, false)
	verifyCfg := *cfg
	verifyCfg.RoutingMode = config.RoutingModeVerify
	unavailableRM, err := newManager(&verifyCfg, zap.NewNop(), metrics.New(prometheus.NewRegistry()), ops, time.Hour)
	if err != nil {
		t.Fatalf("unavailable-route manager: %v", err)
	}
	if err := unavailableRM.Initialize(context.Background()); err != nil {
		t.Fatalf("unavailable-route initialize: %v", err)
	}
	assertManagerReason(t, unavailableRM.(*manager), metrics.RoutingFailureReasonRouteUnavailable)
	writeIntegrationStatus(t, statusPath, "Running", true, true)

	assertEffectiveRoute(t, mgr.op, "-4", "10.10.0.1", "10.30.0.1", "tailscale0", "envelope0", cfg.RoutingTableID)
	assertEffectiveRoute(t, mgr.op, "-4", "10.20.0.1", "10.30.0.1", "tailscale0", "underlay0", mainRouteTable)
	assertEffectiveRoute(t, mgr.op, "-4", "10.30.0.1", "10.10.0.1", "envelope0", "tailscale0", config.TailscaleRouteTableID)
	assertEffectiveRoute(t, mgr.op, "-6", "2001:db8:10::1", "2001:db8:30::1", "tailscale0", "envelope0", cfg.RoutingTableID)
	assertEffectiveRoute(t, mgr.op, "-6", "2001:db8:20::1", "2001:db8:30::1", "tailscale0", "underlay0", mainRouteTable)
	assertEffectiveRoute(t, mgr.op, "-6", "2001:db8:30::1", "2001:db8:10::1", "envelope0", "tailscale0", config.TailscaleRouteTableID)

	runIntegrationCommand(t, "ip", "route", "add", "blackhole", "10.10.0.64/26", "table", strconv.Itoa(cfg.RoutingTableID))
	mgr.reconcile(context.Background(), false)
	assertManagerReason(t, mgr, metrics.RoutingFailureReasonReturnRoute)
	runIntegrationCommand(t, "ip", "route", "del", "blackhole", "10.10.0.64/26", "table", strconv.Itoa(cfg.RoutingTableID))
	mgr.reconcile(context.Background(), false)
	assertManagerReady(t, mgr)

	runIntegrationCommand(t, "ip", "route", "add", "table", "123", "10.20.0.0/24", "dev", "envelope0")
	runIntegrationCommand(t, "ip", "rule", "add", "priority", "50", "from", "10.30.0.64/26", "to", "10.20.0.0/24", "table", "123")
	mgr.reconcile(context.Background(), false)
	assertManagerReason(t, mgr, metrics.RoutingFailureReasonDeliveryRoute)
	runIntegrationCommand(t, "ip", "rule", "del", "priority", "50", "from", "10.30.0.64/26", "to", "10.20.0.0/24", "table", "123")
	runIntegrationCommand(t, "ip", "route", "del", "table", "123", "10.20.0.0/24", "dev", "envelope0")
	mgr.reconcile(context.Background(), false)
	assertManagerReady(t, mgr)

	mssPaths := []struct {
		name          string
		sourceNS      string
		destinationNS string
		captureIface  string
		destination   string
		filter        string
		port          int
		expectedMSS   int
	}{
		{name: "IPv4 underlay to Tailscale", sourceNS: deliveryNS, destinationNS: remoteNS, captureIface: "tailpeer0", destination: "10.30.0.1", filter: "tcp", port: 18080, expectedMSS: 1240},
		{name: "IPv4 Tailscale to underlay", sourceNS: remoteNS, destinationNS: deliveryNS, captureIface: "delivery0", destination: "10.20.0.1", filter: "tcp", port: 18081, expectedMSS: 1240},
		{name: "IPv4 Envelope to Tailscale", sourceNS: returnNS, destinationNS: remoteNS, captureIface: "tailpeer0", destination: "10.30.0.1", filter: "tcp", port: 18082, expectedMSS: 1240},
		{name: "IPv4 Tailscale to Envelope", sourceNS: remoteNS, destinationNS: returnNS, captureIface: "return0", destination: "10.10.0.1", filter: "tcp", port: 18083, expectedMSS: 1240},
		{name: "IPv6 underlay to Tailscale", sourceNS: deliveryNS, destinationNS: remoteNS, captureIface: "tailpeer0", destination: "2001:db8:30::1", filter: "ip6 and tcp", port: 18180, expectedMSS: 1220},
		{name: "IPv6 Tailscale to underlay", sourceNS: remoteNS, destinationNS: deliveryNS, captureIface: "delivery0", destination: "2001:db8:20::1", filter: "ip6 and tcp", port: 18181, expectedMSS: 1220},
		{name: "IPv6 Envelope to Tailscale", sourceNS: returnNS, destinationNS: remoteNS, captureIface: "tailpeer0", destination: "2001:db8:30::1", filter: "ip6 and tcp", port: 18182, expectedMSS: 1220},
		{name: "IPv6 Tailscale to Envelope", sourceNS: remoteNS, destinationNS: returnNS, captureIface: "return0", destination: "2001:db8:10::1", filter: "ip6 and tcp", port: 18183, expectedMSS: 1220},
	}
	for _, path := range mssPaths {
		t.Run(path.name, func(t *testing.T) {
			assertTCPTransferAndMSS(t, path.sourceNS, path.destinationNS, path.captureIface, path.destination, path.filter, path.port, path.expectedMSS)
		})
	}

	runIntegrationCommand(t, "ip", "route", "del", "table", strconv.Itoa(config.TailscaleRouteTableID), "10.30.0.0/24", "dev", "tailscale0")
	mgr.reconcile(context.Background(), false)
	assertManagerReason(t, mgr, metrics.RoutingFailureReasonRouteUnaccepted)
	runIntegrationCommand(t, "ip", "route", "add", "table", strconv.Itoa(config.TailscaleRouteTableID), "10.30.0.0/24", "dev", "tailscale0")
	mgr.reconcile(context.Background(), false)
	assertManagerReady(t, mgr)

	writeIntegrationStatus(t, statusPath, "Running", true, false)
	mgr.reconcile(context.Background(), false)
	assertManagerReason(t, mgr, metrics.RoutingFailureReasonRouteWithdrawn)
	writeIntegrationStatus(t, statusPath, "Running", true, true)
	mgr.reconcile(context.Background(), false)
	assertManagerReady(t, mgr)

	runIntegrationCommand(t, "sysctl", "-q", "-w", "net.ipv4.conf.tailscale0.rp_filter=1")
	mgr.reconcile(context.Background(), false)
	assertManagerReason(t, mgr, metrics.RoutingFailureReasonRPFilter)
	runIntegrationCommand(t, "sysctl", "-q", "-w", "net.ipv4.conf.tailscale0.rp_filter=0")
	mgr.reconcile(context.Background(), false)
	assertManagerReady(t, mgr)

	deleteFirewallPath(t, ops.paths.iptables, "underlay0", "tailscale0")
	mgr.reconcile(context.Background(), false)
	assertManagerReason(t, mgr, metrics.RoutingFailureReasonFirewall)
	addFirewallPath(t, ops.paths.iptables, "underlay0", "tailscale0")
	mgr.reconcile(context.Background(), false)
	assertManagerReady(t, mgr)

	runIntegrationCommand(t, ops.paths.iptables, "-P", "FORWARD", "DROP")
	mgr.reconcile(context.Background(), false)
	assertManagerReason(t, mgr, metrics.RoutingFailureReasonFirewall)
	runIntegrationCommand(t, ops.paths.iptables, "-P", "FORWARD", "ACCEPT")
	mgr.reconcile(context.Background(), false)
	assertManagerReady(t, mgr)

	for _, mutation := range []struct {
		table string
		args  []string
	}{
		{table: "raw", args: []string{"PREROUTING", "-j", "DROP"}},
		{table: "mangle", args: []string{"PREROUTING", "-j", "MARK", "--set-mark", "0x1"}},
		{table: "nat", args: []string{"PREROUTING", "-j", "DNAT", "--to-destination", "192.0.2.99"}},
	} {
		addArgs := append([]string{"-t", mutation.table, "-A"}, mutation.args...)
		runIntegrationCommand(t, ops.paths.iptables, addArgs...)
		mgr.reconcile(context.Background(), false)
		assertManagerReason(t, mgr, metrics.RoutingFailureReasonFirewall)
		deleteArgs := append([]string{"-t", mutation.table, "-D"}, mutation.args...)
		runIntegrationCommand(t, ops.paths.iptables, deleteArgs...)
		mgr.reconcile(context.Background(), false)
		assertManagerReady(t, mgr)
	}

	deleteMSSPath(t, ops.paths.ip6tables, "tailscale0", "envelope0", 1220)
	mgr.reconcile(context.Background(), false)
	assertManagerReason(t, mgr, metrics.RoutingFailureReasonMSS)
	addMSSPath(t, ops.paths.ip6tables, "tailscale0", "envelope0", 1220)
	mgr.reconcile(context.Background(), false)
	assertManagerReady(t, mgr)

	runIntegrationCommand(t, ops.paths.iptables, "-t", "mangle", "-A", "FORWARD", "-j", "DROP")
	mgr.reconcile(context.Background(), false)
	assertManagerReason(t, mgr, metrics.RoutingFailureReasonMSS)
	runIntegrationCommand(t, ops.paths.iptables, "-t", "mangle", "-D", "FORWARD", "-j", "DROP")
	mgr.reconcile(context.Background(), false)
	assertManagerReady(t, mgr)

	runIntegrationCommand(t, ops.paths.iptables, "-t", "mangle", "-P", "FORWARD", "DROP")
	mgr.reconcile(context.Background(), false)
	assertManagerReason(t, mgr, metrics.RoutingFailureReasonMSS)
	runIntegrationCommand(t, ops.paths.iptables, "-t", "mangle", "-P", "FORWARD", "ACCEPT")
	mgr.reconcile(context.Background(), false)
	assertManagerReady(t, mgr)

	nftPath := ops.paths.nft
	ops.paths.nft = filepath.Join(filepath.Dir(nftPath), "missing-envelope-nft")
	mgr.reconcile(context.Background(), false)
	assertManagerReason(t, mgr, metrics.RoutingFailureReasonFirewall)
	ops.paths.nft = nftPath
	mgr.reconcile(context.Background(), false)
	assertManagerReady(t, mgr)

	writeIntegrationStatus(t, statusPath, "Stopped", true, true)
	mgr.reconcile(context.Background(), false)
	assertManagerReason(t, mgr, metrics.RoutingFailureReasonBackend)
	writeIntegrationStatus(t, statusPath, "Running", true, true)
	mgr.reconcile(context.Background(), false)
	assertManagerReady(t, mgr)

	returnTarget := buildTargets(cfg.EffectiveGWLBReturnCIDRs())[0]
	runIntegrationCommand(t, "ip", returnTarget.family, "rule", "del", "priority", strconv.Itoa(cfg.RoutingRulePriority), "iif", cfg.TailscaleIface, "to", returnTarget.cidr, "table", strconv.Itoa(cfg.RoutingTableID), "protocol", strconv.Itoa(ownerProtocol))
	mgr.reconcile(context.Background(), false)
	assertManagerReady(t, mgr)

	before := integrationCommandOutput(t, "ip", "rule", "show")
	if _, err := config.Parse([]string{"--udp-bind=:6081", "--metrics-addr=:9090", "--tun-name=shared0", "--tailscale-iface=shared0"}); err == nil {
		t.Fatal("interface collision unexpectedly passed validation")
	}
	after := integrationCommandOutput(t, "ip", "rule", "show")
	if before != after {
		t.Fatal("interface-collision validation mutated routing state")
	}

	if err := mgr.cleanupManaged(); err != nil {
		t.Fatalf("cleanup: %v", err)
	}
	for _, target := range buildTargets(cfg.EffectiveGWLBReturnCIDRs()) {
		state, err := mgr.op.RuleState(context.Background(), target.family, cfg.RoutingRulePriority, cfg.TailscaleIface, target.cidr, cfg.RoutingTableID, ownerProtocol)
		if err != nil || state == stateOwned {
			t.Fatalf("owned rule survived cleanup for %s: state=%d err=%v", target.cidr, state, err)
		}
	}
	if err := mgr.releaseLock(); err != nil {
		t.Fatalf("release lock: %v", err)
	}
}

func inIntegrationNetworkNamespace[T any](namespace string, operation func() (T, error)) (T, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	var zero T
	current, err := os.Open("/proc/self/ns/net")
	if err != nil {
		return zero, err
	}
	defer current.Close()
	target, err := os.Open("/var/run/netns/" + namespace)
	if err != nil {
		return zero, err
	}
	defer target.Close()
	if err := unix.Setns(int(target.Fd()), unix.CLONE_NEWNET); err != nil {
		return zero, err
	}
	value, operationErr := operation()
	restoreErr := unix.Setns(int(current.Fd()), unix.CLONE_NEWNET)
	return value, errors.Join(operationErr, restoreErr)
}

func integrationIPv4UDPPacket(source, destination net.IP, sourcePort, destinationPort uint16, payload []byte) []byte {
	const ipv4HeaderLength = 20
	const udpHeaderLength = 8
	packet := make([]byte, ipv4HeaderLength+udpHeaderLength+len(payload))
	packet[0] = 0x45
	binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
	binary.BigEndian.PutUint16(packet[4:6], 1)
	packet[8] = 64
	packet[9] = 17
	copy(packet[12:16], source.To4())
	copy(packet[16:20], destination.To4())
	binary.BigEndian.PutUint16(packet[10:12], integrationIPv4Checksum(packet[:ipv4HeaderLength]))
	binary.BigEndian.PutUint16(packet[20:22], sourcePort)
	binary.BigEndian.PutUint16(packet[22:24], destinationPort)
	binary.BigEndian.PutUint16(packet[24:26], uint16(udpHeaderLength+len(payload)))
	copy(packet[28:], payload)
	return packet
}

func integrationIPv4Checksum(header []byte) uint16 {
	var sum uint32
	for offset := 0; offset < len(header); offset += 2 {
		sum += uint32(binary.BigEndian.Uint16(header[offset : offset+2]))
	}
	for sum > 0xffff {
		sum = sum&0xffff + sum>>16
	}
	return ^uint16(sum)
}

func createVethPair(t *testing.T, routerNS, peerNS, routerName, peerName string) {
	t.Helper()
	temporaryRouter := "r" + routerName[:min(8, len(routerName))] + strconv.Itoa(os.Getpid()%1000)
	temporaryPeer := "p" + peerName[:min(8, len(peerName))] + strconv.Itoa(os.Getpid()%1000)
	runIntegrationCommand(t, "ip", "link", "add", temporaryRouter, "type", "veth", "peer", "name", temporaryPeer)
	runIntegrationCommand(t, "ip", "link", "set", temporaryRouter, "netns", routerNS)
	runIntegrationCommand(t, "ip", "link", "set", temporaryPeer, "netns", peerNS)
	runIntegrationCommand(t, "ip", "-n", routerNS, "link", "set", temporaryRouter, "name", routerName)
	runIntegrationCommand(t, "ip", "-n", peerNS, "link", "set", temporaryPeer, "name", peerName)
	runIntegrationCommand(t, "ip", "-n", routerNS, "link", "set", routerName, "up")
	runIntegrationCommand(t, "ip", "-n", peerNS, "link", "set", peerName, "up")
}

func integrationLegacyTables(t *testing.T, family string) (string, string) {
	t.Helper()
	candidates := []string{family + "-legacy", family}
	for _, candidate := range candidates {
		binary, err := exec.LookPath(candidate)
		if err != nil {
			continue
		}
		version, err := exec.Command(binary, "--version").CombinedOutput()
		if err != nil || !strings.Contains(string(version), "(legacy)") {
			continue
		}
		saveName := family + "-save"
		if strings.HasSuffix(candidate, "-legacy") {
			saveName = family + "-legacy-save"
		}
		save, err := exec.LookPath(saveName)
		if err == nil {
			return binary, save
		}
	}
	t.Skipf("requires a legacy %s/%s-save pair", family, family)
	return "", ""
}

func configureNamespaceAddresses(t *testing.T, routerNS, deliveryNS, remoteNS, returnNS string) {
	t.Helper()
	addresses := [][4]string{
		{routerNS, "underlay0", "192.0.2.1/32", "2001:db8:ffff::1/128"},
		{deliveryNS, "delivery0", "10.20.0.1/32", "2001:db8:20::1/128"},
		{routerNS, "tailscale0", "192.0.2.2/32", "2001:db8:ffff::2/128"},
		{remoteNS, "tailpeer0", "10.30.0.1/32", "2001:db8:30::1/128"},
		{routerNS, "envelope0", "192.0.2.3/32", "2001:db8:ffff::3/128"},
		{returnNS, "return0", "10.10.0.1/32", "2001:db8:10::1/128"},
	}
	for _, entry := range addresses {
		runIntegrationCommand(t, "ip", "-n", entry[0], "addr", "add", entry[2], "dev", entry[1])
		runIntegrationCommand(t, "ip", "-n", entry[0], "-6", "addr", "add", entry[3], "dev", entry[1])
	}
	for _, entry := range [][4]string{
		{deliveryNS, "delivery0", "192.0.2.1", "2001:db8:ffff::1"},
		{remoteNS, "tailpeer0", "192.0.2.2", "2001:db8:ffff::2"},
		{returnNS, "return0", "192.0.2.3", "2001:db8:ffff::3"},
	} {
		runIntegrationCommand(t, "ip", "-n", entry[0], "route", "add", "default", "via", entry[2], "dev", entry[1], "onlink")
		runIntegrationCommand(t, "ip", "-n", entry[0], "-6", "route", "add", "default", "via", entry[3], "dev", entry[1], "onlink")
	}
	runIntegrationCommand(t, "ip", "-n", routerNS, "route", "add", "10.20.0.0/24", "dev", "underlay0")
	runIntegrationCommand(t, "ip", "-n", routerNS, "-6", "route", "add", "2001:db8:20::/64", "dev", "underlay0")
	runIntegrationCommand(t, "ip", "-n", routerNS, "route", "add", "10.10.0.0/24", "dev", "envelope0")
	runIntegrationCommand(t, "ip", "-n", routerNS, "route", "add", "table", strconv.Itoa(config.TailscaleRouteTableID), "10.30.0.0/24", "dev", "tailscale0")
	runIntegrationCommand(t, "ip", "-n", routerNS, "-6", "route", "add", "table", strconv.Itoa(config.TailscaleRouteTableID), "2001:db8:30::/64", "dev", "tailscale0")
	for _, family := range []string{"-4", "-6"} {
		runIntegrationCommand(t, "ip", "-n", routerNS, family, "rule", "add", "priority", "5200", "iif", "envelope0", "table", strconv.Itoa(config.TailscaleRouteTableID))
		runIntegrationCommand(t, "ip", "-n", routerNS, family, "rule", "add", "priority", "5201", "iif", "underlay0", "table", strconv.Itoa(config.TailscaleRouteTableID))
	}
	runIntegrationCommand(t, "ip", "-n", routerNS, "link", "set", "tailscale0", "mtu", "1280")
	runIntegrationCommand(t, "ip", "-n", remoteNS, "link", "set", "tailpeer0", "mtu", "1280")
}

func configureRouterHostPolicy(t *testing.T, routerNS, iptablesPath, ip6tablesPath string) {
	t.Helper()
	for _, setting := range []string{
		"net.ipv4.ip_forward=1",
		"net.ipv6.conf.all.forwarding=1",
		"net.ipv4.conf.all.rp_filter=0",
		"net.ipv4.conf.default.rp_filter=2",
		"net.ipv4.conf.underlay0.rp_filter=0",
		"net.ipv4.conf.tailscale0.rp_filter=0",
		"net.ipv4.conf.envelope0.rp_filter=2",
	} {
		runIntegrationCommand(t, "ip", "netns", "exec", routerNS, "sysctl", "-q", "-w", setting)
	}
	for _, binary := range []string{iptablesPath, ip6tablesPath} {
		runIntegrationCommand(t, "ip", "netns", "exec", routerNS, binary, "-P", "FORWARD", "ACCEPT")
		runIntegrationCommand(t, "ip", "netns", "exec", routerNS, binary, "-N", filterChainName)
		runIntegrationCommand(t, "ip", "netns", "exec", routerNS, binary, "-I", "FORWARD", "1", "-j", filterChainName)
		runIntegrationCommand(t, "ip", "netns", "exec", routerNS, binary, "-t", "mangle", "-N", mssChainName)
		runIntegrationCommand(t, "ip", "netns", "exec", routerNS, binary, "-t", "mangle", "-I", "FORWARD", "1", "-j", mssChainName)
		for _, direction := range [][2]string{{"underlay0", "tailscale0"}, {"tailscale0", "underlay0"}, {"envelope0", "tailscale0"}, {"tailscale0", "envelope0"}} {
			runIntegrationCommand(t, "ip", "netns", "exec", routerNS, binary, "-A", filterChainName, "-i", direction[0], "-o", direction[1], "-j", "ACCEPT")
			mss := "1240"
			if binary == ip6tablesPath {
				mss = "1220"
			}
			runIntegrationCommand(t, "ip", "netns", "exec", routerNS, binary, "-t", "mangle", "-A", mssChainName, "-i", direction[0], "-o", direction[1], "-p", "tcp", "-m", "tcp", "--tcp-flags", "SYN,RST", "SYN", "-j", "TCPMSS", "--set-mss", mss)
		}
		runIntegrationCommand(t, "ip", "netns", "exec", routerNS, binary, "-t", "mangle", "-A", mssChainName, "-j", "RETURN")
	}
}

func writeIntegrationStatus(t *testing.T, path, backend string, approved, remote bool) {
	t.Helper()
	status := tailscaleStatus{
		Version:      "1.80.3",
		TUN:          true,
		BackendState: backend,
		Health:       []string{},
		Self:         &tailscalePeerStatus{Online: true},
		Peer:         map[string]*tailscalePeerStatus{},
	}
	if approved {
		status.Self.AllowedIPs = []string{"10.10.0.0/24", "2001:db8:10::/64", "10.20.0.0/24", "2001:db8:20::/64"}
	}
	if remote {
		status.Peer["peer"] = &tailscalePeerStatus{
			TailscaleIPs:  []string{"100.64.0.2"},
			AllowedIPs:    []string{"10.30.0.0/24", "2001:db8:30::/64"},
			PrimaryRoutes: []string{"10.30.0.0/24", "2001:db8:30::/64"},
			Online:        true,
			InNetworkMap:  true,
			InMagicSock:   true,
			InEngine:      true,
		}
	}
	data, err := json.Marshal(status)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write status: %v", err)
	}
}

func assertEffectiveRoute(t *testing.T, ops systemOps, family, destination, source, input, expectedDevice string, expectedTable int) {
	t.Helper()
	result, err := ops.RouteLookup(context.Background(), routeQuery{Family: family, Destination: destination, Source: source, Input: input})
	if err != nil {
		t.Fatalf("route lookup %s: %v", destination, err)
	}
	if result.Device != expectedDevice || result.Table != expectedTable || normalizedRouteType(result.Type) != "unicast" {
		t.Fatalf("route lookup %s selected dev=%q table=%d type=%q, want dev=%q table=%d type=unicast", destination, result.Device, result.Table, result.Type, expectedDevice, expectedTable)
	}
}

func assertTCPTransferAndMSS(t *testing.T, sourceNS, destinationNS, captureIface, destination, filter string, port, expectedMSS int) {
	t.Helper()
	pcap := filepath.Join("/tmp", fmt.Sprintf("envelope-mss-%d-%d.pcap", os.Getpid(), port))
	_ = os.Remove(pcap)
	defer os.Remove(pcap)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	capture := exec.CommandContext(ctx, "ip", "netns", "exec", destinationNS, "tcpdump", "-U", "-i", captureIface, "-c", "1", "-w", pcap, filter+" and dst port "+strconv.Itoa(port))
	var captureErr bytes.Buffer
	capture.Stderr = &captureErr
	if err := capture.Start(); err != nil {
		t.Fatalf("start capture: %v", err)
	}

	family := "socket.AF_INET"
	bindAddress := "('" + destination + "', " + strconv.Itoa(port) + ")"
	if strings.Contains(destination, ":") {
		family = "socket.AF_INET6"
	}
	readyPath := "/tmp/envelope-server-ready-" + strconv.Itoa(port)
	_ = exec.Command("ip", "netns", "exec", destinationNS, "rm", "-f", readyPath).Run()
	serverCode := "import socket, pathlib; s=socket.socket(" + family + ",socket.SOCK_STREAM); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1); s.bind(" + bindAddress + "); s.listen(1); pathlib.Path('" + readyPath + "').touch(); c,_=s.accept(); n=0\nwhile n < 131072:\n d=c.recv(65536)\n if not d: break\n n += len(d)\nc.close(); s.close(); raise SystemExit(0 if n == 131072 else 2)"
	server := exec.CommandContext(ctx, "ip", "netns", "exec", destinationNS, "python3", "-c", serverCode)
	var serverErr bytes.Buffer
	server.Stderr = &serverErr
	if err := server.Start(); err != nil {
		_ = capture.Process.Kill()
		t.Fatalf("start server: %v", err)
	}
	serverReady := false
	for range 50 {
		if exec.Command("ip", "netns", "exec", destinationNS, "test", "-f", readyPath).Run() == nil {
			serverReady = true
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !serverReady {
		_ = server.Process.Kill()
		_ = capture.Process.Kill()
		_ = server.Wait()
		t.Fatalf("TCP server did not become ready: %s", serverErr.String())
	}
	clientCode := "import socket; s=socket.socket(" + family + ",socket.SOCK_STREAM); s.settimeout(5); s.connect(" + bindAddress + "); s.sendall(b'x'*131072); s.shutdown(socket.SHUT_WR); s.close()"
	client := exec.CommandContext(ctx, "ip", "netns", "exec", sourceNS, "python3", "-c", clientCode)
	if output, err := client.CombinedOutput(); err != nil {
		_ = server.Process.Kill()
		_ = capture.Process.Kill()
		t.Fatalf("TCP client: %v: %s", err, output)
	}
	if err := server.Wait(); err != nil {
		_ = capture.Process.Kill()
		t.Fatalf("TCP server: %v: %s", err, serverErr.String())
	}
	if err := capture.Wait(); err != nil {
		t.Fatalf("capture: %v: %s", err, captureErr.String())
	}
	decoded := integrationCommandOutput(t, "tcpdump", "-nn", "-vv", "-r", pcap)
	if !strings.Contains(decoded, "mss "+strconv.Itoa(expectedMSS)) {
		t.Fatalf("captured SYN did not contain MSS %d: %s", expectedMSS, decoded)
	}
}

func addFirewallPath(t *testing.T, binary, input, output string) {
	t.Helper()
	runIntegrationCommand(t, binary, "-A", filterChainName, "-i", input, "-o", output, "-j", "ACCEPT")
}

func deleteFirewallPath(t *testing.T, binary, input, output string) {
	t.Helper()
	runIntegrationCommand(t, binary, "-D", filterChainName, "-i", input, "-o", output, "-j", "ACCEPT")
}

func addMSSPath(t *testing.T, binary, input, output string, mss int) {
	t.Helper()
	runIntegrationCommand(t, binary, "-t", "mangle", "-I", mssChainName, "1", "-i", input, "-o", output, "-p", "tcp", "-m", "tcp", "--tcp-flags", "SYN,RST", "SYN", "-j", "TCPMSS", "--set-mss", strconv.Itoa(mss))
}

func deleteMSSPath(t *testing.T, binary, input, output string, mss int) {
	t.Helper()
	runIntegrationCommand(t, binary, "-t", "mangle", "-D", mssChainName, "-i", input, "-o", output, "-p", "tcp", "-m", "tcp", "--tcp-flags", "SYN,RST", "SYN", "-j", "TCPMSS", "--set-mss", strconv.Itoa(mss))
}

func assertManagerReason(t *testing.T, mgr *manager, reason string) {
	t.Helper()
	if mgr.Ready() || mgr.HealthReason() != reason {
		t.Fatalf("manager ready=%v reason=%q, want unhealthy %q", mgr.Ready(), mgr.HealthReason(), reason)
	}
}

func assertManagerReady(t *testing.T, mgr *manager) {
	t.Helper()
	if !mgr.Ready() {
		t.Fatalf("manager did not recover: %s", mgr.HealthReason())
	}
}

func runIntegrationCommand(t *testing.T, name string, args ...string) {
	t.Helper()
	cmd := exec.Command(name, args...)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("%s %s: %v: %s", name, strings.Join(args, " "), err, output)
	}
}

func integrationCommandOutput(t *testing.T, name string, args ...string) string {
	t.Helper()
	output, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		t.Fatalf("%s %s: %v: %s", name, strings.Join(args, " "), err, output)
	}
	return string(output)
}
