package routing

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/jaxxstorm/envelope/internal/config"
	"github.com/jaxxstorm/envelope/internal/metrics"
	"github.com/prometheus/client_golang/prometheus"
	"go.uber.org/zap"
)

type fakeOps struct {
	interfaces  map[string]interfaceInfo
	sysctls     map[string]int
	lookups     map[string]routeResult
	tableRoutes map[string][]routeEntry
	rules       map[string][]policyRule
	status      tailscaleStatus
	firewallErr error
	queries     []routeQuery
	mutations   []string
	contracts   []forwardingPathContract
}

func newFakeOps() *fakeOps {
	return &fakeOps{
		interfaces:  map[string]interfaceInfo{},
		sysctls:     map[string]int{},
		lookups:     map[string]routeResult{},
		tableRoutes: map[string][]routeEntry{},
		rules:       map[string][]policyRule{},
	}
}

func (f *fakeOps) InterfaceInfo(name string) (interfaceInfo, error) {
	info, ok := f.interfaces[name]
	if !ok {
		return interfaceInfo{}, fmt.Errorf("missing interface %s", name)
	}
	return info, nil
}
func (f *fakeOps) SysctlValue(path string) (int, error) { return f.sysctls[path], nil }
func (*fakeOps) AcquireLock() (routingLock, error)      { return fakeLock{}, nil }
func (f *fakeOps) RuleState(_ context.Context, family string, priority int, iif, cidr string, table, protocol int) (objectState, error) {
	owned, operator := 0, 0
	for _, rule := range f.rules[family] {
		if rule.Priority != priority || rule.Input != iif || rule.Destination != cidr {
			continue
		}
		if rule.Table != table || normalizedRuleAction(rule) != "lookup" || rule.Unsupported || rule.Invert || rule.HasMark || rule.SuppressPrefixLength != -1 || policyRulePrefix(rule.Source, family) != familyDefaultPrefix(family) {
			return stateConflict, nil
		}
		if rule.Protocol == protocol {
			owned++
		} else {
			operator++
		}
	}
	if owned > 1 || operator > 1 || owned > 0 && operator > 0 {
		return stateConflict, nil
	}
	if owned == 1 {
		return stateOwned, nil
	}
	if operator == 1 {
		return stateOperator, nil
	}
	return stateAbsent, nil
}
func (f *fakeOps) AddRule(_ context.Context, family string, priority int, iif, cidr string, table, protocol int) error {
	f.mutations = append(f.mutations, "add-rule:"+family+"|"+iif+"|"+cidr+"|"+fmt.Sprint(priority, "|", table))
	f.rules[family] = append(f.rules[family], policyRule{Family: family, Priority: priority, Input: iif, Destination: cidr, Table: table, Action: "lookup", Protocol: protocol, SuppressPrefixLength: -1})
	return nil
}
func (f *fakeOps) DeleteRule(_ context.Context, family string, priority int, iif, cidr string, table, protocol int) error {
	f.mutations = append(f.mutations, "delete-rule:"+family+"|"+iif+"|"+cidr+"|"+fmt.Sprint(priority, "|", table))
	for index, rule := range f.rules[family] {
		if rule.Priority == priority && rule.Input == iif && rule.Destination == cidr && rule.Table == table && rule.Protocol == protocol {
			f.rules[family] = append(f.rules[family][:index], f.rules[family][index+1:]...)
			break
		}
	}
	return nil
}
func (*fakeOps) RouteState(context.Context, string, int, string, string, int) (objectState, error) {
	return stateAbsent, nil
}
func (f *fakeOps) AddRoute(_ context.Context, family string, table int, cidr, dev string, _ int) error {
	f.mutations = append(f.mutations, "add-route:"+family+"|"+dev+"|"+cidr+"|"+fmt.Sprint(table))
	return nil
}
func (*fakeOps) DeleteRoute(context.Context, string, int, string, string, int) error { return nil }
func (f *fakeOps) RouteLookup(_ context.Context, query routeQuery) (routeResult, error) {
	f.queries = append(f.queries, query)
	return f.lookups[query.Destination], nil
}
func (f *fakeOps) Rules(_ context.Context, family string) ([]policyRule, error) {
	return append([]policyRule(nil), f.rules[family]...), nil
}
func (f *fakeOps) Routes(_ context.Context, family string, table int) ([]routeEntry, error) {
	return append([]routeEntry(nil), f.tableRoutes[tableKey(family, table)]...), nil
}
func (f *fakeOps) TailscaleStatus(context.Context) (tailscaleStatus, error) { return f.status, nil }
func (*fakeOps) TailscalePing(context.Context, string) error                { return nil }
func (f *fakeOps) ValidateFirewall(_ context.Context, contracts []forwardingPathContract) error {
	f.contracts = append([]forwardingPathContract(nil), contracts...)
	return f.firewallErr
}

type fakeLock struct{}

func (fakeLock) Release() error { return nil }

func tableKey(family string, table int) string { return fmt.Sprintf("%s|%d", family, table) }

func routingConfig(t testing.TB, mode config.RoutingMode) *config.Config {
	t.Helper()
	cfg, err := config.Parse([]string{
		"--udp-bind=:6081", "--metrics-addr=:9090", "--routing-mode=" + string(mode),
		"--underlay-interface=eth0", "--local-site-cidrs=10.20.0.0/24", "--remote-site-cidrs=10.30.0.0/24",
	})
	if err != nil {
		t.Fatalf("parse config: %v", err)
	}
	return cfg
}

func readyFakeOps(cfg *config.Config) *fakeOps {
	ops := newFakeOps()
	for _, name := range []string{cfg.TunName, cfg.TailscaleIface, cfg.UnderlayIface} {
		ops.interfaces[name] = interfaceInfo{Name: name, MTU: 1280}
		ops.sysctls["/proc/sys/net/ipv4/conf/"+name+"/rp_filter"] = 0
	}
	ops.interfaces[cfg.UnderlayIface] = interfaceInfo{Name: cfg.UnderlayIface, MTU: 1500}
	ops.sysctls[ipv4ForwardingPath] = 1
	ops.sysctls[ipv6ForwardingPath] = 1
	ops.sysctls[ipv4RPFilterAllPath] = 0
	ops.status = tailscaleStatus{
		Version: "1.80.3", TUN: true, BackendState: "Running", Self: &tailscalePeerStatus{Online: true},
		Peer: map[string]*tailscalePeerStatus{"peer": {
			TailscaleIPs: []string{"100.64.0.2"}, PrimaryRoutes: cfg.EffectiveRemoteSiteCIDRs(), Online: true,
			InNetworkMap: true, InMagicSock: true, InEngine: true,
		}},
	}
	for _, family := range []string{"-4", "-6"} {
		ops.rules[family] = []policyRule{
			{Family: family, Priority: 0, Table: localRouteTable, Action: "lookup", SuppressPrefixLength: -1},
			{Family: family, Priority: 200, Table: config.TailscaleRouteTableID, Action: "lookup", SuppressPrefixLength: -1},
			{Family: family, Priority: 32766, Table: mainRouteTable, Action: "lookup", SuppressPrefixLength: -1},
		}
	}
	addRoutes(ops, cfg.EffectiveLocalSiteCIDRs(), cfg.UnderlayIface, mainRouteTable)
	addRoutes(ops, cfg.EffectiveRemoteSiteCIDRs(), cfg.TailscaleIface, config.TailscaleRouteTableID)
	setLookups(ops, cfg.EffectiveLocalSiteCIDRs(), routeResult{Device: cfg.UnderlayIface, Table: mainRouteTable, Type: "unicast"})
	setLookups(ops, cfg.EffectiveRemoteSiteCIDRs(), routeResult{Device: cfg.TailscaleIface, Table: config.TailscaleRouteTableID, Type: "unicast"})
	return ops
}

func addRoutes(ops *fakeOps, cidrs []string, dev string, table int) {
	for _, target := range buildTargets(cidrs) {
		ops.tableRoutes[tableKey(target.family, table)] = append(ops.tableRoutes[tableKey(target.family, table)], routeEntry{Family: target.family, Prefix: target.cidr, Device: dev, Table: table, Type: "unicast"})
	}
}

func setLookups(ops *fakeOps, cidrs []string, result routeResult) {
	for _, cidr := range cidrs {
		for _, address := range prefixBoundaryAddresses(cidr) {
			ops.lookups[address] = result
		}
	}
}

func newTestManager(t testing.TB, cfg *config.Config, ops *fakeOps) *manager {
	t.Helper()
	mgr, err := newManager(cfg, zap.NewNop(), metrics.New(prometheus.NewRegistry()), ops, time.Hour)
	if err != nil {
		t.Fatalf("new manager: %v", err)
	}
	return mgr.(*manager)
}

func TestManagedRoutingInstallsOwnedPostInspectionRule(t *testing.T) {
	cfg := routingConfig(t, config.RoutingModeManage)
	ops := readyFakeOps(cfg)
	mgr := newTestManager(t, cfg, ops)
	if err := mgr.Initialize(context.Background()); err != nil || !mgr.Ready() {
		t.Fatalf("initialize: ready=%v reason=%q err=%v", mgr.Ready(), mgr.HealthReason(), err)
	}
	if len(ops.mutations) != 1 || ops.mutations[0] != "add-rule:-4|envelope0|10.20.0.0/24|100|254" {
		t.Fatalf("managed routing mutations=%v", ops.mutations)
	}
	if len(ops.queries) != 8 {
		t.Fatalf("route queries=%d, want source and destination boundary checks for both site prefixes", len(ops.queries))
	}
	for _, query := range ops.queries {
		if query.Input != cfg.TunName || query.Source == "" {
			t.Fatalf("query does not model a sourced envelope ingress packet: %+v", query)
		}
	}
}

func TestManagedRoutingPermitsLocalTailscaleFIBOnlyThroughPostInspectionRule(t *testing.T) {
	cfg := routingConfig(t, config.RoutingModeManage)
	ops := readyFakeOps(cfg)
	addRoutes(ops, cfg.EffectiveLocalSiteCIDRs(), cfg.TailscaleIface, config.TailscaleRouteTableID)
	mgr := newTestManager(t, cfg, ops)
	if err := mgr.Initialize(context.Background()); err != nil || !mgr.Ready() {
		t.Fatalf("initialize: ready=%v reason=%q err=%v", mgr.Ready(), mgr.HealthReason(), err)
	}
	if err := mgr.cleanupManaged(); err != nil {
		t.Fatalf("cleanup: %v", err)
	}
	if len(ops.mutations) != 2 || ops.mutations[1] != "delete-rule:-4|envelope0|10.20.0.0/24|100|254" {
		t.Fatalf("managed rule lifecycle=%v", ops.mutations)
	}
}

func TestManagedRoutingCleansOwnedPostInspectionRuleAfterFailedInitialize(t *testing.T) {
	cfg := routingConfig(t, config.RoutingModeManage)
	ops := readyFakeOps(cfg)
	setLookups(ops, cfg.EffectiveRemoteSiteCIDRs(), routeResult{Device: cfg.UnderlayIface, Table: mainRouteTable, Type: "unicast"})
	mgr := newTestManager(t, cfg, ops)
	if err := mgr.Initialize(context.Background()); err == nil {
		t.Fatal("initialize unexpectedly succeeded")
	}
	if len(ops.mutations) != 2 || ops.mutations[1] != "delete-rule:-4|envelope0|10.20.0.0/24|100|254" {
		t.Fatalf("failed initialization left owned rule: %v", ops.mutations)
	}
}

func TestTailscaleLocalFIBRequiresExplicitWinningPostInspectionRule(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*config.Config, *fakeOps)
	}{
		{"missing explicit rule", func(cfg *config.Config, ops *fakeOps) {
			addRoutes(ops, cfg.EffectiveLocalSiteCIDRs(), cfg.TailscaleIface, config.TailscaleRouteTableID)
		}},
		{"tailscale rule wins first", func(cfg *config.Config, ops *fakeOps) {
			addRoutes(ops, cfg.EffectiveLocalSiteCIDRs(), cfg.TailscaleIface, config.TailscaleRouteTableID)
			ops.rules["-4"] = append(ops.rules["-4"],
				policyRule{Family: "-4", Priority: cfg.RoutingRulePriority, Input: cfg.TunName, Destination: "10.20.0.0/24", Table: mainRouteTable, Action: "lookup", SuppressPrefixLength: -1},
				policyRule{Family: "-4", Priority: 50, Input: cfg.TunName, Destination: "10.20.0.0/24", Table: config.TailscaleRouteTableID, Action: "lookup", SuppressPrefixLength: -1},
			)
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := routingConfig(t, config.RoutingModeVerify)
			ops := readyFakeOps(cfg)
			tt.mutate(cfg, ops)
			mgr := newTestManager(t, cfg, ops)
			_ = mgr.Initialize(context.Background())
			if mgr.Ready() || mgr.HealthReason() != metrics.RoutingFailureReasonDeliveryRoute {
				t.Fatalf("ready=%v reason=%q", mgr.Ready(), mgr.HealthReason())
			}
		})
	}
}

func TestTargetRouteValidationRejectsWrongDelivery(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*config.Config, *fakeOps)
		want   string
	}{
		{"local through tailscale", func(cfg *config.Config, ops *fakeOps) {
			setLookups(ops, cfg.EffectiveLocalSiteCIDRs(), routeResult{Device: cfg.TailscaleIface, Table: config.TailscaleRouteTableID, Type: "unicast"})
		}, metrics.RoutingFailureReasonDeliveryRoute},
		{"remote through main", func(cfg *config.Config, ops *fakeOps) {
			setLookups(ops, cfg.EffectiveRemoteSiteCIDRs(), routeResult{Device: cfg.UnderlayIface, Table: mainRouteTable, Type: "unicast"})
		}, metrics.RoutingFailureReasonRouteUnaccepted},
		{"remote terminal route", func(cfg *config.Config, ops *fakeOps) {
			setLookups(ops, cfg.EffectiveRemoteSiteCIDRs(), routeResult{Device: cfg.TailscaleIface, Table: config.TailscaleRouteTableID, Type: "blackhole"})
		}, metrics.RoutingFailureReasonRouteUnaccepted},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := routingConfig(t, config.RoutingModeVerify)
			ops := readyFakeOps(cfg)
			tt.mutate(cfg, ops)
			mgr := newTestManager(t, cfg, ops)
			_ = mgr.Initialize(context.Background())
			if mgr.Ready() || mgr.HealthReason() != tt.want {
				t.Fatalf("ready=%v reason=%q, want %q", mgr.Ready(), mgr.HealthReason(), tt.want)
			}
		})
	}
}

func TestFullPrefixAuditRejectsInteriorAndSourceSpecificShadows(t *testing.T) {
	tests := []struct {
		name string
		add  func(*config.Config, *fakeOps)
	}{
		{"interior local route", func(_ *config.Config, ops *fakeOps) {
			addRoutes(ops, []string{"10.20.0.64/26"}, "tailscale0", mainRouteTable)
		}},
		{"source-specific policy", func(_ *config.Config, ops *fakeOps) {
			ops.rules["-4"] = append(ops.rules["-4"], policyRule{Family: "-4", Priority: 50, Source: "10.30.0.64/26", Destination: "10.20.0.0/24", Table: 123, Action: "lookup", SuppressPrefixLength: -1})
			addRoutes(ops, []string{"10.20.0.0/24"}, "envelope0", 123)
		}},
		{"remote blackhole", func(_ *config.Config, ops *fakeOps) {
			addRoutes(ops, []string{"10.30.0.64/26"}, "", config.TailscaleRouteTableID)
			routes := ops.tableRoutes[tableKey("-4", config.TailscaleRouteTableID)]
			routes[len(routes)-1].Type = "blackhole"
			ops.tableRoutes[tableKey("-4", config.TailscaleRouteTableID)] = routes
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := routingConfig(t, config.RoutingModeVerify)
			ops := readyFakeOps(cfg)
			tt.add(cfg, ops)
			mgr := newTestManager(t, cfg, ops)
			_ = mgr.Initialize(context.Background())
			if mgr.Ready() {
				t.Fatal("full-prefix shadow was accepted")
			}
		})
	}
}

func TestHostAndFirewallValidationRemainStrict(t *testing.T) {
	cfg := routingConfig(t, config.RoutingModeVerify)
	ops := readyFakeOps(cfg)
	ops.firewallErr = errors.New("owned chain missing")
	mgr := newTestManager(t, cfg, ops)
	_ = mgr.Initialize(context.Background())
	if mgr.Ready() || mgr.HealthReason() != metrics.RoutingFailureReasonFirewall {
		t.Fatalf("ready=%v reason=%q", mgr.Ready(), mgr.HealthReason())
	}
	if len(ops.contracts) != 4 {
		t.Fatalf("firewall contracts=%d, want IPv4 and IPv6 envelope paths", len(ops.contracts))
	}
	for _, contract := range ops.contracts {
		if contract.Input != cfg.TunName || contract.Output != cfg.UnderlayIface && contract.Output != cfg.TailscaleIface {
			t.Fatalf("unexpected forwarding contract: %+v", contract)
		}
	}
	ops.firewallErr = nil
	ops.sysctls["/proc/sys/net/ipv4/conf/"+cfg.TunName+"/rp_filter"] = 1
	_ = mgr.reconcile(context.Background(), false)
	if mgr.Ready() || mgr.HealthReason() != metrics.RoutingFailureReasonRPFilter {
		t.Fatalf("ready=%v reason=%q", mgr.Ready(), mgr.HealthReason())
	}
}

func TestStatusReportsSiteCIDRs(t *testing.T) {
	cfg := routingConfig(t, config.RoutingModeVerify)
	mgr := newTestManager(t, cfg, readyFakeOps(cfg))
	status := mgr.Status()
	if len(status.LocalSiteCIDRs) != 1 || len(status.RemoteSiteCIDRs) != 1 {
		t.Fatalf("unexpected status: %+v", status)
	}
}

func TestRouteHelpers(t *testing.T) {
	if got := prefixBoundaryAddresses("10.0.0.0/24"); len(got) != 2 || got[1] != "10.0.0.255" {
		t.Fatalf("IPv4 boundaries=%v", got)
	}
	if !routeSetCovers([]string{"10.0.0.0/8"}, "10.20.0.0/16") {
		t.Fatal("route coverage contract failed")
	}
}
