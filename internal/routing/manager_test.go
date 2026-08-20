package routing

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jaxxstorm/envelope/internal/config"
	"github.com/jaxxstorm/envelope/internal/metrics"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"go.uber.org/zap"
)

type fakeOps struct {
	mu sync.Mutex

	interfaces   map[string]interfaceInfo
	sysctls      map[string]int
	rules        map[string]objectState
	routes       map[string]objectState
	lookups      map[string]routeResult
	lookupErrors map[string]error
	tableRoutes  map[string][]routeEntry
	policyRules  map[string][]policyRule
	status       tailscaleStatus
	statusErr    error
	firewallErr  error
	pingErrors   map[string]error

	addRuleErrors    map[string]error
	addRouteErrors   map[string]error
	addRuleStates    map[string]objectState
	addRouteStates   map[string]objectState
	ruleStateErrors  map[string][]error
	routeStateErrors map[string][]error
	deleteRuleErrors map[string]error
	deleteRouteErrs  map[string]error
	deleteRuleNoops  map[string]bool
	deleteRouteNoops map[string]bool
	lockErr          error

	queries          []routeQuery
	recordQueries    bool
	contracts        []forwardingPathContract
	pings            []string
	mutations        []string
	deleteAttempts   []string
	cleanupDeadlines int
	locks            int
	unlocks          int
}

func newFakeOps() *fakeOps {
	return &fakeOps{
		interfaces:       map[string]interfaceInfo{},
		sysctls:          map[string]int{},
		rules:            map[string]objectState{},
		routes:           map[string]objectState{},
		lookups:          map[string]routeResult{},
		lookupErrors:     map[string]error{},
		tableRoutes:      map[string][]routeEntry{},
		policyRules:      map[string][]policyRule{},
		pingErrors:       map[string]error{},
		addRuleErrors:    map[string]error{},
		addRouteErrors:   map[string]error{},
		addRuleStates:    map[string]objectState{},
		addRouteStates:   map[string]objectState{},
		ruleStateErrors:  map[string][]error{},
		routeStateErrors: map[string][]error{},
		deleteRuleErrors: map[string]error{},
		deleteRouteErrs:  map[string]error{},
		deleteRuleNoops:  map[string]bool{},
		deleteRouteNoops: map[string]bool{},
		recordQueries:    true,
	}
}

func ruleKey(family string, priority int, iif, cidr string, table int) string {
	return fmt.Sprintf("%s|%d|%s|%s|%d", family, priority, iif, cidr, table)
}

func routeKey(family string, table int, cidr, dev string) string {
	return fmt.Sprintf("%s|%d|%s|%s", family, table, cidr, dev)
}

func pathKey(family, input, output string) string {
	return family + "|" + input + "|" + output
}

func tableKey(family string, table int) string {
	return fmt.Sprintf("%s|%d", family, table)
}

func (f *fakeOps) InterfaceInfo(name string) (interfaceInfo, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	info, ok := f.interfaces[name]
	if !ok {
		return interfaceInfo{}, fmt.Errorf("missing interface %s", name)
	}
	return info, nil
}

func (f *fakeOps) SysctlValue(path string) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.sysctls[path], nil
}

type fakeRoutingLock struct {
	ops  *fakeOps
	once sync.Once
}

func (l *fakeRoutingLock) Release() error {
	l.once.Do(func() {
		l.ops.mu.Lock()
		defer l.ops.mu.Unlock()
		l.ops.unlocks++
	})
	return nil
}

func (f *fakeOps) AcquireLock() (routingLock, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.lockErr != nil {
		return nil, f.lockErr
	}
	f.locks++
	return &fakeRoutingLock{ops: f}, nil
}

func (f *fakeOps) RuleState(_ context.Context, family string, priority int, iif, cidr string, table, _ int) (objectState, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	key := ruleKey(family, priority, iif, cidr, table)
	var err error
	if queued := f.ruleStateErrors[key]; len(queued) > 0 {
		err = queued[0]
		f.ruleStateErrors[key] = queued[1:]
	}
	return f.rules[key], err
}

func (f *fakeOps) AddRule(_ context.Context, family string, priority int, iif, cidr string, table, _ int) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	key := ruleKey(family, priority, iif, cidr, table)
	f.mutations = append(f.mutations, "add-rule:"+key)
	if err := f.addRuleErrors[key]; err != nil {
		if state := f.addRuleStates[key]; state != stateAbsent {
			f.rules[key] = state
		}
		return err
	}
	f.rules[key] = stateOwned
	if state := f.addRuleStates[key]; state != stateAbsent {
		f.rules[key] = state
	}
	return nil
}

func (f *fakeOps) DeleteRule(ctx context.Context, family string, priority int, iif, cidr string, table, _ int) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	key := ruleKey(family, priority, iif, cidr, table)
	f.recordDeleteContext(ctx)
	f.deleteAttempts = append(f.deleteAttempts, "rule:"+key)
	f.mutations = append(f.mutations, "delete-rule:"+key)
	if err := f.deleteRuleErrors[key]; err != nil {
		return err
	}
	if f.deleteRuleNoops[key] {
		return nil
	}
	delete(f.rules, key)
	return nil
}

func (f *fakeOps) RouteState(_ context.Context, family string, table int, cidr, dev string, _ int) (objectState, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	key := routeKey(family, table, cidr, dev)
	var err error
	if queued := f.routeStateErrors[key]; len(queued) > 0 {
		err = queued[0]
		f.routeStateErrors[key] = queued[1:]
	}
	return f.routes[key], err
}

func (f *fakeOps) AddRoute(_ context.Context, family string, table int, cidr, dev string, _ int) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	key := routeKey(family, table, cidr, dev)
	f.mutations = append(f.mutations, "add-route:"+key)
	if err := f.addRouteErrors[key]; err != nil {
		if state := f.addRouteStates[key]; state != stateAbsent {
			f.routes[key] = state
		}
		return err
	}
	f.routes[key] = stateOwned
	if state := f.addRouteStates[key]; state != stateAbsent {
		f.routes[key] = state
	}
	return nil
}

func (f *fakeOps) DeleteRoute(ctx context.Context, family string, table int, cidr, dev string, _ int) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	key := routeKey(family, table, cidr, dev)
	f.recordDeleteContext(ctx)
	f.deleteAttempts = append(f.deleteAttempts, "route:"+key)
	f.mutations = append(f.mutations, "delete-route:"+key)
	if err := f.deleteRouteErrs[key]; err != nil {
		return err
	}
	if f.deleteRouteNoops[key] {
		return nil
	}
	delete(f.routes, key)
	return nil
}

func (f *fakeOps) recordDeleteContext(ctx context.Context) {
	if deadline, ok := ctx.Deadline(); ok && time.Until(deadline) > 0 && time.Until(deadline) <= cleanupObjectTimeout {
		f.cleanupDeadlines++
	}
}

func (f *fakeOps) RouteLookup(_ context.Context, query routeQuery) (routeResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.recordQueries {
		f.queries = append(f.queries, query)
	}
	if err := f.lookupErrors[query.Destination]; err != nil {
		return routeResult{}, err
	}
	return f.lookups[query.Destination], nil
}

func (f *fakeOps) Routes(_ context.Context, family string, table int) ([]routeEntry, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	routes := append([]routeEntry(nil), f.tableRoutes[tableKey(family, table)]...)
	for key, state := range f.routes {
		if state != stateOwned && state != stateOperator {
			continue
		}
		parts := strings.Split(key, "|")
		if len(parts) != 4 || parts[0] != family {
			continue
		}
		routeTable, err := strconv.Atoi(parts[1])
		if err != nil || routeTable != table {
			continue
		}
		routes = append(routes, routeEntry{Family: family, Prefix: parts[2], Device: parts[3], Table: table, Type: "unicast"})
	}
	return routes, nil
}

func (f *fakeOps) Rules(_ context.Context, family string) ([]policyRule, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	rules := append([]policyRule(nil), f.policyRules[family]...)
	for key, state := range f.rules {
		if state != stateOwned && state != stateOperator {
			continue
		}
		parts := strings.Split(key, "|")
		if len(parts) != 5 || parts[0] != family {
			continue
		}
		priority, priorityErr := strconv.Atoi(parts[1])
		table, tableErr := strconv.Atoi(parts[4])
		if priorityErr != nil || tableErr != nil {
			continue
		}
		rules = append(rules, policyRule{
			Family:               family,
			Priority:             priority,
			Destination:          parts[3],
			Input:                parts[2],
			Table:                table,
			Action:               "lookup",
			SuppressPrefixLength: -1,
		})
	}
	sort.SliceStable(rules, func(i, j int) bool { return rules[i].Priority < rules[j].Priority })
	return rules, nil
}

func (f *fakeOps) TailscaleStatus(context.Context) (tailscaleStatus, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	status := f.status
	if f.status.Self != nil {
		self := *f.status.Self
		self.TailscaleIPs = append([]string(nil), self.TailscaleIPs...)
		self.AllowedIPs = append([]string(nil), self.AllowedIPs...)
		self.PrimaryRoutes = append([]string(nil), self.PrimaryRoutes...)
		status.Self = &self
	}
	status.Health = append([]string(nil), status.Health...)
	status.Peer = make(map[string]*tailscalePeerStatus, len(f.status.Peer))
	for key, value := range f.status.Peer {
		if value == nil {
			status.Peer[key] = nil
			continue
		}
		peer := *value
		peer.TailscaleIPs = append([]string(nil), peer.TailscaleIPs...)
		peer.AllowedIPs = append([]string(nil), peer.AllowedIPs...)
		peer.PrimaryRoutes = append([]string(nil), peer.PrimaryRoutes...)
		status.Peer[key] = &peer
	}
	return status, f.statusErr
}

func (f *fakeOps) TailscalePing(_ context.Context, address string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.pings = append(f.pings, address)
	return f.pingErrors[address]
}

func (f *fakeOps) ValidateFirewall(_ context.Context, contracts []forwardingPathContract) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.contracts = append([]forwardingPathContract(nil), contracts...)
	return f.firewallErr
}

func routingConfig(t testing.TB, mode config.RoutingMode, returnCIDRs ...string) *config.Config {
	t.Helper()
	if len(returnCIDRs) == 0 {
		returnCIDRs = []string{"10.10.0.0/24"}
	}
	cfg, err := config.Parse([]string{
		"--udp-bind=:6081",
		"--metrics-addr=:9090",
		"--routing-mode=" + string(mode),
		"--underlay-interface=eth0",
		"--gwlb-return-cidrs=" + joinCIDRs(returnCIDRs),
		"--local-delivery-cidrs=10.20.0.0/24",
		"--remote-tailnet-cidrs=10.30.0.0/24",
	})
	if err != nil {
		t.Fatalf("parse config: %v", err)
	}
	return cfg
}

func joinCIDRs(cidrs []string) string {
	var result string
	for index, cidr := range cidrs {
		if index > 0 {
			result += ","
		}
		result += cidr
	}
	return result
}

func readyFakeOps(cfg *config.Config) *fakeOps {
	ops := newFakeOps()
	for _, iface := range []string{cfg.TunName, cfg.TailscaleIface, cfg.UnderlayIface} {
		ops.interfaces[iface] = interfaceInfo{Name: iface, MTU: 1280}
	}
	ops.interfaces[cfg.UnderlayIface] = interfaceInfo{Name: cfg.UnderlayIface, MTU: 1500}
	ops.sysctls[ipv4ForwardingPath] = 1
	ops.sysctls[ipv6ForwardingPath] = 1
	ops.sysctls[ipv4RPFilterAllPath] = 0
	for _, iface := range []string{cfg.UnderlayIface, cfg.TailscaleIface, cfg.TunName} {
		ops.sysctls["/proc/sys/net/ipv4/conf/"+iface+"/rp_filter"] = 0
	}
	localRoutes := append(append([]string(nil), cfg.EffectiveGWLBReturnCIDRs()...), cfg.EffectiveLocalDeliveryCIDRs()...)
	ops.status = tailscaleStatus{
		Version:      "1.80.3",
		BackendState: "Running",
		TUN:          true,
		Self:         &tailscalePeerStatus{AllowedIPs: localRoutes, Online: true},
		Peer: map[string]*tailscalePeerStatus{
			"node-key-redacted": {
				TailscaleIPs:  []string{"100.64.0.2"},
				AllowedIPs:    cfg.EffectiveRemoteTailnetCIDRs(),
				PrimaryRoutes: cfg.EffectiveRemoteTailnetCIDRs(),
				Online:        true,
				InNetworkMap:  true,
				InMagicSock:   true,
				InEngine:      true,
			},
		},
	}
	for _, cidr := range cfg.EffectiveRemoteTailnetCIDRs() {
		addTableRoute(ops, cidr, routeEntry{Prefix: cidr, Device: cfg.TailscaleIface, Table: config.TailscaleRouteTableID, Type: "unicast"})
	}
	for _, cidr := range cfg.EffectiveLocalDeliveryCIDRs() {
		addRouteToTable(ops, cidr, routeEntry{Prefix: cidr, Device: cfg.UnderlayIface, Table: mainRouteTable, Type: "unicast"})
	}
	for _, family := range []string{"-4", "-6"} {
		ops.policyRules[family] = []policyRule{
			{Family: family, Priority: 0, Table: localRouteTable, Action: "lookup", SuppressPrefixLength: -1},
			{Family: family, Priority: 200, Table: config.TailscaleRouteTableID, Action: "lookup", SuppressPrefixLength: -1},
			{Family: family, Priority: 32766, Table: mainRouteTable, Action: "lookup", SuppressPrefixLength: -1},
			{Family: family, Priority: 32767, Table: 253, Action: "lookup", SuppressPrefixLength: -1},
		}
	}
	setRoleLookups(ops, cfg.EffectiveGWLBReturnCIDRs(), routeResult{Device: cfg.TunName, Table: cfg.RoutingTableID, Type: "unicast"})
	setRoleLookups(ops, cfg.EffectiveLocalDeliveryCIDRs(), routeResult{Device: cfg.UnderlayIface, Table: mainRouteTable, Type: "unicast"})
	setRoleLookups(ops, cfg.EffectiveRemoteTailnetCIDRs(), routeResult{Device: cfg.TailscaleIface, Table: config.TailscaleRouteTableID, Type: "unicast"})
	return ops
}

func addTableRoute(ops *fakeOps, cidr string, result routeEntry) {
	addRouteToTable(ops, cidr, result)
}

func addRouteToTable(ops *fakeOps, cidr string, result routeEntry) {
	targets := buildTargets([]string{cidr})
	result.Family = targets[0].family
	ops.tableRoutes[tableKey(targets[0].family, result.Table)] = append(ops.tableRoutes[tableKey(targets[0].family, result.Table)], result)
}

func setRoleLookups(ops *fakeOps, cidrs []string, template routeResult) {
	for _, cidr := range cidrs {
		for _, address := range prefixBoundaryAddresses(cidr) {
			ops.lookups[address] = template
		}
	}
}

func newTestManager(t testing.TB, cfg *config.Config, ops *fakeOps, interval time.Duration) (*manager, *metrics.Metrics) {
	t.Helper()
	reg := prometheus.NewRegistry()
	metricSet := metrics.New(reg)
	rm, err := newManager(cfg, zap.NewNop(), metricSet, ops, interval)
	if err != nil {
		t.Fatalf("new manager: %v", err)
	}
	return rm.(*manager), metricSet
}

func addEquivalentReturnState(cfg *config.Config, ops *fakeOps) {
	for _, target := range buildTargets(cfg.EffectiveGWLBReturnCIDRs()) {
		ops.rules[ruleKey(target.family, cfg.RoutingRulePriority, cfg.TailscaleIface, target.cidr, cfg.RoutingTableID)] = stateOperator
		ops.routes[routeKey(target.family, cfg.RoutingTableID, target.cidr, cfg.TunName)] = stateOperator
	}
}

func TestManagedInitializeUsesStructuredCartesianValidation(t *testing.T) {
	cfg := routingConfig(t, config.RoutingModeManage)
	ops := readyFakeOps(cfg)
	mgr, _ := newTestManager(t, cfg, ops, time.Hour)
	if err := mgr.Initialize(context.Background()); err != nil {
		t.Fatalf("initialize: %v", err)
	}
	if !mgr.Ready() || mgr.HealthReason() != "ok" {
		t.Fatalf("ready=%v reason=%q", mgr.Ready(), mgr.HealthReason())
	}
	if len(ops.mutations) < 2 || !contains(ops.mutations[0], "add-route") || !contains(ops.mutations[1], "add-rule") {
		t.Fatalf("managed state was not installed route-before-rule: %v", ops.mutations)
	}
	if len(ops.queries) != 16 {
		t.Fatalf("route queries=%d, want 16 boundary/source Cartesian queries", len(ops.queries))
	}
	seen := map[string]bool{}
	for _, query := range ops.queries {
		seen[query.Input] = true
		if query.Source == "" || query.Destination == "" {
			t.Fatalf("incomplete route query: %+v", query)
		}
	}
	if !seen[cfg.TailscaleIface] || !seen[cfg.TunName] {
		t.Fatalf("missing packet input contexts: %v", seen)
	}
	if ops.locks != 1 || ops.unlocks != 0 {
		t.Fatalf("lock lifecycle locks=%d unlocks=%d", ops.locks, ops.unlocks)
	}
	if err := mgr.releaseLock(); err != nil || ops.unlocks != 1 {
		t.Fatalf("release lock err=%v unlocks=%d", err, ops.unlocks)
	}
}

func TestVerifyModeNeverMutates(t *testing.T) {
	cfg := routingConfig(t, config.RoutingModeVerify)
	ops := readyFakeOps(cfg)
	mgr, _ := newTestManager(t, cfg, ops, time.Hour)
	if err := mgr.Initialize(context.Background()); err != nil {
		t.Fatalf("verify initialize: %v", err)
	}
	if mgr.Ready() || mgr.HealthReason() != metrics.RoutingFailureReasonReturnRoute || len(ops.mutations) != 0 {
		t.Fatalf("verify ready=%v reason=%q mutations=%v", mgr.Ready(), mgr.HealthReason(), ops.mutations)
	}
	addEquivalentReturnState(cfg, ops)
	mgr.reconcile(context.Background(), false)
	if !mgr.Ready() || len(ops.mutations) != 0 {
		t.Fatalf("verify recovery ready=%v mutations=%v", mgr.Ready(), ops.mutations)
	}
}

func TestRouteResultContractRejectsWrongTableTypePrefixAndUnderlay(t *testing.T) {
	tests := []struct {
		name   string
		reason string
		mutate func(*config.Config, *fakeOps)
	}{
		{name: "return table", reason: metrics.RoutingFailureReasonReturnRoute, mutate: func(cfg *config.Config, ops *fakeOps) {
			setRoleLookups(ops, cfg.EffectiveGWLBReturnCIDRs(), routeResult{Device: cfg.TunName, Table: mainRouteTable, Type: "unicast"})
		}},
		{name: "throw route", reason: metrics.RoutingFailureReasonRouteUnaccepted, mutate: func(cfg *config.Config, ops *fakeOps) {
			setRoleLookups(ops, cfg.EffectiveRemoteTailnetCIDRs(), routeResult{Device: cfg.TailscaleIface, Table: config.TailscaleRouteTableID, Type: "throw"})
		}},
		{name: "last boundary shadowed", reason: metrics.RoutingFailureReasonDeliveryRoute, mutate: func(cfg *config.Config, ops *fakeOps) {
			last := prefixBoundaryAddresses(cfg.EffectiveLocalDeliveryCIDRs()[0])[1]
			ops.lookups[last] = routeResult{Device: cfg.UnderlayIface, Table: 253, Type: "unicast"}
		}},
		{name: "wrong local interface", reason: metrics.RoutingFailureReasonDeliveryRoute, mutate: func(cfg *config.Config, ops *fakeOps) {
			setRoleLookups(ops, cfg.EffectiveLocalDeliveryCIDRs(), routeResult{Device: "eth1", Table: mainRouteTable, Type: "unicast"})
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := routingConfig(t, config.RoutingModeVerify)
			ops := readyFakeOps(cfg)
			addEquivalentReturnState(cfg, ops)
			tt.mutate(cfg, ops)
			mgr, metricSet := newTestManager(t, cfg, ops, time.Hour)
			_ = mgr.Initialize(context.Background())
			if mgr.Ready() || mgr.HealthReason() != tt.reason {
				t.Fatalf("ready=%v reason=%q, want %q", mgr.Ready(), mgr.HealthReason(), tt.reason)
			}
			if got := testutil.ToFloat64(metricSet.RoutingValidationFailures.WithLabelValues(tt.reason)); got != 1 {
				t.Fatalf("failure metric=%v", got)
			}
		})
	}
}

func TestFullPrefixAuditRejectsInteriorRouteAndSourcePolicyShadows(t *testing.T) {
	tests := []struct {
		name   string
		reason string
		mutate func(*config.Config, *fakeOps)
	}{
		{
			name:   "interior more-specific return route",
			reason: metrics.RoutingFailureReasonReturnRoute,
			mutate: func(cfg *config.Config, ops *fakeOps) {
				addRouteToTable(ops, "10.10.0.64/26", routeEntry{Prefix: "10.10.0.64/26", Device: cfg.UnderlayIface, Table: cfg.RoutingTableID, Type: "unicast"})
			},
		},
		{
			name:   "interior source policy shadow",
			reason: metrics.RoutingFailureReasonDeliveryRoute,
			mutate: func(cfg *config.Config, ops *fakeOps) {
				ops.policyRules["-4"] = append(ops.policyRules["-4"], policyRule{
					Family:               "-4",
					Priority:             50,
					Source:               "10.30.0.64/26",
					Destination:          "10.20.0.0/24",
					Table:                123,
					Action:               "lookup",
					SuppressPrefixLength: -1,
				})
				addRouteToTable(ops, "10.20.0.0/24", routeEntry{Prefix: "10.20.0.0/24", Device: cfg.TunName, Table: 123, Type: "unicast"})
			},
		},
		{
			name:   "interior blackhole",
			reason: metrics.RoutingFailureReasonRouteUnaccepted,
			mutate: func(_ *config.Config, ops *fakeOps) {
				addRouteToTable(ops, "10.30.0.64/26", routeEntry{Prefix: "10.30.0.64/26", Table: config.TailscaleRouteTableID, Type: "blackhole"})
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := routingConfig(t, config.RoutingModeVerify)
			ops := readyFakeOps(cfg)
			addEquivalentReturnState(cfg, ops)
			tt.mutate(cfg, ops)
			mgr, _ := newTestManager(t, cfg, ops, time.Hour)
			if err := mgr.Initialize(context.Background()); err != nil {
				t.Fatalf("verify initialize: %v", err)
			}
			if mgr.Ready() || mgr.HealthReason() != tt.reason {
				t.Fatalf("ready=%v reason=%q, want %q", mgr.Ready(), mgr.HealthReason(), tt.reason)
			}
		})
	}
}

func TestFullPrefixAuditAcceptsCompatibleAWSResolverHostRoute(t *testing.T) {
	cfg := routingConfig(t, config.RoutingModeVerify)
	ops := readyFakeOps(cfg)
	addEquivalentReturnState(cfg, ops)
	addRouteToTable(ops, "10.20.0.2/32", routeEntry{
		Prefix: "10.20.0.2/32", Device: cfg.UnderlayIface, Table: mainRouteTable, Type: "unicast",
	})
	mgr, _ := newTestManager(t, cfg, ops, time.Hour)
	if err := mgr.Initialize(context.Background()); err != nil || !mgr.Ready() {
		t.Fatalf("compatible AWS resolver route rejected: ready=%v reason=%q err=%v", mgr.Ready(), mgr.HealthReason(), err)
	}
}

func TestFullPrefixAuditRejectsIncompatibleResolverHostRoutes(t *testing.T) {
	for _, tt := range []struct {
		name  string
		route routeEntry
	}{
		{name: "wrong device", route: routeEntry{Device: "envelope0", Table: mainRouteTable, Type: "unicast"}},
		{name: "wrong table", route: routeEntry{Device: "eth0", Table: 123, Type: "unicast"}},
		{name: "blackhole", route: routeEntry{Table: mainRouteTable, Type: "blackhole"}},
		{name: "unreachable", route: routeEntry{Table: mainRouteTable, Type: "unreachable"}},
		{name: "prohibit", route: routeEntry{Table: mainRouteTable, Type: "prohibit"}},
		{name: "source specific", route: routeEntry{Source: "10.30.0.0/24", Device: "eth0", Table: mainRouteTable, Type: "unicast"}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			cfg := routingConfig(t, config.RoutingModeVerify)
			ops := readyFakeOps(cfg)
			addEquivalentReturnState(cfg, ops)
			route := tt.route
			route.Prefix = "10.20.0.2/32"
			if tt.name == "wrong device" || tt.name == "source specific" {
				route.Device = tt.route.Device
			} else if route.Device == "" && route.Type == "unicast" {
				route.Device = cfg.UnderlayIface
			}
			if tt.name == "wrong table" {
				route.Family = "-4"
				ops.tableRoutes[tableKey("-4", mainRouteTable)] = append(
					ops.tableRoutes[tableKey("-4", mainRouteTable)], route,
				)
			} else {
				addRouteToTable(ops, route.Prefix, route)
			}
			mgr, _ := newTestManager(t, cfg, ops, time.Hour)
			if err := mgr.Initialize(context.Background()); err != nil {
				t.Fatalf("verify initialize: %v", err)
			}
			if mgr.Ready() || mgr.HealthReason() != metrics.RoutingFailureReasonDeliveryRoute {
				t.Fatalf("incompatible resolver route accepted: ready=%v reason=%q", mgr.Ready(), mgr.HealthReason())
			}
		})
	}
}

func TestFullPrefixAuditRejectsRelevantIPv6SourceSpecificRoute(t *testing.T) {
	ops := newFakeOps()
	ops.policyRules["-6"] = []policyRule{{Family: "-6", Priority: 32766, Table: mainRouteTable, Action: "lookup", SuppressPrefixLength: -1}}
	ops.tableRoutes[tableKey("-6", mainRouteTable)] = []routeEntry{
		{Family: "-6", Prefix: "2001:db8:20::/64", Source: "::/0", Device: "underlay0", Table: mainRouteTable, Type: "unicast"},
		{Family: "-6", Prefix: "2001:db8:20::/64", Source: "2001:db8:30:0:8000::/65", Device: "envelope0", Table: mainRouteTable, Type: "unicast"},
	}
	audit := newPolicyAuditor(context.Background(), ops)
	err := audit.auditPath(
		targetRoute{family: "-6", cidr: "2001:db8:30::/64"},
		targetRoute{family: "-6", cidr: "2001:db8:20::/64"},
		"tailscale0",
		"underlay0",
		mainRouteTable,
		metrics.RoutingFailureReasonDeliveryRoute,
	)
	if err == nil || !strings.Contains(err.Error(), "source-specific route") {
		t.Fatalf("relevant IPv6 source-specific route accepted: %v", err)
	}
}

func TestTailscaleContractAndFIBOverlap(t *testing.T) {
	tests := []struct {
		name   string
		reason string
		mutate func(*config.Config, *fakeOps)
	}{
		{name: "unsupported version", reason: metrics.RoutingFailureReasonBackend, mutate: func(_ *config.Config, ops *fakeOps) { ops.status.Version = "1.82.0" }},
		{name: "userspace networking", reason: metrics.RoutingFailureReasonBackend, mutate: func(_ *config.Config, ops *fakeOps) { ops.status.TUN = false }},
		{name: "backend stopped", reason: metrics.RoutingFailureReasonBackend, mutate: func(_ *config.Config, ops *fakeOps) { ops.status.BackendState = "Stopped" }},
		{name: "local route unapproved", reason: metrics.RoutingFailureReasonRouteUnapproved, mutate: func(_ *config.Config, ops *fakeOps) { ops.status.Self = &tailscalePeerStatus{Online: true} }},
		{name: "remote route unavailable", reason: metrics.RoutingFailureReasonRouteUnavailable, mutate: func(_ *config.Config, ops *fakeOps) { ops.status.Peer = nil }},
		{name: "foreign overlapping table route", reason: metrics.RoutingFailureReasonDeliveryRoute, mutate: func(_ *config.Config, ops *fakeOps) {
			key := tableKey("-4", config.TailscaleRouteTableID)
			ops.tableRoutes[key] = append(ops.tableRoutes[key], routeEntry{Family: "-4", Prefix: "10.0.0.0/8", Device: "tailscale0", Table: config.TailscaleRouteTableID, Type: "unicast"})
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := routingConfig(t, config.RoutingModeVerify)
			ops := readyFakeOps(cfg)
			addEquivalentReturnState(cfg, ops)
			tt.mutate(cfg, ops)
			mgr, _ := newTestManager(t, cfg, ops, time.Hour)
			_ = mgr.Initialize(context.Background())
			if mgr.Ready() || mgr.HealthReason() != tt.reason {
				t.Fatalf("ready=%v reason=%q, want %q", mgr.Ready(), mgr.HealthReason(), tt.reason)
			}
		})
	}
}

func TestHostAndMTUContracts(t *testing.T) {
	cfg := routingConfig(t, config.RoutingModeVerify)
	ops := readyFakeOps(cfg)
	addEquivalentReturnState(cfg, ops)
	mgr, _ := newTestManager(t, cfg, ops, time.Hour)
	if err := mgr.Initialize(context.Background()); err != nil || !mgr.Ready() {
		t.Fatalf("initialize ready=%v reason=%q err=%v", mgr.Ready(), mgr.HealthReason(), err)
	}
	if len(ops.contracts) != len(forwardingDirections)*2 {
		t.Fatalf("firewall contracts=%d", len(ops.contracts))
	}
	for _, contract := range ops.contracts {
		want := 1240
		if contract.Family == "-6" {
			want = 1220
		}
		if contract.PathMTU != 1280 || contract.MSS != want {
			t.Fatalf("unexpected path contract: %+v", contract)
		}
	}

	cfg.TunMTU = 39
	mgr.reconcile(context.Background(), false)
	if mgr.Ready() || mgr.HealthReason() != metrics.RoutingFailureReasonMSS {
		t.Fatalf("missing MTU ready=%v reason=%q", mgr.Ready(), mgr.HealthReason())
	}
}

func TestRPFilterAcceptsDisabledOrLooseAndRejectsStrict(t *testing.T) {
	for _, tt := range []struct {
		value   int
		wantErr bool
	}{
		{value: 0},
		{value: 2},
		{value: 1, wantErr: true},
	} {
		t.Run(strconv.Itoa(tt.value), func(t *testing.T) {
			cfg := routingConfig(t, config.RoutingModeVerify)
			ops := readyFakeOps(cfg)
			ops.sysctls["/proc/sys/net/ipv4/conf/"+cfg.TunName+"/rp_filter"] = tt.value
			mgr, _ := newTestManager(t, cfg, ops, time.Hour)
			err := mgr.checkRPFilter()
			if (err != nil) != tt.wantErr {
				t.Fatalf("rp_filter=%d err=%v wantErr=%v", tt.value, err, tt.wantErr)
			}
		})
	}
}

func TestHostPrerequisiteFailureReasonValues(t *testing.T) {
	tests := []struct {
		name   string
		reason string
		mutate func(*config.Config, *fakeOps)
	}{
		{name: "interface", reason: metrics.RoutingFailureReasonInterface, mutate: func(cfg *config.Config, ops *fakeOps) { delete(ops.interfaces, cfg.UnderlayIface) }},
		{name: "forwarding", reason: metrics.RoutingFailureReasonSysctl, mutate: func(_ *config.Config, ops *fakeOps) { ops.sysctls[ipv4ForwardingPath] = 0 }},
		{name: "rp filter", reason: metrics.RoutingFailureReasonRPFilter, mutate: func(cfg *config.Config, ops *fakeOps) {
			ops.sysctls["/proc/sys/net/ipv4/conf/"+cfg.TailscaleIface+"/rp_filter"] = 1
		}},
		{name: "firewall", reason: metrics.RoutingFailureReasonFirewall, mutate: func(_ *config.Config, ops *fakeOps) { ops.firewallErr = errors.New("owned chain missing") }},
		{name: "MSS", reason: metrics.RoutingFailureReasonMSS, mutate: func(_ *config.Config, ops *fakeOps) { ops.firewallErr = fmt.Errorf("%w: wrong clamp", errMSSContract) }},
		{name: "data plane ping", reason: metrics.RoutingFailureReasonBackend, mutate: func(_ *config.Config, ops *fakeOps) { ops.pingErrors["100.64.0.2"] = errors.New("timeout") }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := routingConfig(t, config.RoutingModeVerify)
			ops := readyFakeOps(cfg)
			addEquivalentReturnState(cfg, ops)
			tt.mutate(cfg, ops)
			mgr, metricSet := newTestManager(t, cfg, ops, time.Hour)
			if err := mgr.Initialize(context.Background()); err != nil {
				t.Fatalf("verify initialize: %v", err)
			}
			if mgr.Ready() || mgr.HealthReason() != tt.reason {
				t.Fatalf("ready=%v reason=%q, want %q", mgr.Ready(), mgr.HealthReason(), tt.reason)
			}
			if got := testutil.ToFloat64(metricSet.RoutingValidationFailures.WithLabelValues(tt.reason)); got != 1 {
				t.Fatalf("reason metric=%v, want 1", got)
			}
		})
	}
}

func TestOperatorStatePreservedAndConflictFailsClosed(t *testing.T) {
	cfg := routingConfig(t, config.RoutingModeManage)
	ops := readyFakeOps(cfg)
	addEquivalentReturnState(cfg, ops)
	mgr, metricSet := newTestManager(t, cfg, ops, time.Hour)
	if err := mgr.Initialize(context.Background()); err != nil || !mgr.Ready() {
		t.Fatalf("operator state initialize ready=%v err=%v", mgr.Ready(), err)
	}
	if len(mgr.ownedRules) != 0 || len(mgr.ownedRoutes) != 0 || len(ops.mutations) != 0 {
		t.Fatalf("operator state claimed or mutated: rules=%v routes=%v mutations=%v", mgr.ownedRules, mgr.ownedRoutes, ops.mutations)
	}
	if got := testutil.ToFloat64(metricSet.RoutingOwnershipDecisions.WithLabelValues(metrics.RoutingOwnershipPreserved)); got != 2 {
		t.Fatalf("preserved decisions=%v", got)
	}

	conflictOps := readyFakeOps(cfg)
	target := buildTargets(cfg.EffectiveGWLBReturnCIDRs())[0]
	conflictOps.routes[routeKey(target.family, cfg.RoutingTableID, target.cidr, cfg.TunName)] = stateConflict
	conflictMgr, _ := newTestManager(t, cfg, conflictOps, time.Hour)
	err := conflictMgr.Initialize(context.Background())
	if err == nil || conflictMgr.HealthReason() != metrics.RoutingFailureReasonOwnership {
		t.Fatalf("conflict err=%v reason=%q", err, conflictMgr.HealthReason())
	}
	_ = mgr.releaseLock()
}

func TestApplyRollbackAndCleanupAttemptAllObjects(t *testing.T) {
	cfg := routingConfig(t, config.RoutingModeManage, "10.10.0.0/24", "10.11.0.0/24")
	ops := readyFakeOps(cfg)
	targets := buildTargets(cfg.EffectiveGWLBReturnCIDRs())
	failed := routeKey(targets[1].family, cfg.RoutingTableID, targets[1].cidr, cfg.TunName)
	ops.addRouteErrors[failed] = errors.New("injected add failure")
	mgr, metricSet := newTestManager(t, cfg, ops, time.Hour)
	if err := mgr.Initialize(context.Background()); err == nil {
		t.Fatal("manage startup accepted partial apply")
	}
	if len(ops.rules) != 0 || len(ops.routes) != 0 || len(mgr.ownedRules) != 0 || len(mgr.ownedRoutes) != 0 {
		t.Fatalf("rollback left state rules=%v routes=%v", ops.rules, ops.routes)
	}
	if got := testutil.ToFloat64(metricSet.RoutingOwnershipDecisions.WithLabelValues(metrics.RoutingOwnershipRolledBack)); got != 1 {
		t.Fatalf("rollback decisions=%v", got)
	}

	delete(ops.addRouteErrors, failed)
	if err := mgr.Initialize(context.Background()); err != nil {
		t.Fatalf("second initialize: %v", err)
	}
	ops.deleteRouteErrs[routeKey(targets[0].family, cfg.RoutingTableID, targets[0].cidr, cfg.TunName)] = errors.New("route cleanup")
	ops.deleteRuleErrors[ruleKey(targets[1].family, cfg.RoutingRulePriority, cfg.TailscaleIface, targets[1].cidr, cfg.RoutingTableID)] = errors.New("rule cleanup")
	if err := mgr.cleanupManaged(); err == nil {
		t.Fatal("cleanup did not join object errors")
	}
	if len(ops.deleteAttempts) != 5 {
		t.Fatalf("delete attempts=%d, want 1 rollback plus all 4 cleanup: %v", len(ops.deleteAttempts), ops.deleteAttempts)
	}
	if ops.cleanupDeadlines != len(ops.deleteAttempts) {
		t.Fatalf("deadline-scoped deletes=%d attempts=%d", ops.cleanupDeadlines, len(ops.deleteAttempts))
	}
}

func TestSuccessfulMutationWithFailedRereadIsRolledBack(t *testing.T) {
	tests := []struct {
		name    string
		prepare func(*config.Config, *fakeOps, targetRoute)
		assert  func(*testing.T, *config.Config, *fakeOps, targetRoute)
	}{
		{
			name: "route",
			prepare: func(cfg *config.Config, ops *fakeOps, target targetRoute) {
				key := routeKey(target.family, cfg.RoutingTableID, target.cidr, cfg.TunName)
				ops.routeStateErrors[key] = []error{nil, errors.New("injected route reread failure")}
			},
			assert: func(t *testing.T, cfg *config.Config, ops *fakeOps, target targetRoute) {
				t.Helper()
				key := routeKey(target.family, cfg.RoutingTableID, target.cidr, cfg.TunName)
				if ops.routes[key] != stateAbsent || !contains(strings.Join(ops.deleteAttempts, "\n"), "route:"+key) {
					t.Fatalf("route was not rolled back: state=%d deletes=%v", ops.routes[key], ops.deleteAttempts)
				}
			},
		},
		{
			name: "rule",
			prepare: func(cfg *config.Config, ops *fakeOps, target targetRoute) {
				ops.routes[routeKey(target.family, cfg.RoutingTableID, target.cidr, cfg.TunName)] = stateOperator
				key := ruleKey(target.family, cfg.RoutingRulePriority, cfg.TailscaleIface, target.cidr, cfg.RoutingTableID)
				ops.ruleStateErrors[key] = []error{nil, errors.New("injected rule reread failure")}
			},
			assert: func(t *testing.T, cfg *config.Config, ops *fakeOps, target targetRoute) {
				t.Helper()
				key := ruleKey(target.family, cfg.RoutingRulePriority, cfg.TailscaleIface, target.cidr, cfg.RoutingTableID)
				if ops.rules[key] != stateAbsent || !contains(strings.Join(ops.deleteAttempts, "\n"), "rule:"+key) {
					t.Fatalf("rule was not rolled back: state=%d deletes=%v", ops.rules[key], ops.deleteAttempts)
				}
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := routingConfig(t, config.RoutingModeManage)
			ops := readyFakeOps(cfg)
			target := buildTargets(cfg.EffectiveGWLBReturnCIDRs())[0]
			tt.prepare(cfg, ops, target)
			mgr, metricSet := newTestManager(t, cfg, ops, time.Hour)
			if err := mgr.Initialize(context.Background()); err == nil {
				t.Fatal("manage startup accepted a mutation whose reread failed")
			}
			tt.assert(t, cfg, ops, target)
			if len(mgr.ownedRoutes) != 0 || len(mgr.ownedRules) != 0 {
				t.Fatalf("rollback left ownership: routes=%v rules=%v", mgr.ownedRoutes, mgr.ownedRules)
			}
			if got := testutil.ToFloat64(metricSet.RoutingOwnershipDecisions.WithLabelValues(metrics.RoutingOwnershipRolledBack)); got != 1 {
				t.Fatalf("rollback decisions=%v, want 1", got)
			}
			if got := testutil.ToFloat64(metricSet.RoutingOwnershipDecisions.WithLabelValues(metrics.RoutingOwnershipCleanupFailure)); got != 0 {
				t.Fatalf("cleanup failures=%v, want 0", got)
			}
			if got := testutil.ToFloat64(metricSet.RoutingOwnershipDecisions.WithLabelValues(metrics.RoutingOwnershipRemoved)); got != 0 {
				t.Fatalf("removed decisions=%v, want 0", got)
			}
		})
	}
}

func TestSuccessfulMutationWithConflictRereadIsRolledBack(t *testing.T) {
	tests := []struct {
		name    string
		prepare func(*config.Config, *fakeOps, targetRoute)
		assert  func(*testing.T, *config.Config, *fakeOps, targetRoute)
	}{
		{
			name: "route",
			prepare: func(cfg *config.Config, ops *fakeOps, target targetRoute) {
				key := routeKey(target.family, cfg.RoutingTableID, target.cidr, cfg.TunName)
				ops.addRouteStates[key] = stateConflict
			},
			assert: func(t *testing.T, cfg *config.Config, ops *fakeOps, target targetRoute) {
				t.Helper()
				key := routeKey(target.family, cfg.RoutingTableID, target.cidr, cfg.TunName)
				if ops.routes[key] != stateAbsent || !contains(strings.Join(ops.deleteAttempts, "\n"), "route:"+key) {
					t.Fatalf("conflicting route was not rolled back: state=%d deletes=%v", ops.routes[key], ops.deleteAttempts)
				}
			},
		},
		{
			name: "rule",
			prepare: func(cfg *config.Config, ops *fakeOps, target targetRoute) {
				ops.routes[routeKey(target.family, cfg.RoutingTableID, target.cidr, cfg.TunName)] = stateOperator
				key := ruleKey(target.family, cfg.RoutingRulePriority, cfg.TailscaleIface, target.cidr, cfg.RoutingTableID)
				ops.addRuleStates[key] = stateConflict
			},
			assert: func(t *testing.T, cfg *config.Config, ops *fakeOps, target targetRoute) {
				t.Helper()
				key := ruleKey(target.family, cfg.RoutingRulePriority, cfg.TailscaleIface, target.cidr, cfg.RoutingTableID)
				if ops.rules[key] != stateAbsent || !contains(strings.Join(ops.deleteAttempts, "\n"), "rule:"+key) {
					t.Fatalf("conflicting rule was not rolled back: state=%d deletes=%v", ops.rules[key], ops.deleteAttempts)
				}
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := routingConfig(t, config.RoutingModeManage)
			ops := readyFakeOps(cfg)
			target := buildTargets(cfg.EffectiveGWLBReturnCIDRs())[0]
			tt.prepare(cfg, ops, target)
			mgr, metricSet := newTestManager(t, cfg, ops, time.Hour)
			if err := mgr.Initialize(context.Background()); err == nil {
				t.Fatal("manage startup accepted a successful add with a conflicting reread")
			}
			tt.assert(t, cfg, ops, target)
			if len(mgr.ownedRoutes) != 0 || len(mgr.ownedRules) != 0 {
				t.Fatalf("rollback left ownership: routes=%v rules=%v", mgr.ownedRoutes, mgr.ownedRules)
			}
			if got := testutil.ToFloat64(metricSet.RoutingOwnershipDecisions.WithLabelValues(metrics.RoutingOwnershipRolledBack)); got != 1 {
				t.Fatalf("rollback decisions=%v, want 1", got)
			}
			if got := testutil.ToFloat64(metricSet.RoutingOwnershipDecisions.WithLabelValues(metrics.RoutingOwnershipCleanupFailure)); got != 0 {
				t.Fatalf("cleanup failures=%v, want 0", got)
			}
			if got := testutil.ToFloat64(metricSet.RoutingOwnershipDecisions.WithLabelValues(metrics.RoutingOwnershipRemoved)); got != 0 {
				t.Fatalf("removed decisions=%v, want 0", got)
			}
		})
	}
}

func TestCleanupRetainsOwnershipWhenConflictPersistsAfterDelete(t *testing.T) {
	tests := []struct {
		name    string
		prepare func(*config.Config, *fakeOps, *manager, targetRoute)
		assert  func(*testing.T, *config.Config, *fakeOps, *manager, targetRoute)
	}{
		{
			name: "route",
			prepare: func(cfg *config.Config, ops *fakeOps, mgr *manager, target targetRoute) {
				key := routeKey(target.family, cfg.RoutingTableID, target.cidr, cfg.TunName)
				ops.routes[key] = stateConflict
				ops.deleteRouteNoops[key] = true
				mgr.ownedRoutes[targetKey(target)] = target
			},
			assert: func(t *testing.T, cfg *config.Config, ops *fakeOps, mgr *manager, target targetRoute) {
				t.Helper()
				key := routeKey(target.family, cfg.RoutingTableID, target.cidr, cfg.TunName)
				if ops.routes[key] != stateConflict || len(mgr.ownedRoutes) != 1 || !contains(strings.Join(ops.deleteAttempts, "\n"), "route:"+key) {
					t.Fatalf("route conflict was discarded: state=%d ownership=%v deletes=%v", ops.routes[key], mgr.ownedRoutes, ops.deleteAttempts)
				}
			},
		},
		{
			name: "rule",
			prepare: func(cfg *config.Config, ops *fakeOps, mgr *manager, target targetRoute) {
				key := ruleKey(target.family, cfg.RoutingRulePriority, cfg.TailscaleIface, target.cidr, cfg.RoutingTableID)
				ops.rules[key] = stateConflict
				ops.deleteRuleNoops[key] = true
				mgr.ownedRules[targetKey(target)] = target
			},
			assert: func(t *testing.T, cfg *config.Config, ops *fakeOps, mgr *manager, target targetRoute) {
				t.Helper()
				key := ruleKey(target.family, cfg.RoutingRulePriority, cfg.TailscaleIface, target.cidr, cfg.RoutingTableID)
				if ops.rules[key] != stateConflict || len(mgr.ownedRules) != 1 || !contains(strings.Join(ops.deleteAttempts, "\n"), "rule:"+key) {
					t.Fatalf("rule conflict was discarded: state=%d ownership=%v deletes=%v", ops.rules[key], mgr.ownedRules, ops.deleteAttempts)
				}
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := routingConfig(t, config.RoutingModeManage)
			ops := readyFakeOps(cfg)
			target := buildTargets(cfg.EffectiveGWLBReturnCIDRs())[0]
			mgr, metricSet := newTestManager(t, cfg, ops, time.Hour)
			tt.prepare(cfg, ops, mgr, target)
			if err := mgr.cleanupManaged(); err == nil {
				t.Fatal("cleanup accepted a persistent ownership conflict")
			}
			tt.assert(t, cfg, ops, mgr, target)
			if got := testutil.ToFloat64(metricSet.RoutingOwnershipDecisions.WithLabelValues(metrics.RoutingOwnershipCleanupFailure)); got != 1 {
				t.Fatalf("cleanup failures=%v, want 1", got)
			}
			if got := testutil.ToFloat64(metricSet.RoutingOwnershipDecisions.WithLabelValues(metrics.RoutingOwnershipRemoved)); got != 0 {
				t.Fatalf("removed decisions=%v, want 0", got)
			}
			if got := testutil.ToFloat64(metricSet.RoutingOwnershipDecisions.WithLabelValues(metrics.RoutingOwnershipRolledBack)); got != 0 {
				t.Fatalf("rollback decisions=%v, want 0", got)
			}
		})
	}
}

func TestFailedMutationNeverClaimsObservedProtocolState(t *testing.T) {
	tests := []struct {
		name    string
		prepare func(*config.Config, *fakeOps, targetRoute)
		assert  func(*testing.T, *config.Config, *fakeOps, targetRoute)
	}{
		{
			name: "route",
			prepare: func(cfg *config.Config, ops *fakeOps, target targetRoute) {
				key := routeKey(target.family, cfg.RoutingTableID, target.cidr, cfg.TunName)
				ops.addRouteErrors[key] = errors.New("ambiguous route add failure")
				ops.addRouteStates[key] = stateOwned
			},
			assert: func(t *testing.T, cfg *config.Config, ops *fakeOps, target targetRoute) {
				t.Helper()
				key := routeKey(target.family, cfg.RoutingTableID, target.cidr, cfg.TunName)
				if ops.routes[key] != stateOwned {
					t.Fatalf("observed route state=%d, want preserved", ops.routes[key])
				}
			},
		},
		{
			name: "rule",
			prepare: func(cfg *config.Config, ops *fakeOps, target targetRoute) {
				ops.routes[routeKey(target.family, cfg.RoutingTableID, target.cidr, cfg.TunName)] = stateOperator
				key := ruleKey(target.family, cfg.RoutingRulePriority, cfg.TailscaleIface, target.cidr, cfg.RoutingTableID)
				ops.addRuleErrors[key] = errors.New("ambiguous rule add failure")
				ops.addRuleStates[key] = stateOwned
			},
			assert: func(t *testing.T, cfg *config.Config, ops *fakeOps, target targetRoute) {
				t.Helper()
				key := ruleKey(target.family, cfg.RoutingRulePriority, cfg.TailscaleIface, target.cidr, cfg.RoutingTableID)
				if ops.rules[key] != stateOwned {
					t.Fatalf("observed rule state=%d, want preserved", ops.rules[key])
				}
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := routingConfig(t, config.RoutingModeManage)
			ops := readyFakeOps(cfg)
			target := buildTargets(cfg.EffectiveGWLBReturnCIDRs())[0]
			tt.prepare(cfg, ops, target)
			mgr, _ := newTestManager(t, cfg, ops, time.Hour)
			if err := mgr.Initialize(context.Background()); err == nil {
				t.Fatal("manage startup accepted an ambiguous add failure")
			}
			tt.assert(t, cfg, ops, target)
			if len(ops.deleteAttempts) != 0 || len(mgr.ownedRoutes) != 0 || len(mgr.ownedRules) != 0 {
				t.Fatalf("ambiguous state was claimed or deleted: deletes=%v routes=%v rules=%v", ops.deleteAttempts, mgr.ownedRoutes, mgr.ownedRules)
			}
			if mgr.HealthReason() != metrics.RoutingFailureReasonOwnership {
				t.Fatalf("health reason=%q, want ownership", mgr.HealthReason())
			}
		})
	}
}

func TestLockFailureModeBehavior(t *testing.T) {
	cfg := routingConfig(t, config.RoutingModeManage)
	ops := readyFakeOps(cfg)
	ops.lockErr = errors.New("busy")
	mgr, metricSet := newTestManager(t, cfg, ops, time.Hour)
	if err := mgr.Initialize(context.Background()); err == nil {
		t.Fatal("manage mode did not fail startup on lock failure")
	}
	if mgr.Ready() || mgr.HealthReason() != metrics.RoutingFailureReasonOwnership {
		t.Fatalf("ready=%v reason=%q", mgr.Ready(), mgr.HealthReason())
	}
	if got := testutil.ToFloat64(metricSet.RoutingValidationFailures.WithLabelValues(metrics.RoutingFailureReasonOwnership)); got != 1 {
		t.Fatalf("ownership metric=%v", got)
	}

	verifyCfg := routingConfig(t, config.RoutingModeVerify)
	verifyOps := readyFakeOps(verifyCfg)
	addEquivalentReturnState(verifyCfg, verifyOps)
	verifyOps.lockErr = errors.New("must not be consulted")
	verifyMgr, _ := newTestManager(t, verifyCfg, verifyOps, time.Hour)
	if err := verifyMgr.Initialize(context.Background()); err != nil || !verifyMgr.Ready() || verifyOps.locks != 0 {
		t.Fatalf("verify lock behavior ready=%v locks=%d err=%v", verifyMgr.Ready(), verifyOps.locks, err)
	}
}

func TestManagedRunRepairsOwnedDriftAndCleansUp(t *testing.T) {
	cfg := routingConfig(t, config.RoutingModeManage)
	ops := readyFakeOps(cfg)
	mgr, metricSet := newTestManager(t, cfg, ops, 2*time.Millisecond)
	if err := mgr.Initialize(context.Background()); err != nil {
		t.Fatal(err)
	}
	target := buildTargets(cfg.EffectiveGWLBReturnCIDRs())[0]
	rule := ruleKey(target.family, cfg.RoutingRulePriority, cfg.TailscaleIface, target.cidr, cfg.RoutingTableID)
	delete(ops.rules, rule)
	changed, err := mgr.ensureManaged(context.Background(), false)
	if err != nil || !changed || ops.rules[rule] != stateOwned {
		t.Fatalf("drift repair changed=%v err=%v state=%v", changed, err, ops.rules[rule])
	}
	if got := testutil.ToFloat64(metricSet.RoutingDriftRepairs); got != 1 {
		t.Fatalf("drift repairs=%v", got)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- mgr.Run(ctx) }()
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("run: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Run did not stop")
	}
	if len(ops.rules) != 0 || len(ops.routes) != 0 {
		t.Fatalf("Run cleanup left state rules=%v routes=%v", ops.rules, ops.routes)
	}
}

func TestManagedRunDetectsWithdrawalAndRecovery(t *testing.T) {
	cfg := routingConfig(t, config.RoutingModeManage)
	ops := readyFakeOps(cfg)
	mgr, _ := newTestManager(t, cfg, ops, 2*time.Millisecond)
	if err := mgr.Initialize(context.Background()); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- mgr.Run(ctx) }()

	ops.mu.Lock()
	ops.status.Peer = nil
	ops.mu.Unlock()
	waitForManagerState(t, mgr, false, metrics.RoutingFailureReasonRouteWithdrawn)

	restored := readyFakeOps(cfg).status.Peer
	ops.mu.Lock()
	ops.status.Peer = restored
	ops.mu.Unlock()
	waitForManagerState(t, mgr, true, "ok")

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("run: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Run did not stop")
	}
}

func waitForManagerState(t *testing.T, mgr *manager, ready bool, reason string) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if mgr.Ready() == ready && mgr.HealthReason() == reason {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("manager ready=%v reason=%q, want ready=%v reason=%q", mgr.Ready(), mgr.HealthReason(), ready, reason)
}

func TestStatusIsRoleSpecificAndOffModeIsNeutral(t *testing.T) {
	cfg := routingConfig(t, config.RoutingModeVerify)
	ops := readyFakeOps(cfg)
	addEquivalentReturnState(cfg, ops)
	mgr, _ := newTestManager(t, cfg, ops, time.Hour)
	_ = mgr.Initialize(context.Background())
	status := mgr.Status()
	if !status.Ready || len(status.GWLBReturnCIDRs) != 1 || len(status.LocalDeliveryCIDRs) != 1 || len(status.RemoteTailnetCIDRs) != 1 {
		t.Fatalf("unexpected status: %+v", status)
	}

	offCfg, err := config.Parse([]string{"--udp-bind=:6081", "--metrics-addr=:9090"})
	if err != nil {
		t.Fatal(err)
	}
	offOps := newFakeOps()
	off, _ := newTestManager(t, offCfg, offOps, time.Millisecond)
	if err := off.Initialize(context.Background()); err != nil || !off.Ready() {
		t.Fatalf("off initialize ready=%v err=%v", off.Ready(), err)
	}
	if len(offOps.queries) != 0 || offOps.locks != 0 {
		t.Fatalf("off mode touched host state: queries=%v locks=%d", offOps.queries, offOps.locks)
	}
}

func TestRouteHelpers(t *testing.T) {
	if got := prefixBoundaryAddresses("10.0.0.0/24"); len(got) != 2 || got[0] != "10.0.0.0" || got[1] != "10.0.0.255" {
		t.Fatalf("IPv4 boundaries=%v", got)
	}
	if got := prefixBoundaryAddresses("2001:db8::/64"); len(got) != 2 || got[0] != "2001:db8::" || got[1] != "2001:db8::ffff:ffff:ffff:ffff" {
		t.Fatalf("IPv6 boundaries=%v", got)
	}
	if !routeSetCovers([]string{"10.0.0.0/8"}, "10.20.0.0/16") || routeSetCovers([]string{"10.20.0.0/24"}, "10.20.0.0/16") {
		t.Fatal("route coverage contract failed")
	}
	if !ruleMatchesZeroMark(policyRule{HasMark: true, Mark: 1, Mask: 0}) || ruleMatchesZeroMark(policyRule{HasMark: true, Mark: 1, Mask: ^uint32(0)}) {
		t.Fatal("zero-mark policy mask semantics failed")
	}
}

func contains(value, fragment string) bool {
	for index := 0; index+len(fragment) <= len(value); index++ {
		if value[index:index+len(fragment)] == fragment {
			return true
		}
	}
	return false
}
