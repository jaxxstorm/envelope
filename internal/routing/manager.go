package routing

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jaxxstorm/envelope/internal/config"
	"github.com/jaxxstorm/envelope/internal/metrics"
	"go.uber.org/zap"
)

const (
	defaultReconcileInterval = 30 * time.Second
	cleanupObjectTimeout     = 2 * time.Second
	ipv4ForwardingPath       = "/proc/sys/net/ipv4/ip_forward"
	ipv6ForwardingPath       = "/proc/sys/net/ipv6/conf/all/forwarding"
	ipv4RPFilterAllPath      = "/proc/sys/net/ipv4/conf/all/rp_filter"
	ownerProtocol            = 186
	supportedTailscaleMajor  = 1
	supportedTailscaleMinor  = 80
	mainRouteTable           = 254
	localRouteTable          = 255
	filterChainName          = "ENVELOPE-FORWARD"
	mssChainName             = "ENVELOPE-MSS"
)

var (
	errMSSContract                         = errors.New("MSS contract validation failed")
	errSupplementaryRouteLookupUnavailable = errors.New("supplementary route lookup unavailable")
)

var forwardingDirections = [][2]string{
	{"envelope", "underlay"},
	{"envelope", "tailscale"},
}

type Manager interface {
	Initialize(context.Context) error
	Run(context.Context) error
	Ready() bool
	HealthReason() string
	Mode() config.RoutingMode
	Status() Status
}

type Status struct {
	Mode               string   `json:"mode"`
	Ready              bool     `json:"ready"`
	Reason             string   `json:"reason"`
	EnvelopeInterface  string   `json:"envelope_interface"`
	TailscaleInterface string   `json:"tailscale_interface"`
	UnderlayInterface  string   `json:"underlay_interface"`
	LocalSiteCIDRs     []string `json:"local_site_cidrs"`
	RemoteSiteCIDRs    []string `json:"remote_site_cidrs"`
	RoutingTableID     int      `json:"routing_table_id"`
	RulePriority       int      `json:"rule_priority"`
	OwnerProtocol      int      `json:"owner_protocol"`
	TailscaleSchema    string   `json:"tailscale_status_schema"`
}

type interfaceInfo struct {
	Name string
	MTU  int
}

type routeQuery struct {
	Family      string
	Destination string
	Source      string
	Input       string
}

type routeResult struct {
	Device   string
	Table    int
	Type     string
	Protocol int
}

type routeEntry struct {
	Family   string
	Prefix   string
	Source   string
	Device   string
	Table    int
	Type     string
	Protocol int
}

type policyRule struct {
	Family               string
	Priority             int
	Source               string
	Destination          string
	Input                string
	Table                int
	Action               string
	Protocol             int
	Mark                 uint32
	Mask                 uint32
	HasMark              bool
	Invert               bool
	SuppressPrefixLength int
	Unsupported          bool
}

type tailscalePeerStatus struct {
	TailscaleIPs  []string `json:"TailscaleIPs"`
	AllowedIPs    []string `json:"AllowedIPs"`
	PrimaryRoutes []string `json:"PrimaryRoutes"`
	Online        bool     `json:"Online"`
	Expired       bool     `json:"Expired"`
	InNetworkMap  bool     `json:"InNetworkMap"`
	InMagicSock   bool     `json:"InMagicSock"`
	InEngine      bool     `json:"InEngine"`
}

type tailscaleStatus struct {
	Version      string                          `json:"Version"`
	TUN          bool                            `json:"TUN"`
	BackendState string                          `json:"BackendState"`
	Health       []string                        `json:"Health"`
	Self         *tailscalePeerStatus            `json:"Self"`
	Peer         map[string]*tailscalePeerStatus `json:"Peer"`
}

type objectState uint8

const (
	stateAbsent objectState = iota
	stateOperator
	stateOwned
	stateConflict
)

type forwardingPathContract struct {
	Family  string
	Input   string
	Output  string
	PathMTU int
	MSS     int
}

type routingLock interface {
	Release() error
}

type systemOps interface {
	InterfaceInfo(name string) (interfaceInfo, error)
	SysctlValue(path string) (int, error)
	AcquireLock() (routingLock, error)
	RuleState(ctx context.Context, family string, priority int, iif, cidr string, table, protocol int) (objectState, error)
	AddRule(ctx context.Context, family string, priority int, iif, cidr string, table, protocol int) error
	DeleteRule(ctx context.Context, family string, priority int, iif, cidr string, table, protocol int) error
	RouteState(ctx context.Context, family string, table int, cidr, dev string, protocol int) (objectState, error)
	AddRoute(ctx context.Context, family string, table int, cidr, dev string, protocol int) error
	DeleteRoute(ctx context.Context, family string, table int, cidr, dev string, protocol int) error
	RouteLookup(ctx context.Context, query routeQuery) (routeResult, error)
	Rules(ctx context.Context, family string) ([]policyRule, error)
	Routes(ctx context.Context, family string, table int) ([]routeEntry, error)
	TailscaleStatus(ctx context.Context) (tailscaleStatus, error)
	TailscalePing(ctx context.Context, address string) error
	ValidateFirewall(ctx context.Context, contracts []forwardingPathContract) error
}

type targetRoute struct {
	family string
	cidr   string
}

type reasonError struct {
	reason string
	err    error
}

func (e *reasonError) Error() string { return e.err.Error() }
func (e *reasonError) Unwrap() error { return e.err }

type manager struct {
	cfg            *config.Config
	log            *zap.Logger
	metrics        *metrics.Metrics
	op             systemOps
	reconcileEvery time.Duration
	routingMode    config.RoutingMode
	ready          atomic.Bool
	reason         atomic.Value
	mu             sync.Mutex
	hostLock       routingLock
	seenRemote     map[string]bool
}

func New(cfg *config.Config, log *zap.Logger, metricSet *metrics.Metrics) (Manager, error) {
	if cfg == nil {
		return nil, errors.New("config is required")
	}
	mode := cfg.RoutingMode
	if mode == "" {
		mode = config.RoutingModeOff
	}
	if mode != config.RoutingModeOff && runtime.GOOS != "linux" {
		return nil, errors.New("routing integration is only supported on linux")
	}
	return newManager(cfg, log, metricSet, newSystemOps(), defaultReconcileInterval)
}

func newManager(cfg *config.Config, log *zap.Logger, metricSet *metrics.Metrics, op systemOps, interval time.Duration) (Manager, error) {
	if cfg == nil {
		return nil, errors.New("config is required")
	}
	if log == nil {
		log = zap.NewNop()
	}
	if metricSet == nil {
		return nil, errors.New("metrics is required")
	}
	if op == nil {
		return nil, errors.New("routing system operations are required")
	}
	mode := cfg.RoutingMode
	if mode == "" {
		mode = config.RoutingModeOff
	}
	if interval <= 0 {
		interval = defaultReconcileInterval
	}
	mgr := &manager{
		cfg:            cfg,
		log:            log,
		metrics:        metricSet,
		op:             op,
		reconcileEvery: interval,
		routingMode:    mode,
		seenRemote:     make(map[string]bool),
	}
	mgr.reason.Store("not_checked")
	if mode == config.RoutingModeOff {
		mgr.setReady(true, "ok")
	} else {
		mgr.setReady(false, "not_checked")
	}
	return mgr, nil
}

func (m *manager) Mode() config.RoutingMode { return m.routingMode }
func (m *manager) Ready() bool              { return m.ready.Load() }

func (m *manager) HealthReason() string {
	reason, _ := m.reason.Load().(string)
	if reason == "" {
		return "not_checked"
	}
	return reason
}

func (m *manager) Status() Status {
	return Status{
		Mode:               string(m.routingMode),
		Ready:              m.Ready(),
		Reason:             m.HealthReason(),
		EnvelopeInterface:  m.cfg.TunName,
		TailscaleInterface: m.cfg.TailscaleIface,
		UnderlayInterface:  m.cfg.UnderlayIface,
		LocalSiteCIDRs:     m.cfg.EffectiveLocalSiteCIDRs(),
		RemoteSiteCIDRs:    m.cfg.EffectiveRemoteSiteCIDRs(),
		RoutingTableID:     m.cfg.RoutingTableID,
		RulePriority:       m.cfg.RoutingRulePriority,
		OwnerProtocol:      ownerProtocol,
		TailscaleSchema:    fmt.Sprintf("ipnstate.Status/v%d.%d", supportedTailscaleMajor, supportedTailscaleMinor),
	}
}

func (m *manager) Initialize(ctx context.Context) error {
	switch m.routingMode {
	case config.RoutingModeOff:
		m.setReady(true, "ok")
		return nil
	case config.RoutingModeVerify:
		_ = m.reconcile(ctx, true)
		return nil
	case config.RoutingModeManage:
		lock, err := m.op.AcquireLock()
		if err != nil {
			m.recordFailure(fail(metrics.RoutingFailureReasonOwnership, "acquire routing ownership lock: %v", err))
			return fmt.Errorf("initialize managed routing: %w", err)
		}
		m.hostLock = lock
		if err := m.reconcile(ctx, true); err != nil {
			cleanupErr := m.cleanupManaged()
			releaseErr := m.releaseLock()
			return fmt.Errorf("initialize managed routing: %w", errors.Join(err, cleanupErr, releaseErr))
		}
		return nil
	default:
		return fmt.Errorf("unsupported routing mode %q", m.routingMode)
	}
}

func (m *manager) Run(ctx context.Context) error {
	if m.routingMode == config.RoutingModeOff {
		<-ctx.Done()
		return nil
	}
	ticker := time.NewTicker(m.reconcileEvery)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			if m.routingMode == config.RoutingModeManage {
				if err := m.cleanupManaged(); err != nil {
					m.log.Warn("routing cleanup failed", zap.Error(err))
				}
				if err := m.releaseLock(); err != nil {
					m.log.Warn("routing lock release failed", zap.Error(err))
				}
			}
			m.setReady(false, "stopped")
			return nil
		case <-ticker.C:
			_ = m.reconcile(ctx, false)
		}
	}
}

func (m *manager) reconcile(ctx context.Context, initial bool) error {
	var err error
	switch m.routingMode {
	case config.RoutingModeManage:
		_, err = m.ensureManaged(ctx, initial)
	case config.RoutingModeVerify:
		err = m.verify(ctx)
	}
	if err == nil {
		m.setReady(true, "ok")
		return nil
	}
	m.recordFailure(err)
	return err
}

func (m *manager) recordFailure(err error) {
	reason := failureReason(err)
	m.metrics.RoutingValidationFailures.WithLabelValues(reason).Inc()
	m.setReady(false, reason)
	m.log.Warn("routing readiness check failed", zap.String("reason", reason), zap.Error(err))
}

func (m *manager) setReady(ready bool, reason string) {
	m.ready.Store(ready)
	m.reason.Store(reason)
	if ready {
		m.metrics.RoutingReady.Set(1)
	} else {
		m.metrics.RoutingReady.Set(0)
	}
}

func (m *manager) releaseLock() error {
	if m.hostLock == nil {
		return nil
	}
	err := m.hostLock.Release()
	m.hostLock = nil
	return err
}

func (m *manager) cleanupManaged() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), cleanupObjectTimeout)
	defer cancel()
	var errs []error
	for _, target := range buildTargets(m.cfg.EffectiveLocalSiteCIDRs()) {
		state, err := m.op.RuleState(ctx, target.family, m.cfg.RoutingRulePriority, m.cfg.TunName, target.cidr, mainRouteTable, ownerProtocol)
		if err != nil {
			errs = append(errs, fmt.Errorf("inspect managed post-inspection rule for %s: %w", target.cidr, err))
			continue
		}
		switch state {
		case stateOwned:
			if err := m.op.DeleteRule(ctx, target.family, m.cfg.RoutingRulePriority, m.cfg.TunName, target.cidr, mainRouteTable, ownerProtocol); err != nil {
				errs = append(errs, fmt.Errorf("delete managed post-inspection rule for %s: %w", target.cidr, err))
			}
		case stateConflict:
			errs = append(errs, fmt.Errorf("managed post-inspection rule for %s is conflicted; refusing to delete it", target.cidr))
		}
	}
	return errors.Join(errs...)
}

func (m *manager) ensureManaged(ctx context.Context, initial bool) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.metrics.RoutingApplyAttempts.Inc()
	if err := m.ensurePostInspectionRules(ctx); err != nil {
		m.metrics.RoutingApplyFailures.Inc()
		return false, err
	}
	if err := m.verifyPrerequisites(ctx); err != nil {
		m.metrics.RoutingApplyFailures.Inc()
		return false, err
	}

	if err := m.verifyTargetRoutes(ctx); err != nil {
		m.metrics.RoutingApplyFailures.Inc()
		return false, err
	}
	return false, nil
}

func (m *manager) ensurePostInspectionRules(ctx context.Context) error {
	for _, target := range buildTargets(m.cfg.EffectiveLocalSiteCIDRs()) {
		state, err := m.op.RuleState(ctx, target.family, m.cfg.RoutingRulePriority, m.cfg.TunName, target.cidr, mainRouteTable, ownerProtocol)
		if err != nil {
			return fail(metrics.RoutingFailureReasonOwnership, "inspect post-inspection rule for %s: %v", target.cidr, err)
		}
		switch state {
		case stateAbsent:
			if err := m.op.AddRule(ctx, target.family, m.cfg.RoutingRulePriority, m.cfg.TunName, target.cidr, mainRouteTable, ownerProtocol); err != nil {
				return fail(metrics.RoutingFailureReasonOwnership, "add post-inspection rule for %s: %v", target.cidr, err)
			}
		case stateOwned, stateOperator:
			// An exact operator rule already meets the contract and is never claimed.
		case stateConflict:
			return fail(metrics.RoutingFailureReasonOwnership, "post-inspection rule for %s conflicts with an existing policy rule", target.cidr)
		}
	}
	return nil
}

func (m *manager) verify(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.verifyPrerequisites(ctx); err != nil {
		return err
	}
	return m.verifyTargetRoutes(ctx)
}

func (m *manager) verifyPrerequisites(ctx context.Context) error {
	interfaces, err := m.checkInterfaces()
	if err != nil {
		return err
	}
	status, err := m.op.TailscaleStatus(ctx)
	if err != nil {
		return fail(metrics.RoutingFailureReasonBackend, "read bounded Tailscale status: %v", err)
	}
	servingPeers, err := m.validateTailscaleStatus(status)
	if err != nil {
		return err
	}
	if err := m.checkHostPrerequisites(ctx, interfaces); err != nil {
		return err
	}
	if err := m.validateTailscaleFIB(ctx); err != nil {
		return err
	}
	for _, address := range servingPeers {
		if err := m.op.TailscalePing(ctx, address); err != nil {
			return fail(metrics.RoutingFailureReasonBackend, "Tailscale data-plane ping to route-serving peer %s failed: %v", address, err)
		}
	}
	return nil
}

func (m *manager) checkInterfaces() (map[string]interfaceInfo, error) {
	interfaces := make(map[string]interfaceInfo, 3)
	for role, name := range map[string]string{"envelope": m.cfg.TunName, "tailscale": m.cfg.TailscaleIface, "underlay": m.cfg.UnderlayIface} {
		info, err := m.op.InterfaceInfo(name)
		if err != nil {
			return nil, fail(metrics.RoutingFailureReasonInterface, "inspect %s interface %q: %v", role, name, err)
		}
		if info.Name != name || info.MTU <= 0 {
			return nil, fail(metrics.RoutingFailureReasonInterface, "%s interface %q has invalid identity or MTU", role, name)
		}
		interfaces[role] = info
	}
	return interfaces, nil
}

func (m *manager) validateTailscaleStatus(status tailscaleStatus) ([]string, error) {
	if err := validateTailscaleVersion(status.Version); err != nil {
		return nil, fail(metrics.RoutingFailureReasonBackend, "%v", err)
	}
	if !status.TUN {
		return nil, fail(metrics.RoutingFailureReasonBackend, "tailscaled is not using kernel TUN mode")
	}
	if status.BackendState != "Running" {
		return nil, fail(metrics.RoutingFailureReasonBackend, "tailscaled backend is %q, want Running", status.BackendState)
	}
	if len(status.Health) != 0 {
		return nil, fail(metrics.RoutingFailureReasonBackend, "tailscaled reports %d health problem(s)", len(status.Health))
	}
	if status.Self == nil || !status.Self.Online || status.Self.Expired {
		return nil, fail(metrics.RoutingFailureReasonBackend, "tailscaled self status is offline, missing, or expired")
	}
	serving := make(map[string]struct{})
	for _, cidr := range m.cfg.EffectiveRemoteSiteCIDRs() {
		found := false
		for _, peer := range status.Peer {
			if peer == nil || !peer.Online || peer.Expired || !peer.InNetworkMap || !peer.InMagicSock || !peer.InEngine || !routeSetCovers(peer.PrimaryRoutes, cidr) {
				continue
			}
			for _, address := range peer.TailscaleIPs {
				if ip, err := netip.ParseAddr(address); err == nil && ip.IsValid() {
					serving[ip.String()] = struct{}{}
					found = true
					break
				}
			}
		}
		if !found {
			if m.seenRemote[cidr] {
				return nil, fail(metrics.RoutingFailureReasonRouteWithdrawn, "remote Tailnet route %s has no online non-expired serving peer", cidr)
			}
			return nil, fail(metrics.RoutingFailureReasonRouteUnavailable, "remote Tailnet route %s has no online non-expired serving peer", cidr)
		}
		m.seenRemote[cidr] = true
	}
	addresses := make([]string, 0, len(serving))
	for address := range serving {
		addresses = append(addresses, address)
	}
	sort.Strings(addresses)
	return addresses, nil
}

func validateTailscaleVersion(version string) error {
	short := strings.TrimPrefix(strings.TrimSpace(version), "v")
	parts := strings.SplitN(short, ".", 3)
	if len(parts) < 3 {
		return fmt.Errorf("unsupported Tailscale status version %q", version)
	}
	major, majorErr := strconv.Atoi(parts[0])
	minor, minorErr := strconv.Atoi(parts[1])
	if majorErr != nil || minorErr != nil || major != supportedTailscaleMajor || minor != supportedTailscaleMinor {
		return fmt.Errorf("unsupported Tailscale status schema version %q; require v%d.%d.x", version, supportedTailscaleMajor, supportedTailscaleMinor)
	}
	return nil
}

func (m *manager) checkHostPrerequisites(ctx context.Context, interfaces map[string]interfaceInfo) error {
	for _, path := range []string{ipv4ForwardingPath, ipv6ForwardingPath} {
		value, err := m.op.SysctlValue(path)
		if err != nil {
			return fail(metrics.RoutingFailureReasonForwarding, "read forwarding sysctl %s: %v", path, err)
		}
		if value != 1 {
			return fail(metrics.RoutingFailureReasonForwarding, "%s must be 1 (got %d)", path, value)
		}
	}
	if err := m.checkRPFilter(); err != nil {
		return err
	}
	contracts := make([]forwardingPathContract, 0, len(forwardingDirections)*2)
	for _, family := range []string{"-4", "-6"} {
		header := 40
		if family == "-6" {
			header = 60
		}
		for _, direction := range forwardingDirections {
			input := interfaces[direction[0]]
			output := interfaces[direction[1]]
			pathMTU := min(m.cfg.TunMTU, input.MTU, output.MTU)
			if pathMTU-header <= 0 {
				return fail(metrics.RoutingFailureReasonMSS, "%s path %s->%s MTU %d cannot produce a safe MSS", family, input.Name, output.Name, pathMTU)
			}
			contracts = append(contracts, forwardingPathContract{Family: family, Input: input.Name, Output: output.Name, PathMTU: pathMTU, MSS: pathMTU - header})
		}
	}
	if err := m.op.ValidateFirewall(ctx, contracts); err != nil {
		reason := metrics.RoutingFailureReasonFirewall
		if errors.Is(err, errMSSContract) {
			reason = metrics.RoutingFailureReasonMSS
		}
		return fail(reason, "deterministic firewall/MSS contract: %v", err)
	}
	return nil
}

func (m *manager) checkRPFilter() error {
	settings := []struct {
		name string
		path string
	}{{"conf/all", ipv4RPFilterAllPath}}
	for _, iface := range []string{m.cfg.UnderlayIface, m.cfg.TailscaleIface, m.cfg.TunName} {
		settings = append(settings, struct{ name, path string }{iface, "/proc/sys/net/ipv4/conf/" + iface + "/rp_filter"})
	}
	for _, setting := range settings {
		value, err := m.op.SysctlValue(setting.path)
		if err != nil {
			return fail(metrics.RoutingFailureReasonRPFilter, "read raw rp_filter for %s: %v", setting.name, err)
		}
		if value != 0 && value != 2 {
			return fail(metrics.RoutingFailureReasonRPFilter, "raw rp_filter for %s must be 0 or 2 (got %d)", setting.name, value)
		}
	}
	return nil
}

func (m *manager) validateTailscaleFIB(ctx context.Context) error {
	local := m.cfg.EffectiveLocalSiteCIDRs()
	audit := newPolicyAuditor(ctx, m.op)
	for _, family := range []string{"-4", "-6"} {
		routes, err := m.op.Routes(ctx, family, config.TailscaleRouteTableID)
		if err != nil {
			return fail(metrics.RoutingFailureReasonRouteUnaccepted, "read Tailscale table %d: %v", config.TailscaleRouteTableID, err)
		}
		for _, target := range buildTargets(local) {
			if target.family != family {
				continue
			}
			for _, route := range routes {
				if !prefixesOverlap(route.Prefix, target.cidr) {
					continue
				}
				if err := m.validatePostInspectionRule(audit, target); err != nil {
					return err
				}
				break
			}
		}
		for _, target := range buildTargets(m.cfg.EffectiveRemoteSiteCIDRs()) {
			if target.family != family {
				continue
			}
			found := false
			for _, route := range routes {
				if route.Table == config.TailscaleRouteTableID && route.Device == m.cfg.TailscaleIface && normalizedRouteType(route.Type) == "unicast" && prefixCovers(route.Prefix, target.cidr) {
					found = true
					break
				}
			}
			if !found {
				return fail(metrics.RoutingFailureReasonRouteUnaccepted, "remote Tailnet route %s has no unicast owner in Tailscale table %d", target.cidr, config.TailscaleRouteTableID)
			}
		}
	}
	return nil
}

func (m *manager) validatePostInspectionRule(audit *policyAuditor, target targetRoute) error {
	rules, err := audit.policyRules(target.family)
	if err != nil {
		return fail(metrics.RoutingFailureReasonDeliveryRoute, "read policy rules for local site %s: %v", target.cidr, err)
	}
	var explicit *policyRule
	for index := range rules {
		if !m.isPostInspectionRule(rules[index], target) {
			continue
		}
		if explicit != nil {
			return fail(metrics.RoutingFailureReasonDeliveryRoute, "local site %s has duplicate post-inspection policy rules", target.cidr)
		}
		explicit = &rules[index]
	}
	if explicit == nil {
		return fail(metrics.RoutingFailureReasonDeliveryRoute, "Tailscale FIB overlaps local site %s without an explicit post-inspection rule", target.cidr)
	}

	// No earlier matching rule may resolve part of the local prefix before the
	// explicit envelope-to-main rule. This keeps the table-52 exception scoped
	// to the post-inspection path rather than merely observing a correct lookup.
	for _, rule := range rules {
		if rule.Priority > explicit.Priority {
			break
		}
		if m.isPostInspectionRule(rule, target) || !policyRuleMayMatch(rule, targetRoute{family: target.family}, target, m.cfg.TunName) {
			continue
		}
		if rule.Unsupported {
			return fail(metrics.RoutingFailureReasonDeliveryRoute, "policy rule priority %d can precede post-inspection delivery for %s with unsupported selectors", rule.Priority, target.cidr)
		}
		switch normalizedRuleAction(rule) {
		case "nop":
			continue
		case "blackhole", "unreachable", "prohibit":
			return fail(metrics.RoutingFailureReasonDeliveryRoute, "policy rule priority %d terminates post-inspection delivery for %s", rule.Priority, target.cidr)
		case "lookup":
		default:
			return fail(metrics.RoutingFailureReasonDeliveryRoute, "policy rule priority %d has unprovable action %q before post-inspection delivery for %s", rule.Priority, rule.Action, target.cidr)
		}
		if rule.Table == 0 {
			return fail(metrics.RoutingFailureReasonDeliveryRoute, "policy rule priority %d has no table before post-inspection delivery for %s", rule.Priority, target.cidr)
		}
		routes, err := audit.routes(target.family, rule.Table)
		if err != nil {
			return fail(metrics.RoutingFailureReasonDeliveryRoute, "read policy table %d before post-inspection delivery for %s: %v", rule.Table, target.cidr, err)
		}
		if route, ok := firstRelevantSourceSpecificRoute(routes, targetRoute{family: target.family}, target); ok {
			return fail(metrics.RoutingFailureReasonDeliveryRoute, "policy rule priority %d table %d has source-specific route %s before post-inspection delivery for %s", rule.Priority, rule.Table, route.Prefix, target.cidr)
		}
		if route, ok := firstShadowingRoute(routes, target.cidr, rule.SuppressPrefixLength); ok {
			return fail(metrics.RoutingFailureReasonDeliveryRoute, "policy rule priority %d table %d route %s wins before the explicit post-inspection rule for %s", rule.Priority, rule.Table, route.Prefix, target.cidr)
		}
	}
	if err := audit.auditPath(targetRoute{family: target.family}, target, m.cfg.TunName, m.cfg.UnderlayIface, mainRouteTable, metrics.RoutingFailureReasonDeliveryRoute); err != nil {
		return err
	}
	return nil
}

func (m *manager) isPostInspectionRule(rule policyRule, target targetRoute) bool {
	return rule.Priority == m.cfg.RoutingRulePriority &&
		rule.Input == m.cfg.TunName &&
		rule.Destination == target.cidr &&
		rule.Table == mainRouteTable &&
		normalizedRuleAction(rule) == "lookup" &&
		!rule.Unsupported && !rule.Invert && !rule.HasMark &&
		rule.SuppressPrefixLength == -1 &&
		policyRulePrefix(rule.Source, rule.Family) == familyDefaultPrefix(rule.Family)
}

func (m *manager) verifyTargetRoutes(ctx context.Context) error {
	audit := newPolicyAuditor(ctx, m.op)
	for _, target := range buildTargets(m.cfg.EffectiveLocalSiteCIDRs()) {
		if err := m.verifyRoleLookups(ctx, audit, target, buildTargets(m.cfg.EffectiveRemoteSiteCIDRs()), m.cfg.TunName, m.cfg.UnderlayIface, mainRouteTable, metrics.RoutingFailureReasonDeliveryRoute); err != nil {
			return err
		}
	}
	for _, target := range buildTargets(m.cfg.EffectiveRemoteSiteCIDRs()) {
		if err := m.verifyRoleLookups(ctx, audit, target, buildTargets(m.cfg.EffectiveLocalSiteCIDRs()), m.cfg.TunName, m.cfg.TailscaleIface, config.TailscaleRouteTableID, metrics.RoutingFailureReasonRouteUnaccepted); err != nil {
			return err
		}
	}
	return nil
}

func (m *manager) verifyRoleLookups(ctx context.Context, audit *policyAuditor, destination targetRoute, sources []targetRoute, input, expectedDevice string, expectedTable int, reason string) error {
	matchingSources := make([]targetRoute, 0, len(sources))
	for _, source := range sources {
		if source.family == destination.family {
			matchingSources = append(matchingSources, source)
		}
	}
	destinations := prefixBoundaryAddresses(destination.cidr)
	if len(matchingSources) == 0 {
		matchingSources = append(matchingSources, targetRoute{family: destination.family})
	}
	for _, source := range matchingSources {
		if err := audit.auditPath(source, destination, input, expectedDevice, expectedTable, reason); err != nil {
			return err
		}
	}
	for _, source := range matchingSources {
		sourceAddresses := []string{""}
		if source.cidr != "" {
			sourceAddresses = prefixBoundaryAddresses(source.cidr)
		}
		for _, sourceAddress := range sourceAddresses {
			for _, destinationAddress := range destinations {
				query := routeQuery{Family: destination.family, Destination: destinationAddress, Source: sourceAddress, Input: input}
				result, err := m.op.RouteLookup(ctx, query)
				if err != nil {
					if errors.Is(err, errSupplementaryRouteLookupUnavailable) && m.canSkipSupplementaryRouteLookup(query) {
						m.log.Debug("supplementary route lookup unavailable after successful full-prefix audit",
							zap.String("source", query.Source),
							zap.String("destination", query.Destination),
							zap.String("input", query.Input),
							zap.Error(err),
						)
						continue
					}
					return fail(reason, "effective lookup %+v failed: %v", query, err)
				}
				if result.Device != expectedDevice || result.Table != expectedTable || normalizedRouteType(result.Type) != "unicast" {
					return fail(reason, "effective lookup %+v selected dev=%q table=%d type=%q, want dev=%q table=%d type=unicast", query, result.Device, result.Table, normalizedRouteType(result.Type), expectedDevice, expectedTable)
				}
			}
		}
	}
	return nil
}

func (m *manager) canSkipSupplementaryRouteLookup(query routeQuery) bool {
	if query.Family != "-4" || query.Input != m.cfg.TunName || !ordinaryUnicastAddress(query.Source) || !ordinaryUnicastAddress(query.Destination) {
		return false
	}
	for _, path := range []string{ipv4RPFilterAllPath, "/proc/sys/net/ipv4/conf/" + query.Input + "/rp_filter"} {
		value, err := m.op.SysctlValue(path)
		if err != nil || value != 0 {
			return false
		}
	}
	return true
}

func ordinaryUnicastAddress(value string) bool {
	address, err := netip.ParseAddr(value)
	if err != nil || !address.Is4() || !address.IsGlobalUnicast() || address.IsLoopback() || address.IsLinkLocalUnicast() {
		return false
	}
	firstOctet := address.As4()[0]
	return firstOctet != 0 && firstOctet < 224
}

type policyAuditor struct {
	ctx         context.Context
	op          systemOps
	rules       map[string][]policyRule
	routeTables map[string][]routeEntry
}

func newPolicyAuditor(ctx context.Context, op systemOps) *policyAuditor {
	return &policyAuditor{ctx: ctx, op: op, rules: make(map[string][]policyRule), routeTables: make(map[string][]routeEntry)}
}

func (a *policyAuditor) auditPath(source, destination targetRoute, input, expectedDevice string, expectedTable int, reason string) error {
	expectedRoutes, err := a.routes(destination.family, expectedTable)
	if err != nil {
		return fail(reason, "read expected table %d for %s: %v", expectedTable, destination.cidr, err)
	}
	if route, ok := firstRelevantSourceSpecificRoute(expectedRoutes, source, destination); ok {
		return fail(reason, "source-specific route %s from %s in table %d intersects source %s destination %s", route.Prefix, routeSourcePrefix(route), expectedTable, sourceCIDR(source), destination.cidr)
	}
	if _, err := selectExpectedRoute(expectedRoutes, source, destination, expectedDevice, expectedTable, -1); err != nil {
		return fail(reason, "full-prefix route audit for %s: %v", destination.cidr, err)
	}
	rules, err := a.policyRules(destination.family)
	if err != nil {
		return fail(reason, "read policy rules for %s: %v", destination.cidr, err)
	}
	resolvedPriority := -1
	for _, rule := range rules {
		if resolvedPriority >= 0 && rule.Priority > resolvedPriority {
			break
		}
		if !policyRuleMayMatch(rule, source, destination, input) {
			continue
		}
		if rule.Unsupported {
			return fail(reason, "policy rule priority %d has unsupported selectors intersecting source %s destination %s", rule.Priority, sourceCIDR(source), destination.cidr)
		}
		switch normalizedRuleAction(rule) {
		case "nop":
			continue
		case "blackhole", "unreachable", "prohibit":
			return fail(reason, "policy rule priority %d can terminate source %s destination %s with %s", rule.Priority, sourceCIDR(source), destination.cidr, normalizedRuleAction(rule))
		case "lookup":
		default:
			return fail(reason, "policy rule priority %d has unprovable action %q for source %s destination %s", rule.Priority, rule.Action, sourceCIDR(source), destination.cidr)
		}
		if rule.Table == 0 {
			return fail(reason, "policy rule priority %d has no auditable table for source %s destination %s", rule.Priority, sourceCIDR(source), destination.cidr)
		}
		routes, err := a.routes(destination.family, rule.Table)
		if err != nil {
			return fail(reason, "read policy table %d for source %s destination %s: %v", rule.Table, sourceCIDR(source), destination.cidr, err)
		}
		if route, ok := firstRelevantSourceSpecificRoute(routes, source, destination); ok {
			return fail(reason, "policy rule priority %d table %d has source-specific route %s from %s intersecting source %s destination %s", rule.Priority, rule.Table, route.Prefix, routeSourcePrefix(route), sourceCIDR(source), destination.cidr)
		}
		if rule.Table == expectedTable {
			if policyRuleCoversPath(rule, source, destination, input) {
				if _, err := selectExpectedRoute(routes, source, destination, expectedDevice, expectedTable, rule.SuppressPrefixLength); err == nil {
					resolvedPriority = rule.Priority
				}
			}
			continue
		}
		if route, ok := firstShadowingRoute(routes, destination.cidr, rule.SuppressPrefixLength); ok {
			return fail(reason, "policy rule priority %d table %d can shadow source %s destination %s with %s type %s dev %s", rule.Priority, rule.Table, sourceCIDR(source), destination.cidr, route.Prefix, normalizedRouteType(route.Type), route.Device)
		}
	}
	if resolvedPriority < 0 {
		return fail(reason, "no policy rule proves full source %s destination %s input %s through table %d", sourceCIDR(source), destination.cidr, input, expectedTable)
	}
	return nil
}

func firstRelevantSourceSpecificRoute(routes []routeEntry, source, destination targetRoute) (routeEntry, bool) {
	sourcePrefix := source.cidr
	if sourcePrefix == "" {
		sourcePrefix = familyDefaultPrefix(destination.family)
	}
	for _, route := range routes {
		routeSource := routeSourcePrefix(route)
		if routeSource == familyDefaultPrefix(destination.family) {
			continue
		}
		if prefixesOverlap(route.Prefix, destination.cidr) && prefixesOverlap(routeSource, sourcePrefix) {
			return route, true
		}
	}
	return routeEntry{}, false
}

func routeSourcePrefix(route routeEntry) string {
	if route.Source == "" {
		return familyDefaultPrefix(route.Family)
	}
	return route.Source
}

func (a *policyAuditor) policyRules(family string) ([]policyRule, error) {
	if rules, ok := a.rules[family]; ok {
		return rules, nil
	}
	rules, err := a.op.Rules(a.ctx, family)
	if err != nil {
		return nil, err
	}
	sort.SliceStable(rules, func(i, j int) bool { return rules[i].Priority < rules[j].Priority })
	a.rules[family] = rules
	return rules, nil
}

func (a *policyAuditor) routes(family string, table int) ([]routeEntry, error) {
	key := family + "|" + strconv.Itoa(table)
	if routes, ok := a.routeTables[key]; ok {
		return routes, nil
	}
	routes, err := a.op.Routes(a.ctx, family, table)
	if err != nil {
		return nil, err
	}
	a.routeTables[key] = routes
	return routes, nil
}

func policyRuleMayMatch(rule policyRule, source, destination targetRoute, input string) bool {
	if rule.Unsupported && (!validPolicyRulePrefix(rule.Source, rule.Family) || !validPolicyRulePrefix(rule.Destination, rule.Family) || !auditableRuleInversion(rule)) {
		return true
	}
	if rule.Input != "" && rule.Input != input || !ruleMatchesZeroMark(rule) {
		return false
	}
	if source.cidr != "" && !prefixesOverlap(policyRulePrefix(rule.Source, rule.Family), source.cidr) {
		return false
	}
	return prefixesOverlap(policyRulePrefix(rule.Destination, rule.Family), destination.cidr)
}

func validPolicyRulePrefix(prefix, family string) bool {
	parsed, err := netip.ParsePrefix(policyRulePrefix(prefix, family))
	if err != nil {
		return false
	}
	return family == "-6" && parsed.Addr().Is6() || family == "-4" && parsed.Addr().Is4()
}

func auditableRuleInversion(rule policyRule) bool {
	if !rule.Invert {
		return true
	}
	return rule.HasMark && rule.Input == "" && prefixCovers(policyRulePrefix(rule.Source, rule.Family), familyDefaultPrefix(rule.Family)) && prefixCovers(policyRulePrefix(rule.Destination, rule.Family), familyDefaultPrefix(rule.Family))
}

func policyRuleCoversPath(rule policyRule, source, destination targetRoute, input string) bool {
	if rule.Input != "" && rule.Input != input || !ruleMatchesZeroMark(rule) || rule.Unsupported {
		return false
	}
	if source.cidr == "" {
		if !prefixCovers(policyRulePrefix(rule.Source, rule.Family), familyDefaultPrefix(rule.Family)) {
			return false
		}
	} else if !prefixCovers(policyRulePrefix(rule.Source, rule.Family), source.cidr) {
		return false
	}
	return prefixCovers(policyRulePrefix(rule.Destination, rule.Family), destination.cidr)
}

func policyRulePrefix(prefix, family string) string {
	if prefix == "" {
		return familyDefaultPrefix(family)
	}
	return prefix
}

func familyDefaultPrefix(family string) string {
	if family == "-6" {
		return "::/0"
	}
	return "0.0.0.0/0"
}

func ruleMatchesZeroMark(rule policyRule) bool {
	if !rule.HasMark {
		return true
	}
	mask := rule.Mask
	matches := rule.Mark&mask == 0
	if rule.Invert {
		return !matches
	}
	return matches
}

func normalizedRuleAction(rule policyRule) string {
	action := strings.ToLower(rule.Action)
	if action == "" && rule.Table != 0 {
		return "lookup"
	}
	if action >= "6" && action <= "9" {
		return normalizedRouteType(action)
	}
	return action
}

func selectExpectedRoute(routes []routeEntry, source, destination targetRoute, expectedDevice string, expectedTable, suppressPrefixLength int) (routeEntry, error) {
	bestBits := -1
	var relevant []struct {
		route  routeEntry
		prefix netip.Prefix
		covers bool
	}
	sourcePrefix := source.cidr
	if sourcePrefix == "" {
		sourcePrefix = familyDefaultPrefix(destination.family)
	}
	for _, route := range routes {
		prefix, err := netip.ParsePrefix(route.Prefix)
		if err != nil || !prefixesOverlap(route.Prefix, destination.cidr) || routeSuppressed(prefix, suppressPrefixLength) {
			continue
		}
		routeSource := routeSourcePrefix(route)
		if routeSource != familyDefaultPrefix(destination.family) {
			if prefixesOverlap(routeSource, sourcePrefix) {
				return routeEntry{}, fmt.Errorf("intersecting route %s has source selector %s", route.Prefix, routeSource)
			}
			continue
		}
		covers := prefixCovers(route.Prefix, destination.cidr)
		relevant = append(relevant, struct {
			route  routeEntry
			prefix netip.Prefix
			covers bool
		}{route: route, prefix: prefix, covers: covers})
		if covers && prefix.Bits() > bestBits {
			bestBits = prefix.Bits()
		}
	}
	if bestBits < 0 {
		return routeEntry{}, fmt.Errorf("table %d has no route covering %s", expectedTable, destination.cidr)
	}
	var selected routeEntry
	for _, candidate := range relevant {
		// Less-specific routes cannot win while the full-prefix route exists.
		if candidate.prefix.Bits() < bestBits {
			continue
		}
		if normalizedRouteType(candidate.route.Type) != "unicast" {
			return routeEntry{}, fmt.Errorf("intersecting route %s has terminal type %s", candidate.route.Prefix, normalizedRouteType(candidate.route.Type))
		}
		if candidate.route.Table != expectedTable || candidate.route.Device != expectedDevice {
			return routeEntry{}, fmt.Errorf("intersecting route %s selects dev=%s table=%d, want dev=%s table=%d", candidate.route.Prefix, candidate.route.Device, candidate.route.Table, expectedDevice, expectedTable)
		}
		if candidate.covers && candidate.prefix.Bits() == bestBits {
			selected = candidate.route
		}
	}
	return selected, nil
}

func firstShadowingRoute(routes []routeEntry, destination string, suppressPrefixLength int) (routeEntry, bool) {
	for _, route := range routes {
		prefix, err := netip.ParsePrefix(route.Prefix)
		if err == nil && prefixesOverlap(route.Prefix, destination) && !routeSuppressed(prefix, suppressPrefixLength) && normalizedRouteType(route.Type) != "throw" {
			return route, true
		}
	}
	return routeEntry{}, false
}

func routeSuppressed(prefix netip.Prefix, suppressPrefixLength int) bool {
	return suppressPrefixLength >= 0 && prefix.Bits() <= suppressPrefixLength
}

func sourceCIDR(source targetRoute) string {
	if source.cidr == "" {
		return "all"
	}
	return source.cidr
}

func buildTargets(cidrs []string) []targetRoute {
	targets := make([]targetRoute, 0, len(cidrs))
	for _, cidr := range cidrs {
		prefix, err := netip.ParsePrefix(cidr)
		if err != nil {
			continue
		}
		family := "-4"
		if prefix.Addr().Is6() {
			family = "-6"
		}
		targets = append(targets, targetRoute{family: family, cidr: prefix.Masked().String()})
	}
	return targets
}

func prefixBoundaryAddresses(cidr string) []string {
	prefix, err := netip.ParsePrefix(cidr)
	if err != nil {
		return nil
	}
	prefix = prefix.Masked()
	first := prefix.Addr()
	bytes := first.As16()
	if first.Is4() {
		v4 := first.As4()
		bytes = [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, v4[0], v4[1], v4[2], v4[3]}
	}
	bits := first.BitLen()
	for bit := prefix.Bits(); bit < bits; bit++ {
		index := bit
		if first.Is4() {
			index += 96
		}
		bytes[index/8] |= 1 << (7 - uint(index%8))
	}
	last := netip.AddrFrom16(bytes)
	if first.Is4() {
		last = last.Unmap()
	}
	if first == last {
		return []string{first.String()}
	}
	return []string{first.String(), last.String()}
}

func routeSetCovers(routes []string, required string) bool {
	for _, route := range routes {
		if prefixCovers(route, required) {
			return true
		}
	}
	return false
}

func prefixCovers(available, required string) bool {
	left, leftErr := netip.ParsePrefix(available)
	right, rightErr := netip.ParsePrefix(required)
	if leftErr != nil || rightErr != nil || left.Addr().BitLen() != right.Addr().BitLen() {
		return false
	}
	left, right = left.Masked(), right.Masked()
	return left.Bits() <= right.Bits() && left.Contains(right.Addr())
}

func prefixesOverlap(leftRaw, rightRaw string) bool {
	left, leftErr := netip.ParsePrefix(leftRaw)
	right, rightErr := netip.ParsePrefix(rightRaw)
	if leftErr != nil || rightErr != nil || left.Addr().BitLen() != right.Addr().BitLen() {
		return false
	}
	left, right = left.Masked(), right.Masked()
	return left.Contains(right.Addr()) || right.Contains(left.Addr())
}

func normalizedRouteType(routeType string) string {
	switch routeType {
	case "", "1":
		return "unicast"
	case "2":
		return "local"
	case "3":
		return "broadcast"
	case "4":
		return "anycast"
	case "5":
		return "multicast"
	case "6":
		return "blackhole"
	case "7":
		return "unreachable"
	case "8":
		return "prohibit"
	case "9":
		return "throw"
	}
	return routeType
}

func fail(reason, format string, args ...any) error {
	return &reasonError{reason: reason, err: fmt.Errorf(format, args...)}
}

func failureReason(err error) string {
	var categorized *reasonError
	if errors.As(err, &categorized) {
		return categorized.reason
	}
	return metrics.RoutingFailureReasonApply
}
