//go:build linux

package routing

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"

	"golang.org/x/sys/unix"
)

const defaultRoutingLockPath = "/run/envelope-routing.lock"

type executablePaths struct {
	ip            string
	tailscale     string
	iptables      string
	ip6tables     string
	iptablesSave  string
	ip6tablesSave string
	nft           string
}

var defaultExecutablePaths = executablePaths{
	ip:            "/usr/sbin/ip",
	tailscale:     "/usr/bin/tailscale",
	iptables:      "/usr/sbin/iptables",
	ip6tables:     "/usr/sbin/ip6tables",
	iptablesSave:  "/usr/sbin/iptables-save",
	ip6tablesSave: "/usr/sbin/ip6tables-save",
	nft:           "/usr/sbin/nft",
}

type systemOpsLinux struct {
	runner   commandRunner
	paths    executablePaths
	lockPath string
}

func newSystemOps() systemOps {
	return &systemOpsLinux{runner: execCommandRunner{timeout: systemCommandTimeout}, paths: defaultExecutablePaths, lockPath: defaultRoutingLockPath}
}

func (s *systemOpsLinux) InterfaceInfo(name string) (interfaceInfo, error) {
	if name == "" {
		return interfaceInfo{}, errors.New("interface name is empty")
	}
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return interfaceInfo{}, fmt.Errorf("lookup interface %s: %w", name, err)
	}
	return interfaceInfo{Name: iface.Name, MTU: iface.MTU}, nil
}

func (s *systemOpsLinux) SysctlValue(path string) (int, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, fmt.Errorf("read %s: %w", path, err)
	}
	value, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		return 0, fmt.Errorf("parse %s: %w", path, err)
	}
	return value, nil
}

func (s *systemOpsLinux) AcquireLock() (routingLock, error) {
	path := s.lockPath
	if path == "" {
		path = defaultRoutingLockPath
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := unix.Flock(int(file.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		_ = file.Close()
		return nil, err
	}
	return &fileRoutingLock{file: file}, nil
}

type fileRoutingLock struct {
	mu   sync.Mutex
	file *os.File
}

func (l *fileRoutingLock) Release() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.file == nil {
		return nil
	}
	err := unix.Flock(int(l.file.Fd()), unix.LOCK_UN)
	closeErr := l.file.Close()
	l.file = nil
	return errors.Join(err, closeErr)
}

func (s *systemOpsLinux) RuleState(ctx context.Context, family string, priority int, iif, cidr string, table, protocol int) (objectState, error) {
	rules, err := s.rawRules(ctx, family)
	if err != nil {
		return stateAbsent, err
	}
	owned, operator, conflict := 0, 0, false
	for _, rule := range rules {
		rulePriority, _ := rawInt(rule["priority"])
		destination := rawPrefix(rule, "dst", "dstlen", family)
		ruleIIF := rawString(rule["iif"])
		if !ruleCouldConflict(rulePriority, priority, destination, cidr, ruleIIF, iif) {
			continue
		}
		ruleTable := rawTable(rule["table"])
		ruleProtocol, _ := rawInt(rule["protocol"])
		source := rawPrefix(rule, "src", "srclen", family)
		allSource := "0.0.0.0/0"
		if family == "-6" {
			allSource = "::/0"
		}
		exact := rulePriority == priority && destination == cidr && ruleIIF == iif && ruleTable == table && source == allSource && !hasUnsupportedRuleSelectors(rule)
		if !exact {
			conflict = true
			continue
		}
		if ruleProtocol == protocol {
			owned++
		} else {
			operator++
		}
	}
	if conflict || owned > 1 || operator > 1 || owned > 0 && operator > 0 {
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

func (s *systemOpsLinux) Rules(ctx context.Context, family string) ([]policyRule, error) {
	rawRules, err := s.rawRules(ctx, family)
	if err != nil {
		return nil, err
	}
	rules := make([]policyRule, 0, len(rawRules))
	for _, raw := range rawRules {
		suppress := -1
		if value, ok := rawInt(raw["suppress_prefixlength"]); ok {
			suppress = value
		}
		mark, mask, hasMark := rawMark(raw["fwmark"], raw["fwmask"])
		_, markPresent := raw["fwmark"]
		_, maskPresent := raw["fwmask"]
		source := rawPrefix(raw, "src", "srclen", family)
		destination := rawPrefix(raw, "dst", "dstlen", family)
		input := rawString(raw["iif"])
		invert := rawBool(raw["not"])
		table := rawTable(raw["table"])
		action := rawString(raw["action"])
		if action == "" && table == 0 {
			action = rawString(raw["type"])
		}
		unsupported := hasUnsupportedPolicySelectors(raw) || (markPresent || maskPresent) && !hasMark || !validPolicyRulePrefix(source, family) || !validPolicyRulePrefix(destination, family)
		rules = append(rules, policyRule{
			Family:               family,
			Priority:             rawIntDefault(raw["priority"]),
			Source:               source,
			Destination:          destination,
			Input:                input,
			Table:                table,
			Action:               action,
			Mark:                 mark,
			Mask:                 mask,
			HasMark:              hasMark,
			Invert:               invert,
			SuppressPrefixLength: suppress,
			Unsupported:          unsupported || invert && (!hasMark || input != "" || source != familyDefaultPrefix(family) || destination != familyDefaultPrefix(family)),
		})
	}
	return rules, nil
}

func (s *systemOpsLinux) rawRules(ctx context.Context, family string) ([]map[string]json.RawMessage, error) {
	out, err := s.runIP(ctx, "-j", "-details", "-N", family, "rule", "show")
	if err != nil {
		return nil, err
	}
	var rules []map[string]json.RawMessage
	if err := json.Unmarshal(out, &rules); err != nil {
		return nil, fmt.Errorf("decode rules: %w", err)
	}
	return rules, nil
}

func ruleCouldConflict(rulePriority, priority int, destination, cidr, ruleIIF, iif string) bool {
	if rulePriority != priority || ruleIIF != "" && ruleIIF != iif {
		return false
	}
	return destination == cidr || destination == "0.0.0.0/0" || destination == "::/0" || prefixesOverlap(destination, cidr)
}

func hasUnsupportedRuleSelectors(rule map[string]json.RawMessage) bool {
	for _, key := range []string{"not", "tos", "dsfield", "fwmark", "fwmask", "oif", "uidrange", "ipproto", "sport", "dport", "suppress_prefixlength", "suppress_ifgroup", "goto", "l3mdev", "tun_id", "flow", "realms"} {
		if value, ok := rule[key]; ok && rawSelectorPresent(value) {
			return true
		}
	}
	return false
}

func hasUnsupportedPolicySelectors(rule map[string]json.RawMessage) bool {
	for _, key := range []string{"tos", "dsfield", "oif", "uidrange", "ipproto", "sport", "dport", "suppress_ifgroup", "goto", "l3mdev", "tun_id", "flow", "realms"} {
		if value, ok := rule[key]; ok && rawSelectorPresent(value) {
			return true
		}
	}
	return false
}

func rawSelectorPresent(value json.RawMessage) bool {
	return string(value) != "null" && string(value) != "0" && string(value) != `""` && string(value) != "false"
}

func (s *systemOpsLinux) AddRule(ctx context.Context, family string, priority int, iif, cidr string, table, protocol int) error {
	_, err := s.runIP(ctx, family, "rule", "add", "priority", strconv.Itoa(priority), "iif", iif, "to", cidr, "table", strconv.Itoa(table), "protocol", strconv.Itoa(protocol))
	return err
}

func (s *systemOpsLinux) DeleteRule(ctx context.Context, family string, priority int, iif, cidr string, table, protocol int) error {
	_, err := s.runIP(ctx, family, "rule", "del", "priority", strconv.Itoa(priority), "iif", iif, "to", cidr, "table", strconv.Itoa(table), "protocol", strconv.Itoa(protocol))
	return err
}

func (s *systemOpsLinux) RouteState(ctx context.Context, family string, table int, cidr, dev string, protocol int) (objectState, error) {
	routes, err := s.routes(ctx, family, table, "exact", cidr)
	if err != nil {
		if isMissingFIBTableErr(err) {
			return stateAbsent, nil
		}
		return stateAbsent, err
	}
	owned, operator, conflict := 0, 0, false
	for _, route := range routes {
		if route.Prefix != cidr {
			continue
		}
		if route.Table != table || route.Device != dev || normalizedRouteType(route.Type) != "unicast" || routeSourcePrefix(route) != familyDefaultPrefix(family) {
			conflict = true
			continue
		}
		if route.Protocol == protocol {
			owned++
		} else {
			operator++
		}
	}
	if conflict || owned > 1 || operator > 1 || owned > 0 && operator > 0 {
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

func (s *systemOpsLinux) AddRoute(ctx context.Context, family string, table int, cidr, dev string, protocol int) error {
	_, err := s.runIP(ctx, family, "route", "add", "table", strconv.Itoa(table), cidr, "dev", dev, "proto", strconv.Itoa(protocol))
	return err
}

func (s *systemOpsLinux) DeleteRoute(ctx context.Context, family string, table int, cidr, dev string, protocol int) error {
	_, err := s.runIP(ctx, family, "route", "del", "table", strconv.Itoa(table), cidr, "dev", dev, "proto", strconv.Itoa(protocol))
	return err
}

func (s *systemOpsLinux) RouteLookup(ctx context.Context, query routeQuery) (routeResult, error) {
	args := []string{"-j", "-details", "-N", query.Family, "route", "get", query.Destination}
	if query.Source != "" {
		args = append(args, "from", query.Source)
	}
	if query.Input != "" {
		args = append(args, "iif", query.Input)
	}
	out, err := s.runIP(ctx, args...)
	if err != nil {
		return routeResult{}, err
	}
	var routes []map[string]json.RawMessage
	if err := json.Unmarshal(out, &routes); err != nil {
		return routeResult{}, fmt.Errorf("decode effective route lookup: %w", err)
	}
	if len(routes) != 1 {
		return routeResult{}, fmt.Errorf("effective route lookup returned %d entries", len(routes))
	}
	route := routes[0]
	table := rawTable(route["table"])
	if table == 0 {
		table = mainRouteTable
	}
	protocol, _ := rawInt(route["protocol"])
	return routeResult{Device: rawString(route["dev"]), Table: table, Type: rawString(route["type"]), Protocol: protocol}, nil
}

func (s *systemOpsLinux) Routes(ctx context.Context, family string, table int) ([]routeEntry, error) {
	routes, err := s.routes(ctx, family, table)
	if err != nil && isMissingFIBTableErr(err) {
		return nil, nil
	}
	return routes, err
}

func (s *systemOpsLinux) routes(ctx context.Context, family string, table int, extra ...string) ([]routeEntry, error) {
	args := []string{"-j", "-details", "-N", family, "route", "show", "table", strconv.Itoa(table)}
	args = append(args, extra...)
	out, err := s.runIP(ctx, args...)
	if err != nil {
		return nil, err
	}
	var rawRoutes []map[string]json.RawMessage
	if err := json.Unmarshal(out, &rawRoutes); err != nil {
		return nil, fmt.Errorf("decode routes in table %d: %w", table, err)
	}
	routes := make([]routeEntry, 0, len(rawRoutes))
	for _, route := range rawRoutes {
		prefix := rawPrefix(route, "dst", "dstlen", family)
		if prefix == "default" || prefix == "" {
			if family == "-6" {
				prefix = "::/0"
			} else {
				prefix = "0.0.0.0/0"
			}
		} else if !strings.Contains(prefix, "/") {
			address, err := netip.ParseAddr(prefix)
			if err != nil {
				return nil, fmt.Errorf("decode table %d route address %q: %w", table, prefix, err)
			}
			prefix = netip.PrefixFrom(address, address.BitLen()).String()
		}
		if parsed, err := netip.ParsePrefix(prefix); err == nil {
			prefix = parsed.Masked().String()
		} else {
			return nil, fmt.Errorf("decode table %d route prefix %q: %w", table, prefix, err)
		}
		routeTable := rawTable(route["table"])
		if routeTable == 0 {
			routeTable = table
		}
		protocol, _ := rawInt(route["protocol"])
		source := rawPrefix(route, "from", "fromlen", family)
		if !validPolicyRulePrefix(source, family) {
			return nil, fmt.Errorf("decode table %d route source %q", table, source)
		}
		routes = append(routes, routeEntry{Family: family, Prefix: prefix, Source: source, Device: rawString(route["dev"]), Table: routeTable, Type: rawString(route["type"]), Protocol: protocol})
	}
	return routes, nil
}

func (s *systemOpsLinux) TailscaleStatus(ctx context.Context) (tailscaleStatus, error) {
	out, err := s.runner.Run(ctx, s.paths.tailscale, "status", "--json")
	if err != nil {
		return tailscaleStatus{}, err
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(out, &raw); err != nil {
		return tailscaleStatus{}, fmt.Errorf("decode tailscale status object: %w", err)
	}
	for _, required := range []string{"Version", "TUN", "BackendState", "Health", "Self", "Peer"} {
		if _, ok := raw[required]; !ok {
			return tailscaleStatus{}, fmt.Errorf("tailscale status missing pinned v1.80 field %q", required)
		}
	}
	var status tailscaleStatus
	if err := json.Unmarshal(out, &status); err != nil {
		return tailscaleStatus{}, fmt.Errorf("decode tailscale v1.80 status: %w", err)
	}
	return status, nil
}

func (s *systemOpsLinux) TailscalePing(ctx context.Context, address string) error {
	_, err := s.runner.Run(ctx, s.paths.tailscale, "ping", "--c", "1", "--timeout=2s", "--until-direct=false", address)
	return err
}

func (s *systemOpsLinux) ValidateFirewall(ctx context.Context, contracts []forwardingPathContract) error {
	byFamily := map[string][]forwardingPathContract{"-4": {}, "-6": {}}
	for _, contract := range contracts {
		byFamily[contract.Family] = append(byFamily[contract.Family], contract)
	}
	for _, family := range []string{"-4", "-6"} {
		binary, save := s.paths.iptables, s.paths.iptablesSave
		if family == "-6" {
			binary, save = s.paths.ip6tables, s.paths.ip6tablesSave
		}
		version, err := s.runner.Run(ctx, binary, "--version")
		if err != nil {
			return err
		}
		if !strings.Contains(string(version), "(legacy)") {
			return fmt.Errorf("%s is not the supported legacy backend: %s", binary, strings.TrimSpace(string(version)))
		}
		saved, err := s.runner.Run(ctx, save)
		if err != nil {
			return err
		}
		ruleset, err := parseSavedRules(string(saved))
		if err != nil {
			return fmt.Errorf("%s decode legacy ruleset: %w", family, err)
		}
		if err := validatePristineLegacyHooks(ruleset); err != nil {
			return fmt.Errorf("%s legacy forwarding surface: %w", family, err)
		}
		if err := validateFilterTable(ruleset["filter"], byFamily[family]); err != nil {
			return fmt.Errorf("%s filter contract: %w", family, err)
		}
		if err := validateMSSTable(ruleset["mangle"], byFamily[family]); err != nil {
			return fmt.Errorf("%s mangle contract: %w: %v", family, errMSSContract, err)
		}
	}
	if s.paths.nft == "" {
		return errors.New("native nft inspection tool path is required")
	}
	info, err := os.Stat(s.paths.nft)
	if err != nil {
		return fmt.Errorf("inspect native nft tool %s: %w", s.paths.nft, err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o111 == 0 {
		return fmt.Errorf("native nft inspection tool %s is not executable", s.paths.nft)
	}
	out, err := s.runner.Run(ctx, s.paths.nft, "-j", "list", "ruleset")
	if err != nil {
		return fmt.Errorf("native nft ruleset cannot be validated: %w", err)
	}
	var ruleset struct {
		Objects []map[string]json.RawMessage `json:"nftables"`
	}
	if err := json.Unmarshal(out, &ruleset); err != nil {
		return fmt.Errorf("decode native nft ruleset: %w", err)
	}
	if len(ruleset.Objects) == 0 {
		return errors.New("native nft ruleset output has no metadata")
	}
	for _, object := range ruleset.Objects {
		if _, metadata := object["metainfo"]; !metadata {
			return errors.New("native nft/firewalld rules are unsupported alongside the deployment-owned legacy chains")
		}
	}
	return nil
}

func validateFilterContract(rules string, contracts []forwardingPathContract) error {
	ruleset, err := parseSavedRules(rules)
	if err != nil {
		return err
	}
	return validateFilterTable(ruleset["filter"], contracts)
}

func validateFilterTable(table *savedTable, contracts []forwardingPathContract) error {
	if table == nil {
		return errors.New("filter table is missing")
	}
	forward, err := requiredChain(table, "filter", "FORWARD", "ACCEPT")
	if err != nil {
		return err
	}
	if len(forward.Rules) != 1 || !exactJump(forward.Rules[0], "FORWARD", filterChainName) {
		return fmt.Errorf("filter FORWARD must contain only an unconditional jump to %s", filterChainName)
	}
	owned, err := requiredChain(table, "filter", filterChainName, "-")
	if err != nil {
		return err
	}
	if len(owned.Rules) != len(contracts) {
		return fmt.Errorf("%s must contain exactly %d rules (got %d)", filterChainName, len(contracts), len(owned.Rules))
	}
	remaining := make(map[string]struct{}, len(contracts))
	for _, contract := range contracts {
		remaining[contract.Input+"|"+contract.Output] = struct{}{}
	}
	for _, rule := range owned.Rules {
		input, output, ok := exactAcceptRule(rule, filterChainName)
		if !ok {
			return fmt.Errorf("unsupported or conditional rule in %s: %s", filterChainName, strings.Join(rule, " "))
		}
		key := input + "|" + output
		if _, ok := remaining[key]; !ok {
			return fmt.Errorf("unexpected or duplicate forwarding path %s", key)
		}
		delete(remaining, key)
	}
	if len(remaining) != 0 {
		return fmt.Errorf("missing forwarding paths: %v", sortedMapKeys(remaining))
	}
	return nil
}

func validateMSSContract(rules string, contracts []forwardingPathContract) error {
	ruleset, err := parseSavedRules(rules)
	if err != nil {
		return err
	}
	return validateMSSTable(ruleset["mangle"], contracts)
}

func validateMSSTable(table *savedTable, contracts []forwardingPathContract) error {
	if table == nil {
		return errors.New("mangle table is missing")
	}
	forward, err := requiredChain(table, "mangle", "FORWARD", "ACCEPT")
	if err != nil {
		return err
	}
	if len(forward.Rules) != 1 || !exactJump(forward.Rules[0], "FORWARD", mssChainName) {
		return fmt.Errorf("mangle FORWARD must contain only an unconditional jump to %s", mssChainName)
	}
	owned, err := requiredChain(table, "mangle", mssChainName, "-")
	if err != nil {
		return err
	}
	if len(owned.Rules) != len(contracts)+1 || !exactJump(owned.Rules[len(owned.Rules)-1], mssChainName, "RETURN") {
		return fmt.Errorf("%s must contain exactly %d MSS rules followed by RETURN", mssChainName, len(contracts))
	}
	remaining := make(map[string]int, len(contracts))
	for _, contract := range contracts {
		remaining[contract.Input+"|"+contract.Output] = contract.MSS
	}
	for _, rule := range owned.Rules[:len(owned.Rules)-1] {
		input, output, mss, ok := exactMSSRule(rule, mssChainName)
		if !ok {
			return fmt.Errorf("unsupported or conditional MSS rule: %s", strings.Join(rule, " "))
		}
		key := input + "|" + output
		expected, ok := remaining[key]
		if !ok || mss != expected {
			return fmt.Errorf("MSS path %s has %d, want %d", key, mss, expected)
		}
		delete(remaining, key)
	}
	if len(remaining) != 0 {
		return fmt.Errorf("missing MSS paths: %v", sortedIntMapKeys(remaining))
	}
	return nil
}

type savedRuleset map[string]*savedTable

type savedTable struct {
	Chains map[string]*savedChain
}

type savedChain struct {
	Policy string
	Rules  [][]string
}

func parseSavedRules(input string) (savedRuleset, error) {
	ruleset := make(savedRuleset)
	var current *savedTable
	currentName := ""
	for _, line := range strings.Split(input, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "*") {
			if current != nil {
				return nil, fmt.Errorf("table %s has no COMMIT", currentName)
			}
			currentName = strings.TrimPrefix(line, "*")
			if currentName == "" || ruleset[currentName] != nil {
				return nil, fmt.Errorf("invalid or duplicate table declaration %q", line)
			}
			current = &savedTable{Chains: make(map[string]*savedChain)}
			ruleset[currentName] = current
			continue
		}
		if line == "COMMIT" {
			if current == nil {
				return nil, errors.New("COMMIT outside table")
			}
			current, currentName = nil, ""
			continue
		}
		if current == nil {
			return nil, fmt.Errorf("legacy rule outside table: %s", line)
		}
		fields := strings.Fields(line)
		if strings.HasPrefix(line, ":") {
			if len(fields) < 2 {
				return nil, fmt.Errorf("invalid chain declaration in %s: %s", currentName, line)
			}
			name := strings.TrimPrefix(fields[0], ":")
			if name == "" || current.Chains[name] != nil {
				return nil, fmt.Errorf("invalid or duplicate chain declaration in %s: %s", currentName, line)
			}
			current.Chains[name] = &savedChain{Policy: fields[1]}
			continue
		}
		if len(fields) < 3 || fields[0] != "-A" {
			return nil, fmt.Errorf("unsupported legacy statement in %s: %s", currentName, line)
		}
		chain := current.Chains[fields[1]]
		if chain == nil {
			return nil, fmt.Errorf("rule references undeclared chain %s in %s", fields[1], currentName)
		}
		chain.Rules = append(chain.Rules, fields)
	}
	if current != nil {
		return nil, fmt.Errorf("table %s has no COMMIT", currentName)
	}
	return ruleset, nil
}

func validatePristineLegacyHooks(ruleset savedRuleset) error {
	checks := map[string][]string{
		"raw":      {"PREROUTING", "FORWARD", "POSTROUTING"},
		"mangle":   {"PREROUTING", "POSTROUTING"},
		"nat":      {"PREROUTING", "FORWARD", "POSTROUTING"},
		"security": {"PREROUTING", "FORWARD", "POSTROUTING"},
	}
	for tableName, hooks := range checks {
		table := ruleset[tableName]
		if table == nil {
			continue
		}
		for _, hook := range hooks {
			chain := table.Chains[hook]
			if chain == nil {
				continue
			}
			if chain.Policy != "ACCEPT" {
				return fmt.Errorf("%s %s policy must be ACCEPT (got %s)", tableName, hook, chain.Policy)
			}
			if len(chain.Rules) != 0 {
				return fmt.Errorf("%s %s must be pristine (got %d rule(s))", tableName, hook, len(chain.Rules))
			}
		}
	}
	return nil
}

func requiredChain(table *savedTable, tableName, chainName, policy string) (*savedChain, error) {
	chain := table.Chains[chainName]
	if chain == nil {
		return nil, fmt.Errorf("%s chain %s is missing", tableName, chainName)
	}
	if chain.Policy != policy {
		return nil, fmt.Errorf("%s %s policy must be %s (got %s)", tableName, chainName, policy, chain.Policy)
	}
	return chain, nil
}

func exactJump(fields []string, chain, target string) bool {
	return len(fields) == 4 && fields[0] == "-A" && fields[1] == chain && fields[2] == "-j" && fields[3] == target
}

func exactAcceptRule(fields []string, chain string) (string, string, bool) {
	if len(fields) != 8 || fields[0] != "-A" || fields[1] != chain || fields[2] != "-i" || fields[4] != "-o" || fields[6] != "-j" || fields[7] != "ACCEPT" {
		return "", "", false
	}
	return fields[3], fields[5], true
}

func exactMSSRule(fields []string, chain string) (string, string, int, bool) {
	if len(fields) < 16 || fields[0] != "-A" || fields[1] != chain {
		return "", "", 0, false
	}
	allowed := map[string]bool{"-A": true, "-i": true, "-o": true, "-p": true, "-m": true, "--tcp-flags": true, "-j": true, "--set-mss": true}
	for index := 2; index < len(fields); {
		token := fields[index]
		if !allowed[token] {
			return "", "", 0, false
		}
		step := 2
		if token == "--tcp-flags" {
			step = 3
		}
		if index+step > len(fields) {
			return "", "", 0, false
		}
		index += step
	}
	if tokenValue(fields, "-p") != "tcp" || tokenValue(fields, "-m") != "tcp" || tokenValue(fields, "-j") != "TCPMSS" {
		return "", "", 0, false
	}
	mask, match := twoTokenValues(fields, "--tcp-flags")
	if !(mask == "SYN,RST" || mask == "0x06") || !(match == "SYN" || match == "0x02") {
		return "", "", 0, false
	}
	mss, err := strconv.Atoi(tokenValue(fields, "--set-mss"))
	if err != nil || mss <= 0 {
		return "", "", 0, false
	}
	return tokenValue(fields, "-i"), tokenValue(fields, "-o"), mss, true
}

func tokenValue(fields []string, token string) string {
	for index := 0; index+1 < len(fields); index++ {
		if fields[index] == token {
			return fields[index+1]
		}
	}
	return ""
}

func twoTokenValues(fields []string, token string) (string, string) {
	for index := 0; index+2 < len(fields); index++ {
		if fields[index] == token {
			return fields[index+1], fields[index+2]
		}
	}
	return "", ""
}

func sortedMapKeys(values map[string]struct{}) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func sortedIntMapKeys(values map[string]int) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func canonicalRulePrefix(value, family string) string {
	if value == "" || value == "all" {
		if family == "-6" {
			return "::/0"
		}
		return "0.0.0.0/0"
	}
	if prefix, err := netip.ParsePrefix(value); err == nil {
		return prefix.Masked().String()
	}
	return value
}

func rawPrefix(object map[string]json.RawMessage, valueKey, lengthKey, family string) string {
	value := rawString(object[valueKey])
	if value != "" && value != "all" && value != "default" && !strings.Contains(value, "/") {
		if bits, ok := rawInt(object[lengthKey]); ok {
			value += "/" + strconv.Itoa(bits)
		}
	}
	return canonicalRulePrefix(value, family)
}

func rawString(raw json.RawMessage) string {
	if len(raw) == 0 || string(raw) == "null" {
		return ""
	}
	var value string
	if json.Unmarshal(raw, &value) == nil {
		return value
	}
	return strings.Trim(string(raw), `"`)
}

func rawInt(raw json.RawMessage) (int, bool) {
	if len(raw) == 0 || string(raw) == "null" {
		return 0, false
	}
	var number int
	if json.Unmarshal(raw, &number) == nil {
		return number, true
	}
	value := rawString(raw)
	number, err := strconv.Atoi(value)
	return number, err == nil
}

func rawIntDefault(raw json.RawMessage) int {
	value, _ := rawInt(raw)
	return value
}

func rawBool(raw json.RawMessage) bool {
	var value bool
	return len(raw) != 0 && json.Unmarshal(raw, &value) == nil && value
}

func rawMark(markRaw, maskRaw json.RawMessage) (uint32, uint32, bool) {
	value := rawString(markRaw)
	if value == "" {
		return 0, 0, false
	}
	maskValue := rawString(maskRaw)
	if strings.Contains(value, "/") {
		parts := strings.SplitN(value, "/", 2)
		value, maskValue = parts[0], parts[1]
	}
	mark, err := strconv.ParseUint(value, 0, 32)
	if err != nil {
		return 0, 0, false
	}
	mask := uint64(^uint32(0))
	if maskValue != "" {
		mask, err = strconv.ParseUint(maskValue, 0, 32)
		if err != nil {
			return 0, 0, false
		}
	}
	return uint32(mark), uint32(mask), true
}

func rawTable(raw json.RawMessage) int {
	if value, ok := rawInt(raw); ok {
		return value
	}
	switch rawString(raw) {
	case "local":
		return 255
	case "main":
		return 254
	case "default":
		return 253
	case "unspec":
		return 0
	}
	return 0
}

func (s *systemOpsLinux) runIP(ctx context.Context, args ...string) ([]byte, error) {
	return s.runner.Run(ctx, s.paths.ip, args...)
}

func isMissingFIBTableErr(err error) bool {
	return strings.Contains(err.Error(), "FIB table does not exist")
}
