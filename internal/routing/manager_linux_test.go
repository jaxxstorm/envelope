//go:build linux

package routing

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/jaxxstorm/envelope/internal/config"
)

type scriptedCommandRunner struct {
	mu      sync.Mutex
	outputs map[string][]byte
	errors  map[string]error
	calls   []string
}

func (r *scriptedCommandRunner) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	key := name
	if len(args) > 0 {
		key += " " + strings.Join(args, " ")
	}
	r.calls = append(r.calls, key)
	return r.outputs[key], r.errors[key]
}

func testLinuxOps(runner commandRunner) *systemOpsLinux {
	return &systemOpsLinux{runner: runner, paths: executablePaths{
		ip:            "/test/ip",
		tailscale:     "/test/tailscale",
		iptables:      "/test/iptables",
		ip6tables:     "/test/ip6tables",
		iptablesSave:  "/test/iptables-save",
		ip6tablesSave: "/test/ip6tables-save",
	}}
}

func TestLinuxTailscaleStatusAdapterPinnedSchema(t *testing.T) {
	command := "/test/tailscale status --json"
	runner := &scriptedCommandRunner{outputs: map[string][]byte{
		command: []byte(`{
			"Version":"1.80.3","TUN":true,"BackendState":"Running","Health":[],
			"Self":{"Online":true,"AllowedIPs":["10.10.0.0/24"],"PrimaryRoutes":["10.20.0.0/24"]},
			"Peer":{"node-key":{"Online":true,"TailscaleIPs":["100.64.0.2"],"PrimaryRoutes":["10.30.0.0/24"]}}
		}`),
	}, errors: map[string]error{}}
	status, err := testLinuxOps(runner).TailscaleStatus(context.Background())
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	if status.Version != "1.80.3" || !status.TUN || status.Self == nil || len(status.Self.PrimaryRoutes) != 1 || len(status.Peer) != 1 {
		t.Fatalf("unexpected decoded status: %+v", status)
	}
	if len(runner.calls) != 1 || runner.calls[0] != command {
		t.Fatalf("status calls=%v", runner.calls)
	}
}

func TestLinuxTailscaleStatusAdapterRejectsUnpinnedShape(t *testing.T) {
	command := "/test/tailscale status --json"
	for _, tt := range []struct {
		name   string
		output string
		err    error
	}{
		{name: "command", err: errors.New("unavailable")},
		{name: "invalid JSON", output: `{"BackendState":`},
		{name: "missing TUN", output: `{"Version":"1.80.3","BackendState":"Running","Health":[],"Self":{},"Peer":{}}`},
	} {
		t.Run(tt.name, func(t *testing.T) {
			runner := &scriptedCommandRunner{outputs: map[string][]byte{command: []byte(tt.output)}, errors: map[string]error{command: tt.err}}
			if _, err := testLinuxOps(runner).TailscaleStatus(context.Background()); err == nil {
				t.Fatal("expected status adapter error")
			}
		})
	}
}

func TestLinuxTailscalePingAcceptsAWorkingRelayPath(t *testing.T) {
	command := "/test/tailscale ping --c 1 --timeout=2s --until-direct=false 100.64.0.2"
	runner := &scriptedCommandRunner{outputs: map[string][]byte{command: []byte("pong via DERP(local)")}, errors: map[string]error{}}
	if err := testLinuxOps(runner).TailscalePing(context.Background(), "100.64.0.2"); err != nil {
		t.Fatalf("relay ping: %v", err)
	}
	if len(runner.calls) != 1 || runner.calls[0] != command {
		t.Fatalf("ping calls=%v", runner.calls)
	}
}

func TestLinuxRuleStateUsesExactShapeAndProtocolMarker(t *testing.T) {
	command := "/test/ip -j -details -N -4 rule show"
	base := `{"priority":10000,"src":"all","dst":"10.10.0.0/24","iif":"tailscale0","table":100,"protocol":%d}`
	for _, tt := range []struct {
		name string
		json string
		want objectState
	}{
		{name: "absent", json: `[{"priority":32766,"src":"all","dst":"all","table":"main"}]`, want: stateAbsent},
		{name: "owned", json: "[" + fmt.Sprintf(base, ownerProtocol) + "]", want: stateOwned},
		{name: "operator", json: "[" + fmt.Sprintf(base, 4) + "]", want: stateOperator},
		{name: "omitted all-source", json: `[{"priority":10000,"dst":"10.10.0.0/24","iif":"tailscale0","table":100,"protocol":186}]`, want: stateOwned},
		{name: "split destination prefix", json: `[{"priority":10000,"src":"all","dst":"10.10.0.0","dstlen":24,"iif":"tailscale0","table":"100","protocol":186}]`, want: stateOwned},
		{name: "wrong table conflict", json: `[{"priority":10000,"src":"all","dst":"10.10.0.0/24","iif":"tailscale0","table":101,"protocol":186}]`, want: stateConflict},
		{name: "unsupported selector conflict", json: `[{"priority":10000,"src":"all","dst":"10.10.0.0/24","iif":"tailscale0","table":100,"protocol":186,"fwmark":"0x1"}]`, want: stateConflict},
		{name: "inverted rule conflict", json: `[{"priority":10000,"src":"all","dst":"10.10.0.0/24","iif":"tailscale0","table":100,"protocol":186,"not":true}]`, want: stateConflict},
		{name: "TOS selector conflict", json: `[{"priority":10000,"src":"all","dst":"10.10.0.0/24","iif":"tailscale0","table":100,"protocol":186,"tos":16}]`, want: stateConflict},
		{name: "duplicate conflict", json: "[" + fmt.Sprintf(base, ownerProtocol) + "," + fmt.Sprintf(base, ownerProtocol) + "]", want: stateConflict},
	} {
		t.Run(tt.name, func(t *testing.T) {
			runner := &scriptedCommandRunner{outputs: map[string][]byte{command: []byte(tt.json)}, errors: map[string]error{}}
			state, err := testLinuxOps(runner).RuleState(context.Background(), "-4", 10000, "tailscale0", "10.10.0.0/24", 100, ownerProtocol)
			if err != nil || state != tt.want {
				t.Fatalf("state=%d err=%v, want %d", state, err, tt.want)
			}
		})
	}
}

func TestLinuxRulesDecodeFullPolicySelectors(t *testing.T) {
	command := "/test/ip -j -details -N -4 rule show"
	runner := &scriptedCommandRunner{outputs: map[string][]byte{
		command: []byte(`[
			{"priority":0,"src":"all","table":"local","protocol":"kernel"},
			{"priority":50,"src":"10.30.0.0","srclen":24,"dst":"10.20.0.0","dstlen":24,"iif":"tailscale0","fwmark":"0x1/0xff","table":"100","suppress_prefixlength":8},
			{"priority":55,"src":"all","fwmark":"0x1/0xff","not":true,"table":100},
			{"priority":60,"src":"all","table":100,"fwmark":"invalid"},
			{"priority":70,"src":"all","table":100,"oif":"eth0"},
			{"priority":80,"src":"all","type":"unreachable"}
		]`),
	}, errors: map[string]error{}}
	rules, err := testLinuxOps(runner).Rules(context.Background(), "-4")
	if err != nil {
		t.Fatalf("rules: %v", err)
	}
	if len(rules) != 6 || rules[0].Table != localRouteTable || rules[0].Source != "0.0.0.0/0" || rules[0].Destination != "0.0.0.0/0" {
		t.Fatalf("built-in rule decode=%+v", rules)
	}
	selected := rules[1]
	if selected.Source != "10.30.0.0/24" || selected.Destination != "10.20.0.0/24" || selected.Input != "tailscale0" || selected.Table != 100 || !selected.HasMark || selected.Mark != 1 || selected.Mask != 0xff || selected.Invert || selected.SuppressPrefixLength != 8 || selected.Unsupported {
		t.Fatalf("selected rule decode=%+v", selected)
	}
	if !rules[2].Invert || rules[2].Unsupported || !rules[2].HasMark {
		t.Fatalf("mark-only inversion decode=%+v", rules[2])
	}
	if !rules[3].Unsupported || !rules[4].Unsupported {
		t.Fatalf("unparseable selectors were accepted: %+v", rules[3:5])
	}
	if got := normalizedRuleAction(rules[5]); got != "unreachable" {
		t.Fatalf("numeric terminal action=%q", got)
	}
}

func TestLinuxRouteStateUsesExactShapeAndProtocolMarker(t *testing.T) {
	command := "/test/ip -j -details -N -4 route show table 100 exact 10.10.0.0/24"
	for _, tt := range []struct {
		name string
		json string
		want objectState
	}{
		{name: "absent", json: `[]`, want: stateAbsent},
		{name: "owned", json: `[{"dst":"10.10.0.0/24","dev":"envelope0","table":100,"protocol":186}]`, want: stateOwned},
		{name: "operator", json: `[{"dst":"10.10.0.0/24","dev":"envelope0","table":100,"protocol":"static"}]`, want: stateOperator},
		{name: "wrong device", json: `[{"dst":"10.10.0.0/24","dev":"eth0","table":100,"protocol":186}]`, want: stateConflict},
		{name: "non-unicast", json: `[{"dst":"10.10.0.0/24","type":"blackhole","table":100,"protocol":186}]`, want: stateConflict},
	} {
		t.Run(tt.name, func(t *testing.T) {
			runner := &scriptedCommandRunner{outputs: map[string][]byte{command: []byte(tt.json)}, errors: map[string]error{}}
			state, err := testLinuxOps(runner).RouteState(context.Background(), "-4", 100, "10.10.0.0/24", "envelope0", ownerProtocol)
			if err != nil || state != tt.want {
				t.Fatalf("state=%d err=%v, want %d", state, err, tt.want)
			}
		})
	}

	runner := &scriptedCommandRunner{outputs: map[string][]byte{}, errors: map[string]error{command: errors.New("Error: ipv4: FIB table does not exist")}}
	state, err := testLinuxOps(runner).RouteState(context.Background(), "-4", 100, "10.10.0.0/24", "envelope0", ownerProtocol)
	if err != nil || state != stateAbsent {
		t.Fatalf("missing table state=%d err=%v", state, err)
	}

}

func TestLinuxRouteStateRejectsSourceSpecificEquivalent(t *testing.T) {
	command := "/test/ip -j -details -N -6 route show table 100 exact 2001:db8:10::/64"
	runner := &scriptedCommandRunner{outputs: map[string][]byte{
		command: []byte(`[{"dst":"2001:db8:10::/64","from":"2001:db8:30:0:8000::/65","dev":"envelope0","table":100,"protocol":186}]`),
	}, errors: map[string]error{}}
	state, err := testLinuxOps(runner).RouteState(context.Background(), "-6", 100, "2001:db8:10::/64", "envelope0", ownerProtocol)
	if err != nil || state != stateConflict {
		t.Fatalf("source-specific exact state=%d err=%v, want conflict", state, err)
	}
}

func TestLinuxMutationCommandsIncludeOwnershipMarker(t *testing.T) {
	runner := &scriptedCommandRunner{outputs: map[string][]byte{}, errors: map[string]error{}}
	ops := testLinuxOps(runner)
	ctx := context.Background()
	if err := ops.AddRoute(ctx, "-4", 100, "10.10.0.0/24", "envelope0", ownerProtocol); err != nil {
		t.Fatal(err)
	}
	if err := ops.AddRule(ctx, "-4", 10000, "tailscale0", "10.10.0.0/24", 100, ownerProtocol); err != nil {
		t.Fatal(err)
	}
	if err := ops.DeleteRule(ctx, "-4", 10000, "tailscale0", "10.10.0.0/24", 100, ownerProtocol); err != nil {
		t.Fatal(err)
	}
	if err := ops.DeleteRoute(ctx, "-4", 100, "10.10.0.0/24", "envelope0", ownerProtocol); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"/test/ip -4 route add table 100 10.10.0.0/24 dev envelope0 proto 186",
		"/test/ip -4 rule add priority 10000 iif tailscale0 to 10.10.0.0/24 table 100 protocol 186",
		"/test/ip -4 rule del priority 10000 iif tailscale0 to 10.10.0.0/24 table 100 protocol 186",
		"/test/ip -4 route del table 100 10.10.0.0/24 dev envelope0 proto 186",
	}
	if strings.Join(runner.calls, "\n") != strings.Join(want, "\n") {
		t.Fatalf("mutation calls:\n%s", strings.Join(runner.calls, "\n"))
	}
}

func TestLinuxEffectiveRouteAndFIBAdaptersUseStructuredDetails(t *testing.T) {
	lookupCommand := "/test/ip -j -details -N -4 route get 10.10.0.255 from 10.30.0.0 iif tailscale0"
	routesCommand := "/test/ip -j -details -N -4 route show table 52"
	runner := &scriptedCommandRunner{outputs: map[string][]byte{
		lookupCommand: []byte(`[{"dst":"10.10.0.255","dev":"envelope0","table":100,"type":"unicast","protocol":186}]`),
		routesCommand: []byte(`[{"dst":"10.30.0.0/24","dev":"tailscale0","table":52,"type":"1","protocol":"3"},{"dst":"default","dev":"tailscale0","table":"52","type":"9"}]`),
	}, errors: map[string]error{}}
	ops := testLinuxOps(runner)
	result, err := ops.RouteLookup(context.Background(), routeQuery{Family: "-4", Destination: "10.10.0.255", Source: "10.30.0.0", Input: "tailscale0"})
	if err != nil || result.Device != "envelope0" || result.Table != 100 || result.Type != "unicast" || result.Protocol != ownerProtocol {
		t.Fatalf("route result=%+v err=%v", result, err)
	}
	routes, err := ops.Routes(context.Background(), "-4", config.TailscaleRouteTableID)
	if err != nil || len(routes) != 2 {
		t.Fatalf("routes=%+v err=%v", routes, err)
	}
	if routes[0].Prefix != "10.30.0.0/24" || routes[0].Device != "tailscale0" || routes[0].Table != 52 || normalizedRouteType(routes[0].Type) != "unicast" || routes[1].Prefix != "0.0.0.0/0" || normalizedRouteType(routes[1].Type) != "throw" {
		t.Fatalf("decoded routes=%+v", routes)
	}
}

func TestLinuxIPv6RoutesRetainSourceSelector(t *testing.T) {
	command := "/test/ip -j -details -N -6 route show table 254"
	runner := &scriptedCommandRunner{outputs: map[string][]byte{
		command: []byte(`[
			{"dst":"2001:db8:20::/64","from":"2001:db8:30:0:8000::/65","dev":"underlay0","table":"254","type":"1","protocol":"3"},
			{"dst":"2001:db8:21::","dstlen":64,"from":"2001:db8:31:0:8000::","fromlen":65,"dev":"underlay0","table":254}
		]`),
	}, errors: map[string]error{}}
	routes, err := testLinuxOps(runner).Routes(context.Background(), "-6", mainRouteTable)
	if err != nil || len(routes) != 2 {
		t.Fatalf("routes=%+v err=%v", routes, err)
	}
	if routes[0].Source != "2001:db8:30:0:8000::/65" || routes[1].Source != "2001:db8:31:0:8000::/65" {
		t.Fatalf("source selectors were not retained: %+v", routes)
	}
}

func TestFirewallContractsRequireDeploymentOwnedFirstJumpChains(t *testing.T) {
	contracts := []forwardingPathContract{
		{Input: "eth0", Output: "tailscale0", MSS: 1240},
		{Input: "tailscale0", Output: "eth0", MSS: 1240},
	}
	filter := strings.Join([]string{
		"*filter",
		":FORWARD ACCEPT [0:0]",
		":" + filterChainName + " - [0:0]",
		"-A FORWARD -j " + filterChainName,
		"-A " + filterChainName + " -i eth0 -o tailscale0 -j ACCEPT",
		"-A " + filterChainName + " -i tailscale0 -o eth0 -j ACCEPT",
		"COMMIT",
	}, "\n")
	mangle := strings.Join([]string{
		"*mangle",
		":FORWARD ACCEPT [0:0]",
		":" + mssChainName + " - [0:0]",
		"-A FORWARD -j " + mssChainName,
		"-A " + mssChainName + " -i eth0 -o tailscale0 -p tcp -m tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1240",
		"-A " + mssChainName + " -i tailscale0 -o eth0 -p tcp -m tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1240",
		"-A " + mssChainName + " -j RETURN",
		"COMMIT",
	}, "\n")
	if err := validateFilterContract(filter, contracts); err != nil {
		t.Fatalf("valid filter contract: %v", err)
	}
	if err := validateMSSContract(mangle, contracts); err != nil {
		t.Fatalf("valid MSS contract: %v", err)
	}

	for _, tt := range []struct {
		name  string
		rules string
		check func(string, []forwardingPathContract) error
	}{
		{name: "policy-only filter", rules: "-P FORWARD ACCEPT\n", check: validateFilterContract},
		{name: "filter policy DROP", rules: strings.Replace(filter, ":FORWARD ACCEPT", ":FORWARD DROP", 1), check: validateFilterContract},
		{name: "jump not first", rules: strings.Replace(filter, "-A FORWARD -j "+filterChainName, "-A FORWARD -i lo -j ACCEPT\n-A FORWARD -j "+filterChainName, 1), check: validateFilterContract},
		{name: "conditional filter jump", rules: strings.Replace(filter, "-A FORWARD -j "+filterChainName, "-A FORWARD -i eth0 -j "+filterChainName, 1), check: validateFilterContract},
		{name: "conditional owned rule", rules: strings.Replace(filter, "-j ACCEPT", "-m conntrack --ctstate ESTABLISHED -j ACCEPT", 1), check: validateFilterContract},
		{name: "PMTU clamp", rules: strings.Replace(mangle, "--set-mss 1240", "--clamp-mss-to-pmtu", 1), check: validateMSSContract},
		{name: "wrong MSS", rules: strings.Replace(mangle, "--set-mss 1240", "--set-mss 1241", 1), check: validateMSSContract},
		{name: "mangle FORWARD policy DROP", rules: strings.Replace(mangle, ":FORWARD ACCEPT", ":FORWARD DROP", 1), check: validateMSSContract},
		{name: "conditional mangle jump", rules: strings.Replace(mangle, "-A FORWARD -j "+mssChainName, "-A FORWARD -p tcp -j "+mssChainName, 1), check: validateMSSContract},
		{name: "later FORWARD drop", rules: strings.Replace(mangle, "-A "+mssChainName, "-A FORWARD -j DROP\n-A "+mssChainName, 1), check: validateMSSContract},
		{name: "later FORWARD TCPMSS", rules: strings.Replace(mangle, "-A "+mssChainName, "-A FORWARD -p tcp -j TCPMSS --set-mss 1200\n-A "+mssChainName, 1), check: validateMSSContract},
		{name: "extra owned rule", rules: strings.Replace(filter, "COMMIT", "-A "+filterChainName+" -i lo -o eth0 -j ACCEPT\nCOMMIT", 1), check: validateFilterContract},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.check(tt.rules, contracts); err == nil {
				t.Fatal("unsupported firewall layout was accepted")
			}
		})
	}

}

func TestLegacyRulesetRejectsForwardingHookMutations(t *testing.T) {
	contracts := []forwardingPathContract{
		{Input: "eth0", Output: "tailscale0", MSS: 1240},
		{Input: "tailscale0", Output: "eth0", MSS: 1240},
	}
	valid := legacyRulesetFixture(contracts)
	for _, tt := range []struct {
		name  string
		table string
		rule  string
	}{
		{name: "raw PREROUTING DROP", table: "raw", rule: "-A PREROUTING -j DROP"},
		{name: "security FORWARD DROP", table: "security", rule: "-A FORWARD -j DROP"},
		{name: "mangle PREROUTING MARK", table: "mangle", rule: "-A PREROUTING -j MARK --set-mark 0x1"},
		{name: "nat PREROUTING DNAT", table: "nat", rule: "-A PREROUTING -j DNAT --to-destination 192.0.2.99"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			ruleset, err := parseSavedRules(insertRuleBeforeCommit(valid, tt.table, tt.rule))
			if err != nil {
				t.Fatalf("parse fixture: %v", err)
			}
			if err := validatePristineLegacyHooks(ruleset); err == nil {
				t.Fatal("forwarding hook mutation was accepted")
			}
		})
	}
	for _, tt := range []struct {
		name string
		from string
		to   string
	}{
		{name: "raw PREROUTING policy DROP", from: ":PREROUTING ACCEPT", to: ":PREROUTING DROP"},
		{name: "security FORWARD policy DROP", from: ":FORWARD ACCEPT", to: ":FORWARD DROP"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			mutated := valid
			if strings.HasPrefix(tt.name, "security") {
				start := strings.Index(mutated, "*security\n")
				mutated = mutated[:start] + strings.Replace(mutated[start:], tt.from, tt.to, 1)
			} else {
				mutated = strings.Replace(mutated, tt.from, tt.to, 1)
			}
			ruleset, err := parseSavedRules(mutated)
			if err != nil {
				t.Fatalf("parse fixture: %v", err)
			}
			if err := validatePristineLegacyHooks(ruleset); err == nil {
				t.Fatal("forwarding hook DROP policy was accepted")
			}
		})
	}
}

func TestValidateFirewallRequiresLegacyBackendAndRejectsNativeNFT(t *testing.T) {
	contracts := []forwardingPathContract{{Family: "-4", Input: "eth0", Output: "tailscale0", MSS: 1240}, {Family: "-6", Input: "eth0", Output: "tailscale0", MSS: 1220}}
	legacy4 := legacyRulesetFixture([]forwardingPathContract{{Input: "eth0", Output: "tailscale0", MSS: 1240}})
	legacy6 := legacyRulesetFixture([]forwardingPathContract{{Input: "eth0", Output: "tailscale0", MSS: 1220}})
	outputs := map[string][]byte{
		"/test/iptables --version":  []byte("iptables v1.8.9 (legacy)"),
		"/test/ip6tables --version": []byte("ip6tables v1.8.9 (legacy)"),
		"/test/iptables-save":       []byte(legacy4),
		"/test/ip6tables-save":      []byte(legacy6),
	}
	nft := filepath.Join(t.TempDir(), "nft")
	if err := os.WriteFile(nft, []byte("fixture"), 0o700); err != nil {
		t.Fatal(err)
	}
	outputs[nft+" -j list ruleset"] = []byte(`{"nftables":[{"metainfo":{"version":"1.0"}}]}`)
	runner := &scriptedCommandRunner{outputs: outputs, errors: map[string]error{}}
	ops := testLinuxOps(runner)
	ops.paths.nft = nft
	if err := ops.ValidateFirewall(context.Background(), contracts); err != nil {
		t.Fatalf("valid legacy firewall: %v", err)
	}

	outputs["/test/iptables --version"] = []byte("iptables v1.8.9 (nf_tables)")
	if err := testLinuxOps(&scriptedCommandRunner{outputs: outputs, errors: map[string]error{}}).ValidateFirewall(context.Background(), contracts); err == nil {
		t.Fatal("nft iptables backend was accepted")
	}
	outputs["/test/iptables --version"] = []byte("iptables v1.8.9 (legacy)")
	ops = testLinuxOps(&scriptedCommandRunner{outputs: outputs, errors: map[string]error{}})
	ops.paths.nft = nft
	outputs[nft+" -j list ruleset"] = []byte(`{"nftables":[{"metainfo":{"version":"1.0"}},{"table":{"family":"inet","name":"firewalld"}}]}`)
	if err := ops.ValidateFirewall(context.Background(), contracts); err == nil || !strings.Contains(err.Error(), "unsupported") {
		t.Fatalf("native nft ruleset error=%v", err)
	}

	for _, tt := range []struct {
		name    string
		path    string
		prepare func(string) error
		runErr  error
	}{
		{name: "empty path"},
		{name: "missing executable", path: filepath.Join(t.TempDir(), "missing")},
		{name: "non-executable", path: filepath.Join(t.TempDir(), "nft"), prepare: func(path string) error { return os.WriteFile(path, []byte("fixture"), 0o600) }},
		{name: "execution failure", path: filepath.Join(t.TempDir(), "nft"), prepare: func(path string) error { return os.WriteFile(path, []byte("fixture"), 0o700) }, runErr: errors.New("permission denied")},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if tt.prepare != nil {
				if err := tt.prepare(tt.path); err != nil {
					t.Fatal(err)
				}
			}
			errs := map[string]error{}
			if tt.runErr != nil {
				errs[tt.path+" -j list ruleset"] = tt.runErr
			}
			candidate := testLinuxOps(&scriptedCommandRunner{outputs: outputs, errors: errs})
			candidate.paths.nft = tt.path
			if err := candidate.ValidateFirewall(context.Background(), contracts); err == nil {
				t.Fatal("unavailable nft inspection was accepted")
			}
		})
	}

	metadataFree := testLinuxOps(&scriptedCommandRunner{outputs: outputs, errors: map[string]error{}})
	metadataFree.paths.nft = nft
	outputs[nft+" -j list ruleset"] = []byte(`{"nftables":[]}`)
	if err := metadataFree.ValidateFirewall(context.Background(), contracts); err == nil {
		t.Fatal("metadata-free nft output was accepted as an empty ruleset")
	}
}

func legacyRulesetFixture(contracts []forwardingPathContract) string {
	filter := []string{
		"*filter",
		":INPUT ACCEPT [0:0]",
		":FORWARD ACCEPT [0:0]",
		":OUTPUT ACCEPT [0:0]",
		":" + filterChainName + " - [0:0]",
		"-A FORWARD -j " + filterChainName,
	}
	mangle := []string{
		"*mangle",
		":PREROUTING ACCEPT [0:0]",
		":INPUT ACCEPT [0:0]",
		":FORWARD ACCEPT [0:0]",
		":OUTPUT ACCEPT [0:0]",
		":POSTROUTING ACCEPT [0:0]",
		":" + mssChainName + " - [0:0]",
		"-A FORWARD -j " + mssChainName,
	}
	for _, contract := range contracts {
		filter = append(filter, "-A "+filterChainName+" -i "+contract.Input+" -o "+contract.Output+" -j ACCEPT")
		mangle = append(mangle, "-A "+mssChainName+" -i "+contract.Input+" -o "+contract.Output+" -p tcp -m tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss "+strconv.Itoa(contract.MSS))
	}
	filter = append(filter, "COMMIT")
	mangle = append(mangle, "-A "+mssChainName+" -j RETURN", "COMMIT")
	return strings.Join([]string{
		"*raw\n:PREROUTING ACCEPT [0:0]\n:OUTPUT ACCEPT [0:0]\nCOMMIT",
		strings.Join(mangle, "\n"),
		"*nat\n:PREROUTING ACCEPT [0:0]\n:INPUT ACCEPT [0:0]\n:OUTPUT ACCEPT [0:0]\n:POSTROUTING ACCEPT [0:0]\nCOMMIT",
		strings.Join(filter, "\n"),
		"*security\n:INPUT ACCEPT [0:0]\n:FORWARD ACCEPT [0:0]\n:OUTPUT ACCEPT [0:0]\nCOMMIT",
	}, "\n")
}

func insertRuleBeforeCommit(rules, table, rule string) string {
	start := strings.Index(rules, "*"+table+"\n")
	if start < 0 {
		return rules
	}
	commit := strings.Index(rules[start:], "\nCOMMIT")
	if commit < 0 {
		return rules
	}
	commit += start
	return rules[:commit] + "\n" + rule + rules[commit:]
}

func TestLinuxRoutingLockIsExclusiveAndReleaseIsIdempotent(t *testing.T) {
	lockPath := filepath.Join(t.TempDir(), "routing.lock")
	first := &systemOpsLinux{lockPath: lockPath}
	second := &systemOpsLinux{lockPath: lockPath}
	lock, err := first.AcquireLock()
	if err != nil {
		t.Fatalf("first lock: %v", err)
	}
	if _, err := second.AcquireLock(); err == nil {
		t.Fatal("second process lock unexpectedly succeeded")
	}
	if err := lock.Release(); err != nil {
		t.Fatalf("release: %v", err)
	}
	if err := lock.Release(); err != nil {
		t.Fatalf("idempotent release: %v", err)
	}
	reacquired, err := second.AcquireLock()
	if err != nil {
		t.Fatalf("reacquire: %v", err)
	}
	if err := reacquired.Release(); err != nil {
		t.Fatalf("release reacquired lock: %v", err)
	}
}
