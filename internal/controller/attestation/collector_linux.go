//go:build linux

package attestation

import (
	"context"
	"net"
	"net/http"
	"net/netip"
	"reflect"
	"sort"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials/ec2rolecreds"
	"github.com/aws/aws-sdk-go-v2/feature/ec2/imds"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/jaxxstorm/envelope/internal/controller/awscontrol"
	"github.com/jaxxstorm/envelope/internal/controller/model"
	"tailscale.com/client/tailscale"
	"tailscale.com/tailcfg"
	"tailscale.com/types/preftype"
)

type nativeCollector struct {
	configuration CollectorConfig
	owner         model.OwnerAuthority
	local         tailscale.LocalClient
	metadata      *imds.Client
	cloud         *ec2.Client
	ownerHealth   *awscontrol.Controller
	authority     model.DomainAuthority
}

func NewNativeCollector(configuration CollectorConfig) (Collector, error) {
	authority, owner, err := configuration.Authority()
	if err != nil {
		return nil, err
	}
	// IMDS is fixed to the link-local endpoint, requires token authentication,
	// and never inherits an environment-controlled alternate endpoint.
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	metadata := imds.New(imds.Options{Endpoint: "http://169.254.169.254", EnableFallback: aws.FalseTernary, ClientEnableState: imds.ClientEnabled, HTTPClient: &http.Client{Transport: transport, Timeout: configuration.Topology.Policy.APITimeout.Duration()}})
	awsConfiguration := aws.Config{Region: owner.Region, Credentials: aws.NewCredentialsCache(ec2rolecreds.New(func(o *ec2rolecreds.Options) { o.Client = metadata })), HTTPClient: &http.Client{Transport: transport, Timeout: configuration.Topology.Policy.APITimeout.Duration()}, Retryer: func() aws.Retryer { return aws.NopRetryer{} }}
	cloud := ec2.NewFromConfig(awsConfiguration, func(o *ec2.Options) { o.BaseEndpoint = aws.String("https://ec2." + owner.Region + ".amazonaws.com") })
	health, err := awscontrol.New(cloud, owner.Region, awscontrol.WithAPITimeout(configuration.Topology.Policy.APITimeout.Duration()))
	if err != nil {
		return nil, err
	}
	return &nativeCollector{configuration: configuration, owner: owner, authority: authority, cloud: cloud, ownerHealth: health, local: tailscale.LocalClient{Socket: "/var/run/tailscale/tailscaled.sock", UseSocketOnly: true}, metadata: metadata}, nil
}

func (c *nativeCollector) Collect(ctx context.Context) (Checks, error) {
	checks := Checks{Backend: "fail", Advertisements: "fail", RemoteRoutes: "fail", LocalPolicy: "fail", Underlay: "fail", Forwarding: "fail", ReversePath: "fail", Firewall: "fail", NoNAT: "fail", MSS: "fail", Peers: "fail"}
	identity, err := c.metadata.GetInstanceIdentityDocument(ctx, &imds.GetInstanceIdentityDocumentInput{})
	if err != nil || identity == nil || identity.InstanceID != c.owner.InstanceID || identity.Region != c.owner.Region || identity.AvailabilityZone != c.owner.AvailabilityZone {
		return checks, ErrRejected
	}
	underlay, err := net.InterfaceByName(c.configuration.UnderlayInterface)
	if err != nil || underlay.Flags&net.FlagUp == 0 || len(underlay.HardwareAddr) != 6 {
		return checks, ErrRejected
	}
	metadata, err := c.metadata.GetMetadata(ctx, &imds.GetMetadataInput{Path: "network/interfaces/macs/" + underlay.HardwareAddr.String() + "/interface-id"})
	if err != nil || metadata == nil || metadata.Content == nil {
		return checks, ErrRejected
	}
	eni, readErr := readBounded(metadata.Content, 128)
	_ = metadata.Content.Close()
	if readErr != nil || strings.TrimSpace(string(eni)) != c.owner.ENIID {
		return checks, ErrRejected
	}
	if kernelValue("/proc/sys/net/ipv4/ip_forward", "1") && kernelValue("/proc/sys/net/ipv6/conf/all/forwarding", "0") && kernelValue("/proc/sys/net/ipv6/conf/default/forwarding", "0") {
		checks.Forwarding = "pass"
	}
	if kernelValue("/proc/sys/net/ipv4/conf/all/rp_filter", "0") && kernelValue("/proc/sys/net/ipv4/conf/default/rp_filter", "0") && kernelValue("/proc/sys/net/ipv4/conf/"+c.configuration.UnderlayInterface+"/rp_filter", "0") && kernelValue("/proc/sys/net/ipv4/conf/tailscale0/rp_filter", "0") {
		checks.ReversePath = "pass"
	}
	status, err := c.local.Status(ctx)
	if err != nil || status == nil || status.Self == nil || string(status.Self.ID) != c.owner.StableNodeID {
		return checks, ErrRejected
	}
	if (status.Version == "1.80.3" || strings.HasPrefix(status.Version, "1.80.3-")) && status.TUN && status.BackendState == "Running" && len(status.Health) == 0 && status.Self.Online && !status.Self.Expired &&
		(status.Self.KeyExpiry == nil || status.Self.KeyExpiry.After(time.Now())) && status.CurrentTailnet != nil && status.CurrentTailnet.Name == c.configuration.Topology.Tailnet.Name {
		checks.Backend = "pass"
	}
	prefs, err := c.local.GetPrefs(ctx)
	if err != nil || prefs == nil {
		return checks, ErrRejected
	}
	var local, remote []string
	for _, site := range c.configuration.Topology.Sites {
		if site.ID == c.authority.SiteID {
			local = append(local, site.LocalPrefixes...)
		} else {
			remote = append(remote, site.LocalPrefixes...)
		}
	}
	advertised := make([]string, 0, len(prefs.AdvertiseRoutes))
	for _, prefix := range prefs.AdvertiseRoutes {
		advertised = append(advertised, prefix.String())
	}
	sort.Strings(advertised)
	sort.Strings(local)
	sort.Strings(remote)
	if _, err := c.ownerHealth.ValidateOwner(ctx, c.authority, c.owner); err != nil {
		return checks, ErrRejected
	}
	gateway, resolver, err := validateUnderlay(ctx, c.cloud, c.configuration, c.owner)
	if err != nil || !resolverReady(resolver) || networkServiceReady(ctx) != nil {
		return checks, ErrRejected
	}
	before, err := inspectKernel(ctx, local, remote, c.configuration.UnderlayInterface, gateway, c.configuration.MaximumTCPMSS)
	if err != nil {
		return checks, err
	}
	exact := len(local) > 0 && strings.Join(advertised, ",") == strings.Join(local, ",") && exactTailnetRoutes(status, local, remote)
	owners, err := servingOwners(status, remote)
	if err != nil {
		return checks, err
	}
	if exact && prefs.WantRunning && prefs.RouteAll && prefs.NoSNAT && !prefs.CorpDNS && prefs.NetfilterMode == preftype.NetfilterOff && prefs.ExitNodeID == "" && !prefs.ExitNodeIP.IsValid() {
		checks.Advertisements = "pass"
	}
	peersReady := len(remote) > 0
	for _, prefix := range remote {
		var address netip.Addr
		matches := 0
		for _, peer := range status.Peer {
			if peer == nil || peer.PrimaryRoutes == nil {
				continue
			}
			for _, route := range peer.PrimaryRoutes.AsSlice() {
				if route.String() != prefix {
					continue
				}
				matches++
				allowed := configuredPeerForPrefix(c.configuration.Topology, prefix, string(peer.ID))
				if allowed && peer.Online && !peer.Expired && (peer.KeyExpiry == nil || peer.KeyExpiry.After(time.Now())) && peer.InNetworkMap && len(peer.TailscaleIPs) > 0 {
					address = peer.TailscaleIPs[0]
				}
			}
		}
		if matches != 1 || !address.IsValid() {
			peersReady = false
			continue
		}
		ping, err := c.local.Ping(ctx, address, tailcfg.PingTSMP)
		if err != nil || ping == nil || ping.Err != "" || ping.IP != address.String() || ping.IsLocalIP || ping.LatencySeconds < 0 || ping.LatencySeconds > 5 || (ping.NodeIP != "" && ping.NodeIP != address.String()) {
			peersReady = false
		}
	}
	if peersReady {
		checks.Peers = "pass"
	}
	after, err := inspectKernel(ctx, local, remote, c.configuration.UnderlayInterface, gateway, c.configuration.MaximumTCPMSS)
	if err != nil || !reflect.DeepEqual(before, after) {
		return checks, ErrRejected
	}
	nextGateway, nextResolver, err := validateUnderlay(ctx, c.cloud, c.configuration, c.owner)
	if err != nil || nextGateway != gateway || nextResolver != resolver || !resolverReady(resolver) || networkServiceReady(ctx) != nil {
		return checks, ErrRejected
	}
	finalStatus, err := c.local.Status(ctx)
	if err != nil || finalStatus == nil || finalStatus.Self == nil || finalStatus.Self.ID != status.Self.ID || !finalStatus.Self.Online || finalStatus.Self.Expired || finalStatus.BackendState != "Running" || !finalStatus.TUN || len(finalStatus.Health) != 0 {
		return checks, ErrRejected
	}
	finalPrefs, err := c.local.GetPrefs(ctx)
	if err != nil || finalPrefs == nil || !finalPrefs.Equals(prefs) {
		return checks, ErrRejected
	}
	finalOwners, err := servingOwners(finalStatus, remote)
	if err != nil || !reflect.DeepEqual(owners, finalOwners) || !exactTailnetRoutes(finalStatus, local, remote) || finalStatus.CurrentTailnet == nil || finalStatus.CurrentTailnet.Name != c.configuration.Topology.Tailnet.Name || (finalStatus.Self.KeyExpiry != nil && !finalStatus.Self.KeyExpiry.After(time.Now())) {
		return checks, ErrRejected
	}
	checks.RemoteRoutes, checks.LocalPolicy, checks.Underlay, checks.Firewall, checks.NoNAT, checks.MSS = "pass", "pass", "pass", "pass", "pass", "pass"
	return checks, ctx.Err()
}
