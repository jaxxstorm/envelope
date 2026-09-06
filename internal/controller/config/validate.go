package config

import (
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"time"
)

const (
	MinReplicaCount       = 3
	MaxReplicaCount       = 31
	MinPolicyDuration     = 100 * time.Millisecond
	MaxPolicyDuration     = 24 * time.Hour
	maxConfigStringLength = 512
)

var (
	environmentNamePattern = regexp.MustCompile(`^[A-Z_][A-Z0-9_]*$`)
	controllerIDPattern    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
	awsRegionPattern       = regexp.MustCompile(`^[a-z][a-z0-9]*(?:-[a-z0-9]+)*-[0-9]+$`)
)

func (c ProcessConfig) Validate() error {
	var errs []error
	if err := validateControllerID(c.ControllerID); err != nil {
		errs = append(errs, err)
	}
	if err := validateText("topology path", c.TopologyPath); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

// ValidateForTopology additionally checks that this process is an explicitly
// configured controller replica.
func (c ProcessConfig) ValidateForTopology(topology *Topology) error {
	if err := c.Validate(); err != nil {
		return err
	}
	if topology == nil {
		return errors.New("topology is nil")
	}
	if err := topology.Validate(); err != nil {
		return fmt.Errorf("topology: %w", err)
	}
	if !topology.HasControllerID(c.ControllerID) {
		return fmt.Errorf("controller ID %q is not allowed by topology", c.ControllerID)
	}
	return nil
}

func (p Policy) Validate() error {
	var errs []error
	if p.ReplicaCount < MinReplicaCount || p.ReplicaCount > MaxReplicaCount {
		errs = append(errs, fmt.Errorf("replica count must be between %d and %d", MinReplicaCount, MaxReplicaCount))
	}
	if p.ObservationQuorum > p.ReplicaCount {
		errs = append(errs, errors.New("observation quorum cannot exceed replica count"))
	}
	if p.ObservationQuorum <= p.ReplicaCount/2 {
		errs = append(errs, errors.New("observation quorum must be a strict majority of replicas"))
	}

	timings := []struct {
		name  string
		value Duration
	}{
		{"observation interval", p.ObservationInterval},
		{"observation freshness", p.ObservationFreshness},
		{"failover stability", p.FailoverStability},
		{"failback stability", p.FailbackStability},
		{"cooldown", p.Cooldown},
		{"lease duration", p.LeaseDuration},
		{"lease renew interval", p.LeaseRenewInterval},
		{"lease danger window", p.LeaseDangerWindow},
		{"API timeout", p.APITimeout},
		{"route convergence timeout", p.RouteConvergenceTimeout},
	}
	for _, timing := range timings {
		value := timing.value.Duration()
		if value < MinPolicyDuration || value > MaxPolicyDuration {
			errs = append(errs, fmt.Errorf("%s must be between %s and %s", timing.name, MinPolicyDuration, MaxPolicyDuration))
		}
	}

	if p.ObservationFreshness.Duration() < 2*p.ObservationInterval.Duration() {
		errs = append(errs, errors.New("observation freshness must cover at least two observation intervals"))
	}
	if p.FailoverStability.Duration() < p.ObservationInterval.Duration() {
		errs = append(errs, errors.New("failover stability cannot be shorter than the observation interval"))
	}
	if p.FailbackStability.Duration() <= p.FailoverStability.Duration() {
		errs = append(errs, errors.New("failback stability must be longer than failover stability"))
	}
	if p.LeaseRenewInterval.Duration() >= p.LeaseDuration.Duration() {
		errs = append(errs, errors.New("lease renew interval must be shorter than lease duration"))
	}
	completeAction := p.APITimeout.Duration() + p.RouteConvergenceTimeout.Duration()
	if p.LeaseDangerWindow.Duration() < completeAction {
		errs = append(errs, errors.New("lease danger window must cover the API and route convergence deadlines"))
	}
	if p.LeaseRenewInterval.Duration()+p.LeaseDangerWindow.Duration() >= p.LeaseDuration.Duration() {
		errs = append(errs, errors.New("lease renewal must occur before the lease danger window"))
	}
	return errors.Join(errs...)
}

func (c TailnetConfig) Validate() error {
	if containsSecretValue(reflect.ValueOf(c)) {
		return errors.New("tailnet configuration contains a secret value; use environment indirection")
	}
	var errs []error
	if err := validateText("tailnet name", c.Name); err != nil {
		errs = append(errs, err)
	}
	if err := validateControlURL(c.ControlURL); err != nil {
		errs = append(errs, err)
	}
	if !environmentNamePattern.MatchString(c.TSNetAuthKeyEnv) {
		errs = append(errs, errors.New("tsnet auth key must be an uppercase environment variable name"))
	}
	if !environmentNamePattern.MatchString(c.AdminAPIKeyEnv) {
		errs = append(errs, errors.New("Admin API key must be an uppercase environment variable name"))
	}
	if c.TSNetAuthKeyEnv != "" && c.TSNetAuthKeyEnv == c.AdminAPIKeyEnv {
		errs = append(errs, errors.New("tsnet auth key and Admin API key must use different environment variables"))
	}
	if strings.TrimSpace(c.StateBaseDir) == "" {
		errs = append(errs, errors.New("tailnet state base directory is required"))
	} else if !filepath.IsAbs(c.StateBaseDir) || filepath.Clean(c.StateBaseDir) != c.StateBaseDir {
		errs = append(errs, errors.New("tailnet state base directory must be an absolute clean path"))
	}
	return errors.Join(errs...)
}

func (t *Topology) Validate() error {
	if t == nil {
		return errors.New("topology is nil")
	}
	if containsSecretValue(reflect.ValueOf(*t)) {
		return errors.New("topology contains a secret value; use environment indirection")
	}
	var errs []error
	if t.SchemaVersion != TopologySchemaVersion {
		errs = append(errs, fmt.Errorf("unsupported topology schema version %d; expected %d", t.SchemaVersion, TopologySchemaVersion))
	}
	if err := validateText("deployment ID", t.DeploymentID); err != nil {
		errs = append(errs, err)
	}
	if len(t.ControllerIDs) != t.Policy.ReplicaCount {
		errs = append(errs, fmt.Errorf("controller ID count %d does not match policy replica count %d", len(t.ControllerIDs), t.Policy.ReplicaCount))
	}
	seenController := make(map[string]struct{}, len(t.ControllerIDs))
	for index, controllerID := range t.ControllerIDs {
		if err := validateControllerID(controllerID); err != nil {
			errs = append(errs, fmt.Errorf("controller ID %d: %w", index, err))
		}
		if _, exists := seenController[controllerID]; exists && controllerID != "" {
			errs = append(errs, fmt.Errorf("duplicate controller ID %q", controllerID))
		}
		seenController[controllerID] = struct{}{}
	}
	if err := t.Policy.Validate(); err != nil {
		errs = append(errs, fmt.Errorf("policy: %w", err))
	}
	if err := validateText("DynamoDB table", t.DynamoDB.Table); err != nil {
		errs = append(errs, err)
	}
	if err := validateText("DynamoDB region", t.DynamoDB.Region); err != nil {
		errs = append(errs, err)
	}
	if err := t.Tailnet.Validate(); err != nil {
		errs = append(errs, fmt.Errorf("tailnet: %w", err))
	}
	if len(t.Sites) < 2 {
		errs = append(errs, errors.New("topology requires at least two sites"))
	}
	sites := make(map[string]Site, len(t.Sites))
	seenVPC := make(map[string]string, len(t.Sites))
	type sitePrefix struct {
		siteID string
		raw    string
		prefix netip.Prefix
	}
	var sitePrefixes []sitePrefix
	prefixSite := make(map[string]string)
	for index, site := range t.Sites {
		for label, value := range map[string]string{
			"ID":     site.ID,
			"VPC ID": site.VPCID,
			"region": site.Region,
		} {
			if err := validateText(fmt.Sprintf("site %d %s", index, label), value); err != nil {
				errs = append(errs, err)
			}
		}
		if _, exists := sites[site.ID]; exists && site.ID != "" {
			errs = append(errs, fmt.Errorf("duplicate site ID %q", site.ID))
		}
		sites[site.ID] = site
		if previous, exists := seenVPC[site.VPCID]; exists && site.VPCID != "" {
			errs = append(errs, fmt.Errorf("sites %q and %q share VPC ID %q", previous, site.ID, site.VPCID))
		}
		seenVPC[site.VPCID] = site.ID
		if len(site.LocalPrefixes) == 0 {
			errs = append(errs, fmt.Errorf("site %q local prefixes are required", site.ID))
		}
		for prefixIndex, raw := range site.LocalPrefixes {
			prefix, err := validateIPv4Prefix(fmt.Sprintf("site %q local prefix %d", site.ID, prefixIndex), raw)
			if err != nil {
				errs = append(errs, err)
				continue
			}
			for _, previous := range sitePrefixes {
				if previous.prefix.Overlaps(prefix) {
					errs = append(errs, fmt.Errorf("site %q prefix %q overlaps site %q prefix %q", site.ID, raw, previous.siteID, previous.raw))
				}
			}
			sitePrefixes = append(sitePrefixes, sitePrefix{siteID: site.ID, raw: raw, prefix: prefix})
			prefixSite[raw] = site.ID
		}
	}

	routers := make(map[string]Router, len(t.Routers))
	seenStableNode := make(map[string]string, len(t.Routers))
	seenInstance := make(map[string]string, len(t.Routers))
	seenENI := make(map[string]string, len(t.Routers))
	routersBySite := make(map[string][]Router)
	for index, router := range t.Routers {
		for label, value := range map[string]string{
			"ID":                router.ID,
			"site ID":           router.SiteID,
			"stable node ID":    router.StableNodeID,
			"instance ID":       router.InstanceID,
			"ENI ID":            router.ENIID,
			"VPC ID":            router.VPCID,
			"subnet ID":         router.SubnetID,
			"availability zone": router.AvailabilityZone,
			"region":            router.Region,
		} {
			if err := validateText(fmt.Sprintf("router %d %s", index, label), value); err != nil {
				errs = append(errs, err)
			}
		}
		if _, exists := routers[router.ID]; exists && router.ID != "" {
			errs = append(errs, fmt.Errorf("duplicate router ID %q", router.ID))
		}
		routers[router.ID] = router
		checkIdentity := func(label, value string, seen map[string]string) {
			if previous, exists := seen[value]; exists && value != "" {
				errs = append(errs, fmt.Errorf("routers %q and %q share %s %q", previous, router.ID, label, value))
			}
			seen[value] = router.ID
		}
		checkIdentity("stable node ID", router.StableNodeID, seenStableNode)
		checkIdentity("instance ID", router.InstanceID, seenInstance)
		checkIdentity("ENI ID", router.ENIID, seenENI)
		site, found := sites[router.SiteID]
		if !found {
			errs = append(errs, fmt.Errorf("router %q references unknown site %q", router.ID, router.SiteID))
		} else {
			if router.VPCID != site.VPCID {
				errs = append(errs, fmt.Errorf("router %q VPC %q does not match site VPC %q", router.ID, router.VPCID, site.VPCID))
			}
			if router.Region != site.Region {
				errs = append(errs, fmt.Errorf("router %q region %q does not match site region %q", router.ID, router.Region, site.Region))
			}
			if !availabilityZoneMatchesRegion(router.AvailabilityZone, site.Region) {
				errs = append(errs, fmt.Errorf("router %q availability zone %q does not belong to site region %q", router.ID, router.AvailabilityZone, site.Region))
			}
			routersBySite[router.SiteID] = append(routersBySite[router.SiteID], router)
		}
	}
	for siteID := range sites {
		siteRouters := routersBySite[siteID]
		if len(siteRouters) < 2 {
			errs = append(errs, fmt.Errorf("site %q requires at least two routers", siteID))
			continue
		}
		zones := make(map[string]struct{}, len(siteRouters))
		for _, router := range siteRouters {
			zones[router.AvailabilityZone] = struct{}{}
		}
		if len(zones) < 2 {
			errs = append(errs, fmt.Errorf("site %q routers must span at least two availability zones", siteID))
		}
	}

	if len(t.Domains) == 0 {
		errs = append(errs, errors.New("topology requires at least one domain"))
	}
	seenDomain := make(map[string]struct{}, len(t.Domains))
	seenSource := make(map[string]string, len(t.Domains))
	seenRouteTable := make(map[string]string, len(t.Domains))
	seenGWLBESubnet := make(map[string]string, len(t.Domains))
	seenRouteTableAssociation := make(map[string]string, len(t.Domains))
	seenRouteAuthority := make(map[string]string)
	for index, domain := range t.Domains {
		for label, value := range map[string]string{
			"ID":                         domain.ID,
			"site ID":                    domain.SiteID,
			"route table ID":             domain.RouteTableID,
			"GWLBE subnet ID":            domain.GWLBESubnetID,
			"route table association ID": domain.RouteTableAssociationID,
			"preferred owner":            domain.PreferredOwner,
		} {
			if err := validateText(fmt.Sprintf("domain %d %s", index, label), value); err != nil {
				errs = append(errs, err)
			}
		}
		if _, exists := seenDomain[domain.ID]; exists && domain.ID != "" {
			errs = append(errs, fmt.Errorf("duplicate domain ID %q", domain.ID))
		}
		seenDomain[domain.ID] = struct{}{}
		if _, found := sites[domain.SiteID]; !found {
			errs = append(errs, fmt.Errorf("domain %q references unknown site %q", domain.ID, domain.SiteID))
		}
		source, sourceErr := validateIPv4Prefix(fmt.Sprintf("domain %q source prefix", domain.ID), domain.SourcePrefix)
		if sourceErr != nil {
			errs = append(errs, sourceErr)
		} else {
			sourceSite, found := prefixSite[domain.SourcePrefix]
			if !found || sourceSite != domain.SiteID {
				errs = append(errs, fmt.Errorf("domain %q source prefix %q is not a local prefix of site %q", domain.ID, domain.SourcePrefix, domain.SiteID))
			}
			if previous, exists := seenSource[domain.SourcePrefix]; exists {
				errs = append(errs, fmt.Errorf("domains %q and %q share source prefix %q", previous, domain.ID, domain.SourcePrefix))
			}
			seenSource[domain.SourcePrefix] = domain.ID
		}
		if previous, exists := seenRouteTable[domain.RouteTableID]; exists && domain.RouteTableID != "" {
			errs = append(errs, fmt.Errorf("domains %q and %q share route table %q", previous, domain.ID, domain.RouteTableID))
		}
		seenRouteTable[domain.RouteTableID] = domain.ID
		if previous, exists := seenGWLBESubnet[domain.GWLBESubnetID]; exists && domain.GWLBESubnetID != "" {
			errs = append(errs, fmt.Errorf("domains %q and %q share GWLBE subnet %q", previous, domain.ID, domain.GWLBESubnetID))
		}
		seenGWLBESubnet[domain.GWLBESubnetID] = domain.ID
		if previous, exists := seenRouteTableAssociation[domain.RouteTableAssociationID]; exists && domain.RouteTableAssociationID != "" {
			errs = append(errs, fmt.Errorf("domains %q and %q share route table association %q", previous, domain.ID, domain.RouteTableAssociationID))
		}
		seenRouteTableAssociation[domain.RouteTableAssociationID] = domain.ID
		if len(domain.RemotePrefixes) == 0 {
			errs = append(errs, fmt.Errorf("domain %q remote prefixes are required", domain.ID))
		}
		seenRemote := make(map[string]struct{}, len(domain.RemotePrefixes))
		for remoteIndex, raw := range domain.RemotePrefixes {
			remote, remoteErr := validateIPv4Prefix(fmt.Sprintf("domain %q remote prefix %d", domain.ID, remoteIndex), raw)
			if remoteErr != nil {
				errs = append(errs, remoteErr)
				continue
			}
			if _, exists := seenRemote[raw]; exists {
				errs = append(errs, fmt.Errorf("domain %q has duplicate remote prefix %q", domain.ID, raw))
			}
			seenRemote[raw] = struct{}{}
			remoteSite, found := prefixSite[raw]
			if !found {
				errs = append(errs, fmt.Errorf("domain %q remote prefix %q does not exactly match a site local prefix", domain.ID, raw))
			} else if remoteSite == domain.SiteID {
				errs = append(errs, fmt.Errorf("domain %q remote prefix %q belongs to its local site", domain.ID, raw))
			}
			if sourceErr == nil && source.Overlaps(remote) {
				errs = append(errs, fmt.Errorf("domain %q source prefix %q overlaps remote prefix %q", domain.ID, domain.SourcePrefix, raw))
			}
			authorityKey := domain.RouteTableID + "\x00" + raw
			if previous, exists := seenRouteAuthority[authorityKey]; exists {
				errs = append(errs, fmt.Errorf("domains %q and %q share route authority for table %q prefix %q", previous, domain.ID, domain.RouteTableID, raw))
			}
			seenRouteAuthority[authorityKey] = domain.ID
		}
		for _, prefix := range sitePrefixes {
			if prefix.siteID == domain.SiteID {
				continue
			}
			if _, exists := seenRemote[prefix.raw]; !exists {
				errs = append(errs, fmt.Errorf("domain %q does not manage other-site prefix %q", domain.ID, prefix.raw))
			}
		}
		preferred, found := routers[domain.PreferredOwner]
		if !found {
			errs = append(errs, fmt.Errorf("domain %q preferred owner %q is not a configured router", domain.ID, domain.PreferredOwner))
		} else if preferred.SiteID != domain.SiteID {
			errs = append(errs, fmt.Errorf("domain %q preferred owner %q is not a member of site %q", domain.ID, domain.PreferredOwner, domain.SiteID))
		}
	}
	for _, prefix := range sitePrefixes {
		if _, exists := seenSource[prefix.raw]; !exists {
			errs = append(errs, fmt.Errorf("site %q local prefix %q has no domain", prefix.siteID, prefix.raw))
		}
	}
	return errors.Join(errs...)
}

func validateText(label, value string) error {
	if strings.TrimSpace(value) == "" {
		return fmt.Errorf("%s is required", label)
	}
	if value != strings.TrimSpace(value) {
		return fmt.Errorf("%s must not have surrounding whitespace", label)
	}
	if len(value) > maxConfigStringLength {
		return fmt.Errorf("%s exceeds %d bytes", label, maxConfigStringLength)
	}
	for _, r := range value {
		if r < 0x20 || r == 0x7f {
			return fmt.Errorf("%s contains a control character", label)
		}
	}
	return nil
}

func validateControllerID(value string) error {
	if err := validateText("controller ID", value); err != nil {
		return err
	}
	if !controllerIDPattern.MatchString(value) {
		return errors.New("controller ID must start with an alphanumeric character and contain only letters, digits, dots, underscores, or hyphens")
	}
	return nil
}

func validateControlURL(raw string) error {
	if raw == "" {
		return nil
	}
	if raw != strings.TrimSpace(raw) {
		return errors.New("tailnet control URL must not have surrounding whitespace")
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return errors.New("tailnet control URL must be an absolute HTTPS URL without credentials, query, or fragment")
	}
	return nil
}

func validateIPv4Prefix(label, raw string) (netip.Prefix, error) {
	prefix, err := netip.ParsePrefix(raw)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("%s %q is invalid: %w", label, raw, err)
	}
	if !prefix.Addr().Is4() {
		return netip.Prefix{}, fmt.Errorf("%s %q is not IPv4", label, raw)
	}
	if prefix != prefix.Masked() || prefix.String() != raw {
		return netip.Prefix{}, fmt.Errorf("%s %q is not canonical", label, raw)
	}
	return prefix, nil
}

func containsSecretValue(value reflect.Value) bool {
	if !value.IsValid() {
		return false
	}
	switch value.Kind() {
	case reflect.Interface, reflect.Pointer:
		if value.IsNil() {
			return false
		}
		return containsSecretValue(value.Elem())
	case reflect.Struct:
		for index := 0; index < value.NumField(); index++ {
			if containsSecretValue(value.Field(index)) {
				return true
			}
		}
	case reflect.Slice, reflect.Array:
		for index := 0; index < value.Len(); index++ {
			if containsSecretValue(value.Index(index)) {
				return true
			}
		}
	case reflect.Map:
		iterator := value.MapRange()
		for iterator.Next() {
			if containsSecretValue(iterator.Key()) || containsSecretValue(iterator.Value()) {
				return true
			}
		}
	case reflect.String:
		return looksLikeSecret(value.String())
	}
	return false
}

func looksLikeSecret(value string) bool {
	lower := strings.ToLower(value)
	for _, marker := range []string{"tskey-", "nodekey:", "machinekey:", "privkey:", "-----begin private key-----"} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return len(value) == 20 && (strings.HasPrefix(value, "AKIA") || strings.HasPrefix(value, "ASIA"))
}

func availabilityZoneMatchesRegion(availabilityZone, region string) bool {
	if !awsRegionPattern.MatchString(region) || len(availabilityZone) != len(region)+1 || !strings.HasPrefix(availabilityZone, region) {
		return false
	}
	suffix := availabilityZone[len(region)]
	return suffix >= 'a' && suffix <= 'z'
}
