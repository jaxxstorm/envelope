package model

import (
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"strings"
)

const (
	maxIdentifierLength   = 256
	maxErrorCodeLength    = 64
	maxErrorMessageLength = 1024
)

func (p Phase) Validate() error {
	switch p {
	case PhaseStable, PhaseOwnerObserved, PhaseRouteIntentPersisted, PhaseRoutesConverging, PhaseDegraded:
		return nil
	default:
		return fmt.Errorf("invalid phase %q", p)
	}
}

func (e *StateError) Validate() error {
	if e == nil {
		return errors.New("state error is nil")
	}
	var errs []error
	if e.Code == "" || len(e.Code) > maxErrorCodeLength || !isErrorCode(string(e.Code)) {
		errs = append(errs, fmt.Errorf("invalid error code %q", e.Code))
	}
	if strings.TrimSpace(e.Message) == "" {
		errs = append(errs, errors.New("error message is required"))
	} else if len(e.Message) > maxErrorMessageLength {
		errs = append(errs, fmt.Errorf("error message exceeds %d bytes", maxErrorMessageLength))
	}
	if e.At.IsZero() {
		errs = append(errs, errors.New("error timestamp is required"))
	}
	return errors.Join(errs...)
}

func (l *Lease) Validate() error {
	if l == nil {
		return errors.New("lease is nil")
	}
	var errs []error
	if err := validateIdentifier("lease holder", l.HolderID); err != nil {
		errs = append(errs, err)
	}
	if l.FenceTerm == 0 {
		errs = append(errs, errors.New("lease fence term must be positive"))
	}
	if l.RecordVersion == 0 {
		errs = append(errs, errors.New("lease record version must be positive"))
	}
	if l.AcquiredAt.IsZero() || l.RenewedAt.IsZero() || l.ExpiresAt.IsZero() {
		errs = append(errs, errors.New("lease timestamps are required"))
	} else {
		if l.RenewedAt.Before(l.AcquiredAt) {
			errs = append(errs, errors.New("lease renewal precedes acquisition"))
		}
		if !l.ExpiresAt.After(l.RenewedAt) {
			errs = append(errs, errors.New("lease expiry must follow renewal"))
		}
	}
	return errors.Join(errs...)
}

func (a *DomainAuthority) Validate() error {
	if a == nil {
		return errors.New("domain authority is nil")
	}
	var errs []error
	if err := validateTopologyHash(a.TopologyHash); err != nil {
		errs = append(errs, err)
	}
	for label, value := range map[string]string{
		"deployment ID":              a.DeploymentID,
		"domain ID":                  a.DomainID,
		"site ID":                    a.SiteID,
		"VPC ID":                     a.VPCID,
		"region":                     a.Region,
		"route table ID":             a.RouteTableID,
		"GWLBE subnet ID":            a.GWLBESubnetID,
		"route table association ID": a.RouteTableAssociationID,
	} {
		if err := validateIdentifier(label, value); err != nil {
			errs = append(errs, err)
		}
	}
	source, err := validateIPv4Prefix("source prefix", a.SourcePrefix)
	if err != nil {
		errs = append(errs, err)
	}

	if len(a.RemotePrefixes) == 0 {
		errs = append(errs, errors.New("remote prefixes are required"))
	}
	type namedPrefix struct {
		raw    string
		prefix netip.Prefix
	}
	remote := make([]namedPrefix, 0, len(a.RemotePrefixes))
	seenRemote := make(map[string]struct{}, len(a.RemotePrefixes))
	for i, raw := range a.RemotePrefixes {
		prefix, prefixErr := validateIPv4Prefix(fmt.Sprintf("remote prefix %d", i), raw)
		if prefixErr != nil {
			errs = append(errs, prefixErr)
			continue
		}
		if _, exists := seenRemote[raw]; exists {
			errs = append(errs, fmt.Errorf("duplicate remote prefix %q", raw))
			continue
		}
		seenRemote[raw] = struct{}{}
		if err == nil && source.Overlaps(prefix) {
			errs = append(errs, fmt.Errorf("source prefix %q overlaps remote prefix %q", a.SourcePrefix, raw))
		}
		for _, previous := range remote {
			if previous.prefix.Overlaps(prefix) {
				errs = append(errs, fmt.Errorf("remote prefix %q overlaps remote prefix %q", previous.raw, raw))
			}
		}
		remote = append(remote, namedPrefix{raw: raw, prefix: prefix})
	}

	if len(a.Owners) < 2 {
		errs = append(errs, errors.New("domain authority requires at least two owners"))
	}
	seenRouter := make(map[string]struct{}, len(a.Owners))
	seenNode := make(map[string]struct{}, len(a.Owners))
	seenInstance := make(map[string]struct{}, len(a.Owners))
	seenENI := make(map[string]struct{}, len(a.Owners))
	seenAZ := make(map[string]struct{}, len(a.Owners))
	for i, owner := range a.Owners {
		for label, value := range map[string]string{
			"router ID":         owner.RouterID,
			"stable node ID":    owner.StableNodeID,
			"instance ID":       owner.InstanceID,
			"ENI ID":            owner.ENIID,
			"VPC ID":            owner.VPCID,
			"subnet ID":         owner.SubnetID,
			"availability zone": owner.AvailabilityZone,
			"region":            owner.Region,
		} {
			if fieldErr := validateIdentifier(fmt.Sprintf("owner %d %s", i, label), value); fieldErr != nil {
				errs = append(errs, fieldErr)
			}
		}
		checkUnique := func(label, value string, seen map[string]struct{}) {
			if _, exists := seen[value]; exists && value != "" {
				errs = append(errs, fmt.Errorf("duplicate owner %s %q", label, value))
			}
			seen[value] = struct{}{}
		}
		checkUnique("router ID", owner.RouterID, seenRouter)
		checkUnique("stable node ID", owner.StableNodeID, seenNode)
		checkUnique("instance ID", owner.InstanceID, seenInstance)
		checkUnique("ENI ID", owner.ENIID, seenENI)
		if owner.VPCID != a.VPCID {
			errs = append(errs, fmt.Errorf("owner %q VPC %q does not match domain VPC %q", owner.RouterID, owner.VPCID, a.VPCID))
		}
		if owner.Region != a.Region {
			errs = append(errs, fmt.Errorf("owner %q region %q does not match domain region %q", owner.RouterID, owner.Region, a.Region))
		}
		if !availabilityZoneMatchesRegion(owner.AvailabilityZone, a.Region) {
			errs = append(errs, fmt.Errorf("owner %q availability zone %q does not belong to domain region %q", owner.RouterID, owner.AvailabilityZone, a.Region))
		}
		seenAZ[owner.AvailabilityZone] = struct{}{}
	}
	if len(a.Owners) >= 2 && len(seenAZ) < 2 {
		errs = append(errs, errors.New("domain owners must span at least two availability zones"))
	}
	if _, found := a.OwnerByStableNode(a.PreferredOwner); !found {
		errs = append(errs, fmt.Errorf("preferred owner %q is not an authority owner", a.PreferredOwner))
	}
	return errors.Join(errs...)
}

func (s *RouteSnapshot) Validate(authority DomainAuthority) error {
	if s == nil {
		return errors.New("route snapshot is nil")
	}
	var errs []error
	if err := authority.Validate(); err != nil {
		errs = append(errs, fmt.Errorf("authority: %w", err))
	}
	if s.RouteTableID != authority.RouteTableID {
		errs = append(errs, fmt.Errorf("snapshot route table %q does not match authority route table %q", s.RouteTableID, authority.RouteTableID))
	}
	if s.CapturedAt.IsZero() {
		errs = append(errs, errors.New("snapshot capture time is required"))
	}
	expected := make(map[string]struct{}, len(authority.RemotePrefixes))
	for _, prefix := range authority.RemotePrefixes {
		expected[prefix] = struct{}{}
	}
	seen := make(map[string]struct{}, len(s.Routes))
	for i, route := range s.Routes {
		if _, err := validateIPv4Prefix(fmt.Sprintf("snapshot route %d destination", i), route.DestinationPrefix); err != nil {
			errs = append(errs, err)
		}
		if _, exists := seen[route.DestinationPrefix]; exists {
			errs = append(errs, fmt.Errorf("duplicate snapshot route prefix %q", route.DestinationPrefix))
		}
		seen[route.DestinationPrefix] = struct{}{}
		if _, exists := expected[route.DestinationPrefix]; !exists {
			errs = append(errs, fmt.Errorf("snapshot route %d prefix %q is outside domain authority", i, route.DestinationPrefix))
		}
		if !authority.AllowsENI(route.TargetENIID) {
			errs = append(errs, fmt.Errorf("snapshot route %q targets unauthorized ENI %q", route.DestinationPrefix, route.TargetENIID))
		}
		if err := validateIdentifier(fmt.Sprintf("snapshot route %d state", i), route.State); err != nil {
			errs = append(errs, err)
		}
		if err := validateIdentifier(fmt.Sprintf("snapshot route %d origin", i), route.Origin); err != nil {
			errs = append(errs, err)
		}
	}
	for prefix := range expected {
		if _, exists := seen[prefix]; !exists {
			errs = append(errs, fmt.Errorf("snapshot is missing authoritative route %q", prefix))
		}
	}
	return errors.Join(errs...)
}

func (p *RouteProgress) Validate() error {
	if p == nil {
		return errors.New("route progress is nil")
	}
	var errs []error
	if _, err := validateIPv4Prefix("route progress destination", p.DestinationPrefix); err != nil {
		errs = append(errs, err)
	}
	if p.AttemptedAt != nil && p.AttemptedAt.IsZero() {
		errs = append(errs, errors.New("route attempt time cannot be zero"))
	}
	if p.CompletedAt != nil {
		if p.CompletedAt.IsZero() {
			errs = append(errs, errors.New("route completion time cannot be zero"))
		}
		if p.AttemptedAt == nil {
			errs = append(errs, errors.New("completed route was not attempted"))
		} else if p.CompletedAt.Before(*p.AttemptedAt) {
			errs = append(errs, errors.New("route completion precedes attempt"))
		}
		if p.ObservedENIID == "" {
			errs = append(errs, errors.New("completed route requires an observed ENI"))
		}
	}
	if p.AttemptedAt == nil && (p.ObservedENIID != "" || p.Ambiguous || p.Error != nil) {
		errs = append(errs, errors.New("pending route cannot have an outcome"))
	}
	if p.Error != nil {
		if err := p.Error.Validate(); err != nil {
			errs = append(errs, fmt.Errorf("route error: %w", err))
		}
		if p.AttemptedAt != nil && !p.Error.At.IsZero() && p.Error.At.Before(*p.AttemptedAt) {
			errs = append(errs, errors.New("route error precedes attempt"))
		}
	}
	return errors.Join(errs...)
}

func (i *RouteIntent) Validate(authority DomainAuthority) error {
	if i == nil {
		return errors.New("route intent is nil")
	}
	var errs []error
	if err := authority.Validate(); err != nil {
		errs = append(errs, fmt.Errorf("authority: %w", err))
	}
	if err := validateIdentifier("transaction ID", i.TransactionID); err != nil {
		errs = append(errs, err)
	}
	if i.FenceTerm == 0 {
		errs = append(errs, errors.New("intent fence term must be positive"))
	}
	owner, found := authority.OwnerByStableNode(i.DesiredOwner)
	if !found {
		errs = append(errs, fmt.Errorf("desired owner %q is outside domain authority", i.DesiredOwner))
	} else if owner.ENIID != i.DesiredENIID {
		errs = append(errs, fmt.Errorf("desired ENI %q does not belong to owner %q", i.DesiredENIID, i.DesiredOwner))
	}
	if i.CreatedAt.IsZero() {
		errs = append(errs, errors.New("intent creation time is required"))
	}
	if err := i.Before.Validate(authority); err != nil {
		errs = append(errs, fmt.Errorf("before snapshot: %w", err))
	} else if !i.CreatedAt.IsZero() && i.CreatedAt.Before(i.Before.CapturedAt) {
		errs = append(errs, errors.New("intent creation precedes before snapshot"))
	}
	if len(i.Progress) != len(authority.RemotePrefixes) {
		errs = append(errs, fmt.Errorf("route progress has %d entries; expected %d", len(i.Progress), len(authority.RemotePrefixes)))
	}
	seenIncomplete := false
	for index := range i.Progress {
		progress := &i.Progress[index]
		if err := progress.Validate(); err != nil {
			errs = append(errs, fmt.Errorf("route progress %d: %w", index, err))
		}
		if index < len(authority.RemotePrefixes) && progress.DestinationPrefix != authority.RemotePrefixes[index] {
			errs = append(errs, fmt.Errorf("route progress %d prefix %q does not match ordered authority prefix %q", index, progress.DestinationPrefix, authority.RemotePrefixes[index]))
		}
		if progress.AttemptedAt != nil && !i.CreatedAt.IsZero() && progress.AttemptedAt.Before(i.CreatedAt) {
			errs = append(errs, fmt.Errorf("route progress %d attempt precedes intent", index))
		}
		if progress.Completed() {
			if seenIncomplete {
				errs = append(errs, fmt.Errorf("route progress %d completed after an incomplete route", index))
			}
			if progress.ObservedENIID != i.DesiredENIID {
				errs = append(errs, fmt.Errorf("route progress %d completed on ENI %q instead of desired ENI %q", index, progress.ObservedENIID, i.DesiredENIID))
			}
			continue
		}
		if progress.Attempted() {
			if seenIncomplete {
				errs = append(errs, fmt.Errorf("route progress %d was attempted before an earlier route completed", index))
			}
		}
		seenIncomplete = true
	}
	return errors.Join(errs...)
}

func (o *OwnerObservation) Validate() error {
	if o == nil {
		return errors.New("owner observation is nil")
	}
	var errs []error
	if o.SolePrimary && o.StableNodeID == "" {
		errs = append(errs, errors.New("sole primary observation requires a stable node ID"))
	}
	if o.StableNodeID != "" {
		if err := validateIdentifier("observed stable node ID", o.StableNodeID); err != nil {
			errs = append(errs, err)
		}
	}
	if o.Healthy && (!o.Online || o.Expired) {
		errs = append(errs, errors.New("healthy owner observation must be online and non-expired"))
	}
	if o.OwnerChangeGeneration == 0 {
		if o.OwnerSince != nil {
			errs = append(errs, errors.New("owner since requires a positive owner change generation"))
		}
	} else if o.Healthy && o.OwnerSince == nil {
		errs = append(errs, errors.New("healthy generated owner observation requires an owner since timestamp"))
	}
	if o.OwnerSince != nil {
		if o.OwnerSince.IsZero() {
			errs = append(errs, errors.New("owner since timestamp cannot be zero"))
		}
		if !o.Healthy || !o.SolePrimary || o.StableNodeID == "" {
			errs = append(errs, errors.New("owner since requires a healthy sole primary"))
		}
	}
	if o.Healthy && o.Error != nil {
		errs = append(errs, errors.New("healthy owner observation cannot contain an error"))
	}
	advertised, advertisedErrs := validatePrefixSet("advertised prefix", o.AdvertisedPrefixes)
	if advertisedErrs != nil {
		errs = append(errs, advertisedErrs)
	}
	_, enabledErrs := validatePrefixSet("enabled prefix", o.EnabledPrefixes)
	if enabledErrs != nil {
		errs = append(errs, enabledErrs)
	}
	for _, prefix := range o.EnabledPrefixes {
		if _, exists := advertised[prefix]; !exists {
			errs = append(errs, fmt.Errorf("enabled prefix %q is not advertised", prefix))
		}
	}
	if o.Error != nil {
		if err := o.Error.Validate(); err != nil {
			errs = append(errs, fmt.Errorf("owner observation error: %w", err))
		}
	}
	return errors.Join(errs...)
}

func (o *Observation) Validate() error {
	if o == nil {
		return errors.New("observation is nil")
	}
	var errs []error
	if err := validateIdentifier("controller ID", o.ControllerID); err != nil {
		errs = append(errs, err)
	}
	if err := validateTopologyHash(o.TopologyHash); err != nil {
		errs = append(errs, err)
	}
	if o.Sequence == 0 {
		errs = append(errs, errors.New("observation sequence must be positive"))
	}
	if o.CapturedAt.IsZero() || o.ExpiresAt.IsZero() {
		errs = append(errs, errors.New("observation timestamps are required"))
	} else if !o.ExpiresAt.After(o.CapturedAt) {
		errs = append(errs, errors.New("observation expiry must follow capture"))
	}
	if len(o.Domains) == 0 {
		errs = append(errs, errors.New("observation domains are required"))
	}
	for domainID, domain := range o.Domains {
		if err := validateIdentifier("observation domain ID", domainID); err != nil {
			errs = append(errs, err)
		}
		if err := domain.Validate(); err != nil {
			errs = append(errs, fmt.Errorf("domain %q observation: %w", domainID, err))
		}
		if domain.OwnerSince != nil && !o.CapturedAt.IsZero() && domain.OwnerSince.After(o.CapturedAt) {
			errs = append(errs, fmt.Errorf("domain %q owner since timestamp follows observation capture", domainID))
		}
		if domain.OwnerChangeGeneration > o.Sequence {
			errs = append(errs, fmt.Errorf("domain %q owner change generation exceeds observation sequence", domainID))
		}
		if domain.Healthy && domain.OwnerSince != nil && domain.OwnerChangeGeneration == o.Sequence && !domain.OwnerSince.Equal(o.CapturedAt) {
			errs = append(errs, fmt.Errorf("domain %q current owner generation must begin at observation capture", domainID))
		}
	}
	if !o.BackendHealthy && o.Error == nil {
		errs = append(errs, errors.New("unhealthy backend observation requires an error"))
	}
	if o.Error != nil {
		if err := o.Error.Validate(); err != nil {
			errs = append(errs, fmt.Errorf("observation error: %w", err))
		}
	}
	return errors.Join(errs...)
}

func (s *DomainState) Validate() error {
	if s == nil {
		return errors.New("domain state is nil")
	}
	var errs []error
	if err := s.Authority.Validate(); err != nil {
		errs = append(errs, fmt.Errorf("authority: %w", err))
	}
	if s.Revision == 0 {
		errs = append(errs, errors.New("document revision must be positive"))
	}
	if err := s.Phase.Validate(); err != nil {
		errs = append(errs, err)
	}
	if _, found := s.Authority.OwnerByStableNode(s.StableOwner); !found {
		errs = append(errs, fmt.Errorf("stable owner %q is outside domain authority", s.StableOwner))
	}
	if s.ObservedOwner == "" && s.OwnerObservedAt != nil {
		errs = append(errs, errors.New("owner observation time is set without an observed owner"))
	}
	if s.ObservedOwner != "" {
		if _, found := s.Authority.OwnerByStableNode(s.ObservedOwner); !found {
			errs = append(errs, fmt.Errorf("observed owner %q is outside domain authority", s.ObservedOwner))
		}
		if s.OwnerObservedAt == nil || s.OwnerObservedAt.IsZero() {
			errs = append(errs, errors.New("observed owner requires a non-zero observation time"))
		}
	}
	if s.Lease != nil {
		if err := s.Lease.Validate(); err != nil {
			errs = append(errs, fmt.Errorf("lease: %w", err))
		}
		if s.Lease.FenceTerm != s.FenceTerm {
			errs = append(errs, fmt.Errorf("lease fence %d does not match state fence %d", s.Lease.FenceTerm, s.FenceTerm))
		}
	}
	if s.Intent != nil {
		if err := s.Intent.Validate(s.Authority); err != nil {
			errs = append(errs, fmt.Errorf("intent: %w", err))
		}
		if s.Intent.FenceTerm > s.FenceTerm {
			errs = append(errs, fmt.Errorf("intent fence %d exceeds state fence %d", s.Intent.FenceTerm, s.FenceTerm))
		}
		if s.Intent.DesiredOwner != s.ObservedOwner {
			errs = append(errs, errors.New("intent desired owner does not match observed owner"))
		}
	}
	if s.Error != nil {
		if err := s.Error.Validate(); err != nil {
			errs = append(errs, fmt.Errorf("domain error: %w", err))
		}
	}
	if s.LastTransitionAt.IsZero() || s.UpdatedAt.IsZero() {
		errs = append(errs, errors.New("domain state timestamps are required"))
	} else if s.UpdatedAt.Before(s.LastTransitionAt) {
		errs = append(errs, errors.New("domain update precedes last transition"))
	}
	if s.OwnerObservedAt != nil && !s.UpdatedAt.IsZero() && s.UpdatedAt.Before(*s.OwnerObservedAt) {
		errs = append(errs, errors.New("domain update precedes owner observation"))
	}
	if s.Intent != nil && !s.UpdatedAt.IsZero() && s.UpdatedAt.Before(s.Intent.CreatedAt) {
		errs = append(errs, errors.New("domain update precedes route intent"))
	}
	if s.Lease != nil && !s.UpdatedAt.IsZero() && s.UpdatedAt.Before(s.Lease.RenewedAt) {
		errs = append(errs, errors.New("domain update precedes lease renewal"))
	}
	if s.CooldownUntil != nil && s.CooldownUntil.IsZero() {
		errs = append(errs, errors.New("cooldown deadline cannot be zero"))
	}
	if s.Error != nil && !s.UpdatedAt.IsZero() && s.UpdatedAt.Before(s.Error.At) {
		errs = append(errs, errors.New("domain update precedes its error"))
	}
	if s.Intent != nil && !s.UpdatedAt.IsZero() {
		for index, progress := range s.Intent.Progress {
			if progress.AttemptedAt != nil && s.UpdatedAt.Before(*progress.AttemptedAt) {
				errs = append(errs, fmt.Errorf("domain update precedes route progress %d attempt", index))
			}
			if progress.CompletedAt != nil && s.UpdatedAt.Before(*progress.CompletedAt) {
				errs = append(errs, fmt.Errorf("domain update precedes route progress %d completion", index))
			}
			if progress.Error != nil && s.UpdatedAt.Before(progress.Error.At) {
				errs = append(errs, fmt.Errorf("domain update precedes route progress %d error", index))
			}
		}
	}

	switch s.Phase {
	case PhaseStable:
		if s.ObservedOwner != "" || s.OwnerObservedAt != nil || s.Intent != nil || s.Error != nil {
			errs = append(errs, errors.New("stable phase cannot retain observation, intent, or error state"))
		}
	case PhaseOwnerObserved:
		if s.ObservedOwner == "" || s.OwnerObservedAt == nil {
			errs = append(errs, errors.New("owner-observed phase requires an observed owner"))
		}
		if s.Intent != nil || s.Error != nil {
			errs = append(errs, errors.New("owner-observed phase cannot retain intent or error state"))
		}
	case PhaseRouteIntentPersisted:
		if s.ObservedOwner == "" || s.Intent == nil {
			errs = append(errs, errors.New("route-intent-persisted phase requires owner observation and intent"))
		}
		if s.Error != nil {
			errs = append(errs, errors.New("route-intent-persisted phase cannot retain an error"))
		}
		if s.Intent != nil {
			for _, progress := range s.Intent.Progress {
				if progress.Attempted() {
					errs = append(errs, errors.New("route-intent-persisted phase cannot contain attempted routes"))
					break
				}
			}
		}
	case PhaseRoutesConverging:
		if s.ObservedOwner == "" || s.Intent == nil {
			errs = append(errs, errors.New("routes-converging phase requires owner observation and intent"))
		}
		if s.Error != nil {
			errs = append(errs, errors.New("routes-converging phase cannot retain a domain error"))
		}
	case PhaseDegraded:
		if s.Error == nil {
			errs = append(errs, errors.New("degraded phase requires an error"))
		}
	}
	return errors.Join(errs...)
}

func validateIdentifier(label, value string) error {
	if strings.TrimSpace(value) == "" {
		return fmt.Errorf("%s is required", label)
	}
	if value != strings.TrimSpace(value) {
		return fmt.Errorf("%s must not have surrounding whitespace", label)
	}
	if len(value) > maxIdentifierLength {
		return fmt.Errorf("%s exceeds %d bytes", label, maxIdentifierLength)
	}
	for _, r := range value {
		if r < 0x20 || r == 0x7f {
			return fmt.Errorf("%s contains a control character", label)
		}
	}
	return nil
}

func validateTopologyHash(hash string) error {
	if len(hash) != 64 || hash != strings.ToLower(hash) {
		return errors.New("topology hash must be 64 lowercase hexadecimal characters")
	}
	if _, err := hex.DecodeString(hash); err != nil {
		return errors.New("topology hash must be 64 lowercase hexadecimal characters")
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

func validatePrefixSet(label string, prefixes []string) (map[string]struct{}, error) {
	seen := make(map[string]struct{}, len(prefixes))
	var errs []error
	for index, raw := range prefixes {
		if _, err := validateIPv4Prefix(fmt.Sprintf("%s %d", label, index), raw); err != nil {
			errs = append(errs, err)
		}
		if _, exists := seen[raw]; exists {
			errs = append(errs, fmt.Errorf("duplicate %s %q", label, raw))
		}
		seen[raw] = struct{}{}
	}
	return seen, errors.Join(errs...)
}

func isErrorCode(code string) bool {
	for index, r := range code {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-' && index > 0 {
			continue
		}
		return false
	}
	return code != "" && !strings.HasSuffix(code, "-")
}

func availabilityZoneMatchesRegion(availabilityZone, region string) bool {
	if !strings.HasPrefix(availabilityZone, region) {
		return false
	}
	suffix := strings.TrimPrefix(availabilityZone, region)
	return suffix != "" && (suffix[0] == '-' || suffix[0] >= 'a' && suffix[0] <= 'z')
}
