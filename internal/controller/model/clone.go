package model

import "slices"

func (e *StateError) Clone() *StateError {
	if e == nil {
		return nil
	}
	clone := *e
	return &clone
}

func (l *Lease) Clone() *Lease {
	if l == nil {
		return nil
	}
	clone := *l
	return &clone
}

func (a DomainAuthority) Clone() DomainAuthority {
	a.RemotePrefixes = slices.Clone(a.RemotePrefixes)
	a.Owners = slices.Clone(a.Owners)
	return a
}

func (s RouteSnapshot) Clone() RouteSnapshot {
	s.Routes = slices.Clone(s.Routes)
	return s
}

func (p RouteProgress) Clone() RouteProgress {
	if p.AttemptedAt != nil {
		attemptedAt := *p.AttemptedAt
		p.AttemptedAt = &attemptedAt
	}
	if p.CompletedAt != nil {
		completedAt := *p.CompletedAt
		p.CompletedAt = &completedAt
	}
	p.Error = p.Error.Clone()
	return p
}

func (i *RouteIntent) Clone() *RouteIntent {
	if i == nil {
		return nil
	}
	clone := *i
	clone.Before = i.Before.Clone()
	if i.Progress != nil {
		clone.Progress = make([]RouteProgress, len(i.Progress))
		for index, progress := range i.Progress {
			clone.Progress[index] = progress.Clone()
		}
	}
	return &clone
}

func (o OwnerObservation) Clone() OwnerObservation {
	if o.OwnerSince != nil {
		ownerSince := *o.OwnerSince
		o.OwnerSince = &ownerSince
	}
	o.AdvertisedPrefixes = slices.Clone(o.AdvertisedPrefixes)
	o.EnabledPrefixes = slices.Clone(o.EnabledPrefixes)
	o.Error = o.Error.Clone()
	return o
}

func (o *Observation) Clone() *Observation {
	if o == nil {
		return nil
	}
	clone := *o
	if o.Domains != nil {
		clone.Domains = make(map[string]OwnerObservation, len(o.Domains))
		for domainID, domain := range o.Domains {
			clone.Domains[domainID] = domain.Clone()
		}
	}
	clone.Error = o.Error.Clone()
	return &clone
}

func (s *DomainState) Clone() *DomainState {
	if s == nil {
		return nil
	}
	clone := *s
	clone.Authority = s.Authority.Clone()
	clone.Lease = s.Lease.Clone()
	if s.OwnerObservedAt != nil {
		ownerObservedAt := *s.OwnerObservedAt
		clone.OwnerObservedAt = &ownerObservedAt
	}
	clone.Intent = s.Intent.Clone()
	if s.CooldownUntil != nil {
		cooldownUntil := *s.CooldownUntil
		clone.CooldownUntil = &cooldownUntil
	}
	clone.Error = s.Error.Clone()
	return &clone
}
