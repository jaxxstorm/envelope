package config

import (
	"fmt"
	"sort"

	"github.com/jaxxstorm/envelope/internal/controller/model"
)

// DomainAuthority resolves one validated topology domain into the immutable,
// stable-node-based authority persisted by the controller.
func (t *Topology) DomainAuthority(domainID string) (model.DomainAuthority, error) {
	if err := t.Validate(); err != nil {
		return model.DomainAuthority{}, err
	}
	hash, err := t.Hash()
	if err != nil {
		return model.DomainAuthority{}, err
	}
	var domain *Domain
	for index := range t.Domains {
		if t.Domains[index].ID == domainID {
			domain = &t.Domains[index]
			break
		}
	}
	if domain == nil {
		return model.DomainAuthority{}, fmt.Errorf("unknown domain %q", domainID)
	}
	var site Site
	for _, candidate := range t.Sites {
		if candidate.ID == domain.SiteID {
			site = candidate
			break
		}
	}
	authority := model.DomainAuthority{
		TopologyHash:            hash,
		DeploymentID:            t.DeploymentID,
		DomainID:                domain.ID,
		SiteID:                  domain.SiteID,
		VPCID:                   site.VPCID,
		Region:                  site.Region,
		SourcePrefix:            domain.SourcePrefix,
		RouteTableID:            domain.RouteTableID,
		GWLBESubnetID:           domain.GWLBESubnetID,
		RouteTableAssociationID: domain.RouteTableAssociationID,
		RemotePrefixes:          append([]string(nil), domain.RemotePrefixes...),
	}
	for _, router := range t.Routers {
		if router.SiteID != domain.SiteID {
			continue
		}
		authority.Owners = append(authority.Owners, model.OwnerAuthority{
			RouterID:         router.ID,
			StableNodeID:     router.StableNodeID,
			InstanceID:       router.InstanceID,
			ENIID:            router.ENIID,
			VPCID:            router.VPCID,
			SubnetID:         router.SubnetID,
			AvailabilityZone: router.AvailabilityZone,
			Region:           router.Region,
		})
		if router.ID == domain.PreferredOwner {
			authority.PreferredOwner = router.StableNodeID
		}
	}
	sort.Strings(authority.RemotePrefixes)
	sort.Slice(authority.Owners, func(i, j int) bool {
		return authority.Owners[i].RouterID < authority.Owners[j].RouterID
	})
	if err := authority.Validate(); err != nil {
		return model.DomainAuthority{}, fmt.Errorf("build domain authority: %w", err)
	}
	return authority, nil
}
