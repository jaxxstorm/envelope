package attestation

import (
	"context"
	"net/netip"
	"reflect"
	"sort"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/jaxxstorm/envelope/internal/controller/model"
)

type cloudReader interface {
	DescribeRouteTables(context.Context, *ec2.DescribeRouteTablesInput, ...func(*ec2.Options)) (*ec2.DescribeRouteTablesOutput, error)
	DescribeSubnets(context.Context, *ec2.DescribeSubnetsInput, ...func(*ec2.Options)) (*ec2.DescribeSubnetsOutput, error)
	DescribeVpcEndpoints(context.Context, *ec2.DescribeVpcEndpointsInput, ...func(*ec2.Options)) (*ec2.DescribeVpcEndpointsOutput, error)
	DescribeVpcs(context.Context, *ec2.DescribeVpcsInput, ...func(*ec2.Options)) (*ec2.DescribeVpcsOutput, error)
}

// validateUnderlay binds the full effective route set to destination workload
// AZs, not the receiving router's AZ. No resource discovered here is adopted as
// mutation authority; every subnet, association and endpoint is explicit input.
func validateUnderlay(ctx context.Context, client cloudReader, c CollectorConfig, owner model.OwnerAuthority) (netip.Addr, netip.Addr, error) {
	var none netip.Addr
	subnetIDs := map[string]bool{owner.SubnetID: true}
	endpoints := []string{}
	domains := map[string]model.DomainAuthority{}
	for _, domain := range c.Topology.Domains {
		a, err := c.Topology.DomainAuthority(domain.ID)
		if err != nil {
			return none, none, ErrRejected
		}
		if a.VPCID == owner.VPCID && a.Region == owner.Region {
			domains[a.SourcePrefix] = a
			subnetIDs[a.GWLBESubnetID] = true
		}
	}
	for _, destination := range c.LocalDestinations {
		subnetIDs[destination.WorkloadSubnetID] = true
		endpoints = append(endpoints, destination.EndpointID)
	}
	ids := make([]string, 0, len(subnetIDs))
	for id := range subnetIDs {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	sort.Strings(endpoints)
	subnets, err := client.DescribeSubnets(ctx, &ec2.DescribeSubnetsInput{SubnetIds: ids})
	if err != nil || subnets == nil || subnets.NextToken != nil || len(subnets.Subnets) != len(ids) {
		return none, none, ErrRejected
	}
	byID := map[string]types.Subnet{}
	for _, subnet := range subnets.Subnets {
		id := aws.ToString(subnet.SubnetId)
		if !subnetIDs[id] || byID[id].SubnetId != nil || aws.ToString(subnet.VpcId) != owner.VPCID || subnet.State != types.SubnetStateAvailable {
			return none, none, ErrRejected
		}
		byID[id] = subnet
	}
	transport := byID[owner.SubnetID]
	transportPrefix, err := netip.ParsePrefix(aws.ToString(transport.CidrBlock))
	if err != nil || !transportPrefix.Addr().Is4() || transportPrefix != transportPrefix.Masked() || transportPrefix.Bits() > 28 || aws.ToString(transport.AvailabilityZone) != owner.AvailabilityZone {
		return none, none, ErrRejected
	}
	gateway := transportPrefix.Addr().Next()
	observed, err := client.DescribeVpcEndpoints(ctx, &ec2.DescribeVpcEndpointsInput{VpcEndpointIds: endpoints})
	if err != nil || observed == nil || observed.NextToken != nil || len(observed.VpcEndpoints) != len(endpoints) {
		return none, none, ErrRejected
	}
	endpointMap := map[string]types.VpcEndpoint{}
	for _, endpoint := range observed.VpcEndpoints {
		id := aws.ToString(endpoint.VpcEndpointId)
		if endpointMap[id].VpcEndpointId != nil || endpoint.VpcEndpointType != types.VpcEndpointTypeGatewayLoadBalancer || endpoint.State != types.StateAvailable || aws.ToString(endpoint.VpcId) != owner.VPCID {
			return none, none, ErrRejected
		}
		endpointMap[id] = endpoint
	}
	for _, destination := range c.LocalDestinations {
		a, found := domains[destination.Prefix]
		if !found {
			return none, none, ErrRejected
		}
		workload, gwlbe := byID[destination.WorkloadSubnetID], byID[a.GWLBESubnetID]
		prefix, err := netip.ParsePrefix(destination.Prefix)
		if err != nil || prefix.Overlaps(transportPrefix) || aws.ToString(workload.CidrBlock) != destination.Prefix || aws.ToString(workload.AvailabilityZone) == "" || aws.ToString(workload.AvailabilityZone) != aws.ToString(gwlbe.AvailabilityZone) {
			return none, none, ErrRejected
		}
		endpoint := endpointMap[destination.EndpointID]
		if len(endpoint.SubnetIds) != 1 || endpoint.SubnetIds[0] != a.GWLBESubnetID {
			return none, none, ErrRejected
		}
	}
	tables, err := client.DescribeRouteTables(ctx, &ec2.DescribeRouteTablesInput{RouteTableIds: []string{c.TransportRouteTableID}})
	if err != nil || tables == nil || tables.NextToken != nil || len(tables.RouteTables) != 1 {
		return none, none, ErrRejected
	}
	table := tables.RouteTables[0]
	if aws.ToString(table.RouteTableId) != c.TransportRouteTableID || aws.ToString(table.VpcId) != owner.VPCID || len(table.Associations) != 1 {
		return none, none, ErrRejected
	}
	association := table.Associations[0]
	if association.Main == nil || *association.Main || aws.ToString(association.SubnetId) != owner.SubnetID || aws.ToString(association.RouteTableId) != c.TransportRouteTableID || aws.ToString(association.RouteTableAssociationId) != c.TransportAssociationID || aws.ToString(association.GatewayId) != "" || association.AssociationState == nil || association.AssociationState.State != types.RouteTableAssociationStateCodeAssociated {
		return none, none, ErrRejected
	}
	if err := validateVPCRoutes(table.Routes, c.LocalDestinations); err != nil {
		return none, none, err
	}
	vpcs, err := client.DescribeVpcs(ctx, &ec2.DescribeVpcsInput{VpcIds: []string{owner.VPCID}})
	if err != nil || vpcs == nil || vpcs.NextToken != nil || len(vpcs.Vpcs) != 1 || aws.ToString(vpcs.Vpcs[0].VpcId) != owner.VPCID {
		return none, none, ErrRejected
	}
	vpc, err := netip.ParsePrefix(aws.ToString(vpcs.Vpcs[0].CidrBlock))
	if err != nil || !vpc.Addr().Is4() || vpc != vpc.Masked() {
		return none, none, ErrRejected
	}
	resolver := vpc.Addr().Next().Next()
	for _, destination := range c.LocalDestinations {
		if netip.MustParsePrefix(destination.Prefix).Contains(resolver) {
			return none, none, ErrRejected
		}
	}
	return gateway, resolver, nil
}

func validateVPCRoutes(routes []types.Route, destinations []LocalDestination) error {
	for _, route := range routes {
		if aws.ToString(route.DestinationPrefixListId) != "" {
			return ErrRejected
		}
	}
	for _, destination := range destinations {
		prefix, err := netip.ParsePrefix(destination.Prefix)
		if err != nil {
			return ErrRejected
		}
		exact := 0
		for _, route := range routes {
			if route.DestinationCidrBlock == nil {
				continue
			}
			network, err := netip.ParsePrefix(*route.DestinationCidrBlock)
			if err != nil || network != network.Masked() {
				return ErrRejected
			}
			if !network.Overlaps(prefix) || network.Bits() < prefix.Bits() {
				continue
			}
			if network == prefix {
				exact++
			}
			if route.State != types.RouteStateActive || route.Origin != types.RouteOriginCreateRoute || aws.ToString(route.GatewayId) != destination.EndpointID {
				return ErrRejected
			}
			// Reject every alternate target, including target kinds added by the
			// pinned SDK. InstanceId/ENI metadata must not coexist with a GWLBE.
			value := reflect.ValueOf(route)
			shape := value.Type()
			for i := 0; i < value.NumField(); i++ {
				name := shape.Field(i).Name
				if !shape.Field(i).IsExported() || name == "DestinationCidrBlock" || name == "GatewayId" || name == "State" || name == "Origin" {
					continue
				}
				if !value.Field(i).IsZero() {
					return ErrRejected
				}
			}
		}
		if exact != 1 {
			return ErrRejected
		}
	}
	return nil
}
