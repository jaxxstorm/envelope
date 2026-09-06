package attestation

import (
	"bytes"
	"context"
	"os"
	"reflect"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

type cloudFixture struct {
	subnets   *ec2.DescribeSubnetsOutput
	endpoints *ec2.DescribeVpcEndpointsOutput
	tables    *ec2.DescribeRouteTablesOutput
	vpcs      *ec2.DescribeVpcsOutput
}

func (f cloudFixture) DescribeSubnets(context.Context, *ec2.DescribeSubnetsInput, ...func(*ec2.Options)) (*ec2.DescribeSubnetsOutput, error) {
	return f.subnets, nil
}
func (f cloudFixture) DescribeVpcEndpoints(context.Context, *ec2.DescribeVpcEndpointsInput, ...func(*ec2.Options)) (*ec2.DescribeVpcEndpointsOutput, error) {
	return f.endpoints, nil
}
func (f cloudFixture) DescribeRouteTables(context.Context, *ec2.DescribeRouteTablesInput, ...func(*ec2.Options)) (*ec2.DescribeRouteTablesOutput, error) {
	return f.tables, nil
}
func (f cloudFixture) DescribeVpcs(context.Context, *ec2.DescribeVpcsInput, ...func(*ec2.Options)) (*ec2.DescribeVpcsOutput, error) {
	return f.vpcs, nil
}

func collectorFixture(t *testing.T) CollectorConfig {
	t.Helper()
	file, err := os.Open("testdata/router-config.json")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	c, err := ParseCollectorConfig(file)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestDestinationPrefixAZAndWholeVPCRouteProof(t *testing.T) {
	for _, mode := range []string{"valid-cross-az", "wrong-endpoint", "wrong-endpoint-subnet", "wrong-workload-az", "wrong-workload-prefix", "wrong-association", "main-association", "second-association", "interior-bypass", "interior-blackhole", "interior-safe", "extra-target", "prefix-list", "missing-exact", "unknown-vpc", "stale-endpoint", "resolver-overlap", "pagination"} {
		t.Run(mode, func(t *testing.T) {
			c := collectorFixture(t)
			a, o, _ := c.Authority()
			destination := c.LocalDestinations[0]
			subnet := func(id, cidr, az string) types.Subnet {
				return types.Subnet{SubnetId: aws.String(id), VpcId: aws.String(o.VPCID), CidrBlock: aws.String(cidr), AvailabilityZone: aws.String(az), State: types.SubnetStateAvailable}
			}
			f := cloudFixture{
				subnets:   &ec2.DescribeSubnetsOutput{Subnets: []types.Subnet{subnet(o.SubnetID, "10.20.3.0/24", o.AvailabilityZone), subnet(a.GWLBESubnetID, "10.20.2.0/24", "us-east-1b"), subnet(destination.WorkloadSubnetID, destination.Prefix, "us-east-1b")}},
				endpoints: &ec2.DescribeVpcEndpointsOutput{VpcEndpoints: []types.VpcEndpoint{{VpcEndpointId: aws.String(destination.EndpointID), VpcId: aws.String(o.VPCID), VpcEndpointType: types.VpcEndpointTypeGatewayLoadBalancer, State: types.StateAvailable, SubnetIds: []string{a.GWLBESubnetID}}}},
				tables:    &ec2.DescribeRouteTablesOutput{RouteTables: []types.RouteTable{{RouteTableId: aws.String(c.TransportRouteTableID), VpcId: aws.String(o.VPCID), Associations: []types.RouteTableAssociation{{Main: aws.Bool(false), SubnetId: aws.String(o.SubnetID), RouteTableId: aws.String(c.TransportRouteTableID), RouteTableAssociationId: aws.String(c.TransportAssociationID), AssociationState: &types.RouteTableAssociationState{State: types.RouteTableAssociationStateCodeAssociated}}}, Routes: []types.Route{{DestinationCidrBlock: aws.String(destination.Prefix), GatewayId: aws.String(destination.EndpointID), State: types.RouteStateActive, Origin: types.RouteOriginCreateRoute}}}}},
				vpcs:      &ec2.DescribeVpcsOutput{Vpcs: []types.Vpc{{VpcId: aws.String(o.VPCID), CidrBlock: aws.String("10.200.0.0/16"), State: types.VpcStateAvailable}}},
			}
			switch mode {
			case "wrong-endpoint":
				f.endpoints.VpcEndpoints[0].VpcEndpointId = aws.String("vpce-00000000")
			case "wrong-endpoint-subnet":
				f.endpoints.VpcEndpoints[0].SubnetIds = []string{o.SubnetID}
			case "wrong-workload-az":
				f.subnets.Subnets[2].AvailabilityZone = aws.String(o.AvailabilityZone)
			case "wrong-workload-prefix":
				f.subnets.Subnets[2].CidrBlock = aws.String("10.20.1.0/24")
			case "wrong-association":
				f.tables.RouteTables[0].Associations[0].RouteTableAssociationId = aws.String("rtbassoc-00000000")
			case "main-association":
				f.tables.RouteTables[0].Associations[0].Main = aws.Bool(true)
			case "second-association":
				f.tables.RouteTables[0].Associations = append(f.tables.RouteTables[0].Associations, f.tables.RouteTables[0].Associations[0])
			case "interior-bypass", "interior-blackhole", "interior-safe":
				route := f.tables.RouteTables[0].Routes[0]
				route.DestinationCidrBlock = aws.String("10.20.0.64/28")
				if mode == "interior-bypass" {
					route.GatewayId = aws.String("vpce-00000000")
				}
				if mode == "interior-blackhole" {
					route.State = types.RouteStateBlackhole
				}
				f.tables.RouteTables[0].Routes = append(f.tables.RouteTables[0].Routes, route)
			case "extra-target":
				f.tables.RouteTables[0].Routes[0].NetworkInterfaceId = aws.String(o.ENIID)
			case "prefix-list":
				f.tables.RouteTables[0].Routes = append(f.tables.RouteTables[0].Routes, types.Route{DestinationPrefixListId: aws.String("pl-00000000")})
			case "missing-exact":
				f.tables.RouteTables[0].Routes = nil
			case "unknown-vpc":
				f.subnets.Subnets[0].VpcId = aws.String("vpc-00000000")
			case "stale-endpoint":
				f.endpoints.VpcEndpoints[0].State = types.StatePending
			case "resolver-overlap":
				f.vpcs.Vpcs[0].CidrBlock = aws.String("10.20.0.0/16")
			case "pagination":
				f.tables.NextToken = aws.String("more")
			}
			gateway, resolver, err := validateUnderlay(context.Background(), f, c, o)
			if (err == nil) != (mode == "valid-cross-az" || mode == "interior-safe") {
				t.Fatalf("cloud proof=%v", err)
			}
			if err == nil && (gateway.String() != "10.20.3.1" || resolver.String() != "10.200.0.2") {
				t.Fatal("incorrect underlay/resolver derivation")
			}
		})
	}
}

func TestCollectorIdentityCanonicalAndAuthorityComplete(t *testing.T) {
	c := collectorFixture(t)
	canonical, err := c.CanonicalJSON()
	if err != nil {
		t.Fatal(err)
	}
	fixture, err := os.ReadFile("../../../deploy/terraform/router-attestor/tests/fixtures/configuration.json")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(canonical, bytes.TrimSpace(fixture)) {
		t.Fatal("Terraform fixture is not the Go canonical collector identity")
	}
	hash, err := c.Hash()
	if err != nil || hash != "f6262ec7791d73f2e0c079625729cd56c1b543a237582845d5c1e600ec87b0cf" {
		t.Fatalf("canonical identity %s %v", hash, err)
	}
	for _, mutate := range []func(*CollectorConfig){func(c *CollectorConfig) { c.LocalDestinations = nil }, func(c *CollectorConfig) { c.MaximumTCPMSS = 0 }, func(c *CollectorConfig) { c.TransportAssociationID = "" }, func(c *CollectorConfig) { c.LocalDestinations[0].Prefix = "10.21.0.0/24" }} {
		copy := collectorFixture(t)
		mutate(&copy)
		if _, _, err := copy.Authority(); err == nil {
			t.Fatal("incomplete forwarding authority accepted")
		}
	}
	copy := collectorFixture(t)
	copy.MaximumTCPMSS = 1200
	changed, _ := copy.Hash()
	if reflect.DeepEqual(hash, changed) {
		t.Fatal("MSS authority did not change attestation binding")
	}
}
