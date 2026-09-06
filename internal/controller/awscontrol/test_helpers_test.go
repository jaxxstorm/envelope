package awscontrol

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/jaxxstorm/envelope/internal/controller/model"
)

type fakeEC2 struct {
	describeInstancesOutput         *ec2.DescribeInstancesOutput
	describeInstancesErr            error
	describeInstanceStatusOutput    *ec2.DescribeInstanceStatusOutput
	describeInstanceStatusErr       error
	describeNetworkInterfacesOutput *ec2.DescribeNetworkInterfacesOutput
	describeNetworkInterfacesErr    error
	describeRouteTablesFunc         func(context.Context, *ec2.DescribeRouteTablesInput) (*ec2.DescribeRouteTablesOutput, error)
	replaceRouteFunc                func(context.Context, *ec2.ReplaceRouteInput) (*ec2.ReplaceRouteOutput, error)

	describeInstancesCalls         int
	describeInstanceStatusCalls    int
	describeNetworkInterfacesCalls int
	describeRouteTablesCalls       int
	replaceRouteCalls              int
	describeInstancesInput         *ec2.DescribeInstancesInput
	describeInstanceStatusInput    *ec2.DescribeInstanceStatusInput
	describeNetworkInterfacesInput *ec2.DescribeNetworkInterfacesInput
	replaceRouteInputs             []*ec2.ReplaceRouteInput
}

func (f *fakeEC2) DescribeInstances(
	_ context.Context,
	input *ec2.DescribeInstancesInput,
	_ ...func(*ec2.Options),
) (*ec2.DescribeInstancesOutput, error) {
	f.describeInstancesCalls++
	f.describeInstancesInput = input
	return f.describeInstancesOutput, f.describeInstancesErr
}

func (f *fakeEC2) DescribeInstanceStatus(
	_ context.Context,
	input *ec2.DescribeInstanceStatusInput,
	_ ...func(*ec2.Options),
) (*ec2.DescribeInstanceStatusOutput, error) {
	f.describeInstanceStatusCalls++
	f.describeInstanceStatusInput = input
	return f.describeInstanceStatusOutput, f.describeInstanceStatusErr
}

func (f *fakeEC2) DescribeNetworkInterfaces(
	_ context.Context,
	input *ec2.DescribeNetworkInterfacesInput,
	_ ...func(*ec2.Options),
) (*ec2.DescribeNetworkInterfacesOutput, error) {
	f.describeNetworkInterfacesCalls++
	f.describeNetworkInterfacesInput = input
	return f.describeNetworkInterfacesOutput, f.describeNetworkInterfacesErr
}

func (f *fakeEC2) DescribeRouteTables(
	ctx context.Context,
	input *ec2.DescribeRouteTablesInput,
	_ ...func(*ec2.Options),
) (*ec2.DescribeRouteTablesOutput, error) {
	f.describeRouteTablesCalls++
	if f.describeRouteTablesFunc == nil {
		return nil, errors.New("unexpected DescribeRouteTables call")
	}
	return f.describeRouteTablesFunc(ctx, input)
}

func (f *fakeEC2) ReplaceRoute(
	ctx context.Context,
	input *ec2.ReplaceRouteInput,
	_ ...func(*ec2.Options),
) (*ec2.ReplaceRouteOutput, error) {
	f.replaceRouteCalls++
	f.replaceRouteInputs = append(f.replaceRouteInputs, input)
	if f.replaceRouteFunc == nil {
		return nil, errors.New("unexpected ReplaceRoute call")
	}
	return f.replaceRouteFunc(ctx, input)
}

type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func newFakeClock(now time.Time) *fakeClock {
	return &fakeClock{now: now}
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) Advance(duration time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(duration)
	c.mu.Unlock()
}

type advancingSleeper struct {
	clock       *fakeClock
	calls       int
	beforeSleep func(int)
	returnError error
	durations   []time.Duration
}

func (s *advancingSleeper) Sleep(ctx context.Context, duration time.Duration) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.calls++
	s.durations = append(s.durations, duration)
	if s.beforeSleep != nil {
		s.beforeSleep(s.calls)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if s.returnError != nil {
		return s.returnError
	}
	s.clock.Advance(duration)
	return nil
}

func testAuthority() model.DomainAuthority {
	return model.DomainAuthority{
		TopologyHash:            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		DeploymentID:            "deployment-a",
		DomainID:                "domain-a",
		SiteID:                  "site-a",
		VPCID:                   "vpc-a",
		Region:                  "us-east-1",
		SourcePrefix:            "10.0.0.0/24",
		RouteTableID:            "rtb-a",
		GWLBESubnetID:           "subnet-gwlbe-a",
		RouteTableAssociationID: "rtbassoc-gwlbe-a",
		RemotePrefixes:          []string{"10.1.0.0/24", "10.1.1.0/24"},
		PreferredOwner:          "node-a",
		Owners: []model.OwnerAuthority{
			{
				RouterID:         "router-a",
				StableNodeID:     "node-a",
				InstanceID:       "i-a",
				ENIID:            "eni-a",
				VPCID:            "vpc-a",
				SubnetID:         "subnet-a",
				AvailabilityZone: "us-east-1a",
				Region:           "us-east-1",
			},
			{
				RouterID:         "router-b",
				StableNodeID:     "node-b",
				InstanceID:       "i-b",
				ENIID:            "eni-b",
				VPCID:            "vpc-a",
				SubnetID:         "subnet-b",
				AvailabilityZone: "us-east-1b",
				Region:           "us-east-1",
			},
		},
	}
}

func healthyOwnerFake(owner model.OwnerAuthority) *fakeEC2 {
	return &fakeEC2{
		describeInstancesOutput: &ec2.DescribeInstancesOutput{
			Reservations: []types.Reservation{{
				Instances: []types.Instance{{
					InstanceId:      aws.String(owner.InstanceID),
					State:           &types.InstanceState{Name: types.InstanceStateNameRunning},
					SourceDestCheck: aws.Bool(false),
					VpcId:           aws.String(owner.VPCID),
					SubnetId:        aws.String(owner.SubnetID),
					Placement:       &types.Placement{AvailabilityZone: aws.String(owner.AvailabilityZone)},
					NetworkInterfaces: []types.InstanceNetworkInterface{{
						NetworkInterfaceId: aws.String(owner.ENIID),
						SourceDestCheck:    aws.Bool(false),
						VpcId:              aws.String(owner.VPCID),
						SubnetId:           aws.String(owner.SubnetID),
						Status:             types.NetworkInterfaceStatusInUse,
						Attachment: &types.InstanceNetworkInterfaceAttachment{
							DeviceIndex: aws.Int32(0),
							Status:      types.AttachmentStatusAttached,
						},
					}},
				}},
			}},
		},
		describeInstanceStatusOutput: &ec2.DescribeInstanceStatusOutput{
			InstanceStatuses: []types.InstanceStatus{{
				InstanceId:       aws.String(owner.InstanceID),
				AvailabilityZone: aws.String(owner.AvailabilityZone),
				InstanceState:    &types.InstanceState{Name: types.InstanceStateNameRunning},
				SystemStatus:     &types.InstanceStatusSummary{Status: types.SummaryStatusOk},
				InstanceStatus:   &types.InstanceStatusSummary{Status: types.SummaryStatusOk},
			}},
		},
		describeNetworkInterfacesOutput: &ec2.DescribeNetworkInterfacesOutput{
			NetworkInterfaces: []types.NetworkInterface{{
				NetworkInterfaceId: aws.String(owner.ENIID),
				SourceDestCheck:    aws.Bool(false),
				Status:             types.NetworkInterfaceStatusInUse,
				VpcId:              aws.String(owner.VPCID),
				SubnetId:           aws.String(owner.SubnetID),
				AvailabilityZone:   aws.String(owner.AvailabilityZone),
				Attachment: &types.NetworkInterfaceAttachment{
					InstanceId:  aws.String(owner.InstanceID),
					DeviceIndex: aws.Int32(0),
					Status:      types.AttachmentStatusAttached,
				},
			}},
		},
	}
}

func routeTableOutput(authority model.DomainAuthority, targets map[string]string) *ec2.DescribeRouteTablesOutput {
	instancesByENI := make(map[string]string, len(authority.Owners))
	for _, owner := range authority.Owners {
		instancesByENI[owner.ENIID] = owner.InstanceID
	}
	routes := []types.Route{{
		DestinationCidrBlock: aws.String("10.0.0.0/16"),
		GatewayId:            aws.String("local"),
		Origin:               types.RouteOriginCreateRouteTable,
		State:                types.RouteStateActive,
	}}
	for _, destination := range authority.RemotePrefixes {
		route := types.Route{
			DestinationCidrBlock: aws.String(destination),
			NetworkInterfaceId:   aws.String(targets[destination]),
			Origin:               types.RouteOriginCreateRoute,
			State:                types.RouteStateActive,
		}
		if instanceID := instancesByENI[targets[destination]]; instanceID != "" {
			route.InstanceId = aws.String(instanceID)
		}
		routes = append(routes, route)
	}
	return &ec2.DescribeRouteTablesOutput{
		RouteTables: []types.RouteTable{{
			RouteTableId: aws.String(authority.RouteTableID),
			VpcId:        aws.String(authority.VPCID),
			Associations: []types.RouteTableAssociation{{
				Main:                    aws.Bool(false),
				RouteTableAssociationId: aws.String(authority.RouteTableAssociationID),
				RouteTableId:            aws.String(authority.RouteTableID),
				SubnetId:                aws.String(authority.GWLBESubnetID),
				AssociationState: &types.RouteTableAssociationState{
					State: types.RouteTableAssociationStateCodeAssociated,
				},
			}},
			Routes: routes,
		}},
	}
}

func newRouteController(api *fakeEC2, clock *fakeClock, sleeper Sleeper, options ...Option) *Controller {
	controllerOptions := []Option{
		WithClock(clock),
		WithSleeper(sleeper),
		WithAPITimeout(time.Second),
		WithPollInterval(time.Second),
	}
	controllerOptions = append(controllerOptions, options...)
	controller, err := New(api, "us-east-1", controllerOptions...)
	if err != nil {
		panic(err)
	}
	return controller
}
