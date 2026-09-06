package awscontrol

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

func TestSnapshotValidatesExactRouteDomain(t *testing.T) {
	authority := testAuthority()
	targets := map[string]string{
		authority.RemotePrefixes[0]: "eni-a",
		authority.RemotePrefixes[1]: "eni-b",
	}
	now := time.Date(2026, time.September, 4, 13, 0, 0, 0, time.UTC)
	clock := newFakeClock(now)
	api := &fakeEC2{
		describeRouteTablesFunc: func(_ context.Context, input *ec2.DescribeRouteTablesInput) (*ec2.DescribeRouteTablesOutput, error) {
			if len(input.RouteTableIds) != 1 || input.RouteTableIds[0] != authority.RouteTableID || len(input.Filters) != 0 {
				t.Fatalf("DescribeRouteTables was not exact: %+v", input)
			}
			output := routeTableOutput(authority, targets)
			output.RouteTables[0].Associations = append(output.RouteTables[0].Associations, types.RouteTableAssociation{
				Main:                    aws.Bool(false),
				RouteTableAssociationId: aws.String("rtbassoc-stale"),
				RouteTableId:            aws.String(authority.RouteTableID),
				SubnetId:                aws.String("subnet-stale"),
				AssociationState: &types.RouteTableAssociationState{
					State: types.RouteTableAssociationStateCodeDisassociated,
				},
			})
			return output, nil
		},
	}
	controller, err := New(api, authority.Region, WithClock(clock))
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	snapshot, err := controller.Snapshot(context.Background(), authority)
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	if snapshot.RouteTableID != authority.RouteTableID || snapshot.CapturedAt != now {
		t.Fatalf("unexpected snapshot metadata: %+v", snapshot)
	}
	if len(snapshot.Routes) != len(authority.RemotePrefixes) {
		t.Fatalf("snapshot has %d routes, want %d", len(snapshot.Routes), len(authority.RemotePrefixes))
	}
	for index, route := range snapshot.Routes {
		if route.DestinationPrefix != authority.RemotePrefixes[index] || route.TargetENIID != targets[route.DestinationPrefix] {
			t.Fatalf("unexpected route %d: %+v", index, route)
		}
		if route.State != "active" || route.Origin != "CreateRoute" {
			t.Fatalf("route %d was not fully validated: %+v", index, route)
		}
	}
}

func TestSnapshotAllowsLessSpecificIPv4Routes(t *testing.T) {
	authority := testAuthority()
	output := routeTableOutput(authority, map[string]string{
		authority.RemotePrefixes[0]: "eni-a",
		authority.RemotePrefixes[1]: "eni-a",
	})
	output.RouteTables[0].Routes = append(output.RouteTables[0].Routes,
		types.Route{
			DestinationCidrBlock: aws.String("0.0.0.0/0"),
			GatewayId:            aws.String("igw-a"),
			Origin:               types.RouteOriginCreateRoute,
			State:                types.RouteStateActive,
		},
		types.Route{
			DestinationCidrBlock: aws.String("10.1.0.0/16"),
			TransitGatewayId:     aws.String("tgw-a"),
			Origin:               types.RouteOriginCreateRoute,
			State:                types.RouteStateActive,
		},
		types.Route{
			DestinationCidrBlock: aws.String("192.0.2.1/32"),
			NatGatewayId:         aws.String("nat-a"),
			Origin:               types.RouteOriginCreateRoute,
			State:                types.RouteStateActive,
		},
	)
	api := &fakeEC2{describeRouteTablesFunc: func(context.Context, *ec2.DescribeRouteTablesInput) (*ec2.DescribeRouteTablesOutput, error) {
		return output, nil
	}}
	controller, err := New(api, authority.Region)
	if err != nil {
		t.Fatal(err)
	}

	snapshot, err := controller.Snapshot(context.Background(), authority)
	if err != nil {
		t.Fatalf("Snapshot() error = %v", err)
	}
	if len(snapshot.Routes) != len(authority.RemotePrefixes) {
		t.Fatalf("Snapshot() routes = %+v", snapshot.Routes)
	}
}

func TestReplaceRejectsAssociationDriftBeforeMutation(t *testing.T) {
	authority := testAuthority()
	tests := []struct {
		name   string
		mutate func(*types.RouteTableAssociation)
	}{
		{
			name: "subnet",
			mutate: func(association *types.RouteTableAssociation) {
				association.SubnetId = aws.String("subnet-other")
			},
		},
		{
			name: "association ID",
			mutate: func(association *types.RouteTableAssociation) {
				association.RouteTableAssociationId = aws.String("rtbassoc-other")
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			clock := newFakeClock(time.Date(2026, time.September, 4, 13, 15, 0, 0, time.UTC))
			api := &fakeEC2{
				describeRouteTablesFunc: func(context.Context, *ec2.DescribeRouteTablesInput) (*ec2.DescribeRouteTablesOutput, error) {
					output := routeTableOutput(authority, map[string]string{
						authority.RemotePrefixes[0]: "eni-a",
						authority.RemotePrefixes[1]: "eni-a",
					})
					test.mutate(&output.RouteTables[0].Associations[0])
					return output, nil
				},
				replaceRouteFunc: func(context.Context, *ec2.ReplaceRouteInput) (*ec2.ReplaceRouteOutput, error) {
					t.Fatal("ReplaceRoute called after association drift")
					return nil, nil
				},
			}
			controller := newRouteController(api, clock, &advancingSleeper{clock: clock})

			_, err := controller.ReplaceAndWait(
				context.Background(),
				authority,
				authority.RemotePrefixes[0],
				"eni-a",
				"eni-b",
				clock.Now().Add(10*time.Second),
			)
			if !errors.Is(err, ErrOwnerIneligible) {
				t.Fatalf("ReplaceAndWait error = %v, want ineligible association", err)
			}
			if api.describeRouteTablesCalls != 1 || api.replaceRouteCalls != 0 {
				t.Fatalf("association drift calls = %d describes/%d replaces, want 1/0", api.describeRouteTablesCalls, api.replaceRouteCalls)
			}
		})
	}
}

func TestStableSnapshotUsesConfiguredTimeSpacedReads(t *testing.T) {
	authority := testAuthority()
	clock := newFakeClock(time.Date(2026, time.September, 4, 13, 30, 0, 0, time.UTC))
	sleeper := &advancingSleeper{clock: clock}
	targets := map[string]string{
		authority.RemotePrefixes[0]: "eni-a",
		authority.RemotePrefixes[1]: "eni-a",
	}
	api := &fakeEC2{
		describeRouteTablesFunc: func(context.Context, *ec2.DescribeRouteTablesInput) (*ec2.DescribeRouteTablesOutput, error) {
			return routeTableOutput(authority, targets), nil
		},
	}
	controller := newRouteController(api, clock, sleeper, WithStableReads(3))
	started := clock.Now()

	snapshot, err := controller.StableSnapshot(context.Background(), authority, started.Add(10*time.Second))
	if err != nil {
		t.Fatalf("StableSnapshot: %v", err)
	}
	if api.describeRouteTablesCalls != 3 || sleeper.calls != 2 {
		t.Fatalf("stable readback calls = %d describes/%d sleeps, want 3/2", api.describeRouteTablesCalls, sleeper.calls)
	}
	for index, duration := range sleeper.durations {
		if duration != time.Second {
			t.Fatalf("sleep %d = %s, want configured one second", index, duration)
		}
	}
	if !snapshot.CapturedAt.Equal(started.Add(2 * time.Second)) {
		t.Fatalf("stable snapshot captured at %s, want %s", snapshot.CapturedAt, started.Add(2*time.Second))
	}
}

func TestStableSnapshotClampsPollToLeaveMinimumDeadlineReadBudget(t *testing.T) {
	authority := testAuthority()
	clock := newFakeClock(time.Date(2026, time.September, 4, 13, 40, 0, 0, time.UTC))
	sleeper := &advancingSleeper{clock: clock}
	api := &fakeEC2{describeRouteTablesFunc: func(context.Context, *ec2.DescribeRouteTablesInput) (*ec2.DescribeRouteTablesOutput, error) {
		return routeTableOutput(authority, map[string]string{
			authority.RemotePrefixes[0]: "eni-a",
			authority.RemotePrefixes[1]: "eni-a",
		}), nil
	}}
	controller, err := New(
		api,
		authority.Region,
		WithClock(clock),
		WithSleeper(sleeper),
		WithAPITimeout(100*time.Millisecond),
	)
	if err != nil {
		t.Fatal(err)
	}
	deadline := clock.Now().Add(200 * time.Millisecond)
	snapshot, err := controller.StableSnapshot(context.Background(), authority, deadline)
	if err != nil {
		t.Fatalf("StableSnapshot() error = %v", err)
	}
	if api.describeRouteTablesCalls != 2 || sleeper.calls != 1 || sleeper.durations[0] != 100*time.Millisecond {
		t.Fatalf("minimum-deadline readback = %d describes, waits %v", api.describeRouteTablesCalls, sleeper.durations)
	}
	if !snapshot.CapturedAt.Equal(deadline.Add(-100 * time.Millisecond)) {
		t.Fatalf("stable snapshot captured at %s, want %s", snapshot.CapturedAt, deadline.Add(-100*time.Millisecond))
	}
}

func TestStableSnapshotClampsPollJustAboveIntervalToReserveReadBudget(t *testing.T) {
	authority := testAuthority()
	clock := newFakeClock(time.Date(2026, time.September, 4, 13, 42, 0, 0, time.UTC))
	sleeper := &advancingSleeper{clock: clock}
	api := &fakeEC2{describeRouteTablesFunc: func(context.Context, *ec2.DescribeRouteTablesInput) (*ec2.DescribeRouteTablesOutput, error) {
		return routeTableOutput(authority, map[string]string{
			authority.RemotePrefixes[0]: "eni-a",
			authority.RemotePrefixes[1]: "eni-a",
		}), nil
	}}
	controller, err := New(
		api,
		authority.Region,
		WithClock(clock),
		WithSleeper(sleeper),
		WithAPITimeout(100*time.Millisecond),
		WithPollInterval(time.Second),
	)
	if err != nil {
		t.Fatal(err)
	}
	started := clock.Now()
	deadline := started.Add(time.Second + 50*time.Millisecond)

	snapshot, err := controller.StableSnapshot(context.Background(), authority, deadline)
	if err != nil {
		t.Fatalf("StableSnapshot() error = %v", err)
	}
	if api.describeRouteTablesCalls != 2 || sleeper.calls != 1 || sleeper.durations[0] != 950*time.Millisecond {
		t.Fatalf("just-over-interval readback = %d describes, waits %v", api.describeRouteTablesCalls, sleeper.durations)
	}
	if !snapshot.CapturedAt.Equal(deadline.Add(-100 * time.Millisecond)) {
		t.Fatalf("stable snapshot captured at %s, want %s", snapshot.CapturedAt, deadline.Add(-100*time.Millisecond))
	}
}

func TestStableSnapshotRejectsSuccessfulReadPastDeadline(t *testing.T) {
	authority := testAuthority()
	clock := newFakeClock(time.Date(2026, time.September, 4, 13, 43, 0, 0, time.UTC))
	sleeper := &advancingSleeper{clock: clock}
	api := &fakeEC2{}
	api.describeRouteTablesFunc = func(context.Context, *ec2.DescribeRouteTablesInput) (*ec2.DescribeRouteTablesOutput, error) {
		if api.describeRouteTablesCalls == 2 {
			clock.Advance(3 * time.Second)
		}
		return routeTableOutput(authority, map[string]string{
			authority.RemotePrefixes[0]: "eni-a",
			authority.RemotePrefixes[1]: "eni-a",
		}), nil
	}
	controller := newRouteController(api, clock, sleeper)
	deadline := clock.Now().Add(3 * time.Second)

	_, err := controller.StableSnapshot(context.Background(), authority, deadline)
	if !errors.Is(err, ErrUnstableReadback) {
		t.Fatalf("StableSnapshot() error = %v, want deadline-bounded unstable readback", err)
	}
	if api.describeRouteTablesCalls != 2 || clock.Now().Before(deadline) {
		t.Fatalf("successful post-deadline read was not rejected: describes=%d now=%s deadline=%s", api.describeRouteTablesCalls, clock.Now(), deadline)
	}
}

func TestStableSnapshotResetsConsecutiveReadsAfterChange(t *testing.T) {
	authority := testAuthority()
	clock := newFakeClock(time.Date(2026, time.September, 4, 13, 45, 0, 0, time.UTC))
	sleeper := &advancingSleeper{clock: clock}
	sequence := []string{"eni-a", "eni-b", "eni-b"}
	api := &fakeEC2{}
	api.describeRouteTablesFunc = func(context.Context, *ec2.DescribeRouteTablesInput) (*ec2.DescribeRouteTablesOutput, error) {
		target := sequence[min(api.describeRouteTablesCalls-1, len(sequence)-1)]
		return routeTableOutput(authority, map[string]string{
			authority.RemotePrefixes[0]: target,
			authority.RemotePrefixes[1]: target,
		}), nil
	}
	controller := newRouteController(api, clock, sleeper)

	snapshot, err := controller.StableSnapshot(context.Background(), authority, clock.Now().Add(10*time.Second))
	if err != nil {
		t.Fatalf("StableSnapshot: %v", err)
	}
	if api.describeRouteTablesCalls != 3 || sleeper.calls != 2 {
		t.Fatalf("changed readback calls = %d describes/%d sleeps, want 3/2", api.describeRouteTablesCalls, sleeper.calls)
	}
	for _, route := range snapshot.Routes {
		if route.TargetENIID != "eni-b" {
			t.Fatalf("stable snapshot retained pre-change target: %+v", snapshot)
		}
	}
}

func TestStableSnapshotIsBoundedByDeadline(t *testing.T) {
	authority := testAuthority()
	clock := newFakeClock(time.Date(2026, time.September, 4, 13, 50, 0, 0, time.UTC))
	sleeper := &advancingSleeper{clock: clock}
	api := &fakeEC2{}
	api.describeRouteTablesFunc = func(context.Context, *ec2.DescribeRouteTablesInput) (*ec2.DescribeRouteTablesOutput, error) {
		target := "eni-a"
		if api.describeRouteTablesCalls%2 == 0 {
			target = "eni-b"
		}
		return routeTableOutput(authority, map[string]string{
			authority.RemotePrefixes[0]: target,
			authority.RemotePrefixes[1]: target,
		}), nil
	}
	controller := newRouteController(api, clock, sleeper, WithOscillationLimit(10))
	deadline := clock.Now().Add(2500 * time.Millisecond)

	_, err := controller.StableSnapshot(context.Background(), authority, deadline)
	if !errors.Is(err, ErrUnstableReadback) {
		t.Fatalf("StableSnapshot error = %v, want unstable readback", err)
	}
	if api.describeRouteTablesCalls != 3 || sleeper.calls != 3 || !clock.Now().Equal(deadline) {
		t.Fatalf("bounded readback = %d describes/%d sleeps at %s, want 3/3 at %s", api.describeRouteTablesCalls, sleeper.calls, clock.Now(), deadline)
	}
	if api.replaceRouteCalls != 0 {
		t.Fatal("stable readback called ReplaceRoute")
	}
}

func TestSnapshotRejectsInvalidRouteDomain(t *testing.T) {
	authority := testAuthority()
	tests := []struct {
		name         string
		mutate       func(*ec2.DescribeRouteTablesOutput)
		unauthorized bool
	}{
		{
			name: "wrong VPC",
			mutate: func(output *ec2.DescribeRouteTablesOutput) {
				output.RouteTables[0].VpcId = aws.String("vpc-other")
			},
		},
		{
			name: "main association",
			mutate: func(output *ec2.DescribeRouteTablesOutput) {
				output.RouteTables[0].Associations[0].Main = aws.Bool(true)
			},
		},
		{
			name: "wrong GWLBE subnet association",
			mutate: func(output *ec2.DescribeRouteTablesOutput) {
				output.RouteTables[0].Associations[0].SubnetId = aws.String("subnet-other")
			},
		},
		{
			name: "wrong route table association ID",
			mutate: func(output *ec2.DescribeRouteTablesOutput) {
				output.RouteTables[0].Associations[0].RouteTableAssociationId = aws.String("rtbassoc-other")
			},
		},
		{
			name: "association reflects wrong route table",
			mutate: func(output *ec2.DescribeRouteTablesOutput) {
				output.RouteTables[0].Associations[0].RouteTableId = aws.String("rtb-other")
			},
		},
		{
			name: "gateway association shape",
			mutate: func(output *ec2.DescribeRouteTablesOutput) {
				output.RouteTables[0].Associations[0].GatewayId = aws.String("igw-other")
			},
		},
		{
			name: "two active associations",
			mutate: func(output *ec2.DescribeRouteTablesOutput) {
				output.RouteTables[0].Associations = append(output.RouteTables[0].Associations, output.RouteTables[0].Associations[0])
			},
		},
		{
			name: "inactive association",
			mutate: func(output *ec2.DescribeRouteTablesOutput) {
				output.RouteTables[0].Associations[0].AssociationState.State = types.RouteTableAssociationStateCodeDisassociated
			},
		},
		{
			name: "missing route",
			mutate: func(output *ec2.DescribeRouteTablesOutput) {
				output.RouteTables[0].Routes = output.RouteTables[0].Routes[:2]
			},
		},
		{
			name: "duplicate route",
			mutate: func(output *ec2.DescribeRouteTablesOutput) {
				output.RouteTables[0].Routes = append(output.RouteTables[0].Routes, output.RouteTables[0].Routes[1])
			},
		},
		{
			name: "blackhole route",
			mutate: func(output *ec2.DescribeRouteTablesOutput) {
				output.RouteTables[0].Routes[1].State = types.RouteStateBlackhole
			},
		},
		{
			name: "non CreateRoute origin",
			mutate: func(output *ec2.DescribeRouteTablesOutput) {
				output.RouteTables[0].Routes[1].Origin = types.RouteOriginCreateRouteTable
			},
		},
		{
			name: "noncanonical destination",
			mutate: func(output *ec2.DescribeRouteTablesOutput) {
				output.RouteTables[0].Routes[1].DestinationCidrBlock = aws.String("10.1.0.1/24")
			},
		},
		{
			name: "intersecting narrower destination",
			mutate: func(output *ec2.DescribeRouteTablesOutput) {
				output.RouteTables[0].Routes = append(output.RouteTables[0].Routes, types.Route{
					DestinationCidrBlock: aws.String("10.1.0.0/25"),
					NetworkInterfaceId:   aws.String("eni-a"),
					InstanceId:           aws.String("i-a"),
					Origin:               types.RouteOriginCreateRoute,
					State:                types.RouteStateActive,
				})
			},
		},
		{
			name: "noncanonical broader destination",
			mutate: func(output *ec2.DescribeRouteTablesOutput) {
				output.RouteTables[0].Routes = append(output.RouteTables[0].Routes, types.Route{
					DestinationCidrBlock: aws.String("10.1.0.1/16"),
					GatewayId:            aws.String("igw-a"),
					Origin:               types.RouteOriginCreateRoute,
					State:                types.RouteStateActive,
				})
			},
		},
		{
			name: "destination prefix list",
			mutate: func(output *ec2.DescribeRouteTablesOutput) {
				output.RouteTables[0].Routes = append(output.RouteTables[0].Routes, types.Route{
					DestinationPrefixListId: aws.String("pl-unexpanded"),
					GatewayId:               aws.String("vpce-a"),
					Origin:                  types.RouteOriginCreateRoute,
					State:                   types.RouteStateActive,
				})
			},
		},
		{
			name: "reflected instance mismatch",
			mutate: func(output *ec2.DescribeRouteTablesOutput) {
				output.RouteTables[0].Routes[1].InstanceId = aws.String("i-other")
			},
			unauthorized: true,
		},
		{
			name: "non ENI target",
			mutate: func(output *ec2.DescribeRouteTablesOutput) {
				output.RouteTables[0].Routes[1].NetworkInterfaceId = nil
				output.RouteTables[0].Routes[1].NatGatewayId = aws.String("nat-a")
			},
			unauthorized: true,
		},
		{
			name: "multiple targets",
			mutate: func(output *ec2.DescribeRouteTablesOutput) {
				output.RouteTables[0].Routes[1].NatGatewayId = aws.String("nat-a")
			},
			unauthorized: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			output := routeTableOutput(authority, map[string]string{
				authority.RemotePrefixes[0]: "eni-a",
				authority.RemotePrefixes[1]: "eni-a",
			})
			test.mutate(output)
			api := &fakeEC2{
				describeRouteTablesFunc: func(context.Context, *ec2.DescribeRouteTablesInput) (*ec2.DescribeRouteTablesOutput, error) {
					return output, nil
				},
			}
			controller, err := New(api, authority.Region)
			if err != nil {
				t.Fatalf("New: %v", err)
			}

			_, err = controller.Snapshot(context.Background(), authority)
			if test.unauthorized {
				if !errors.Is(err, ErrUnauthorized) {
					t.Fatalf("Snapshot error = %v, want unauthorized", err)
				}
				return
			}
			if !errors.Is(err, ErrOwnerIneligible) {
				t.Fatalf("Snapshot error = %v, want ineligible", err)
			}
		})
	}
}

func TestReplaceRejectsUnauthorizedCurrentTarget(t *testing.T) {
	authority := testAuthority()
	clock := newFakeClock(time.Date(2026, time.September, 4, 14, 0, 0, 0, time.UTC))
	api := &fakeEC2{
		describeRouteTablesFunc: func(context.Context, *ec2.DescribeRouteTablesInput) (*ec2.DescribeRouteTablesOutput, error) {
			return routeTableOutput(authority, map[string]string{
				authority.RemotePrefixes[0]: "eni-outside-authority",
				authority.RemotePrefixes[1]: "eni-a",
			}), nil
		},
	}
	sleeper := &advancingSleeper{clock: clock}
	controller := newRouteController(api, clock, sleeper)

	_, err := controller.ReplaceAndWait(
		context.Background(),
		authority,
		authority.RemotePrefixes[0],
		"eni-a",
		"eni-b",
		clock.Now().Add(10*time.Second),
	)
	if !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("ReplaceAndWait error = %v, want unauthorized", err)
	}
	var unauthorized *UnauthorizedError
	if !errors.As(err, &unauthorized) || unauthorized.TargetENIID != "eni-outside-authority" || len(unauthorized.Observations) == 0 {
		t.Fatalf("unexpected unauthorized error: %#v", err)
	}
	if api.replaceRouteCalls != 0 {
		t.Fatalf("ReplaceRoute called with unauthorized current state")
	}
}

func TestReplaceRejectsMutationOutsideExactAuthority(t *testing.T) {
	authority := testAuthority()
	clock := newFakeClock(time.Date(2026, time.September, 4, 14, 30, 0, 0, time.UTC))
	api := &fakeEC2{}
	controller := newRouteController(api, clock, &advancingSleeper{clock: clock})

	_, err := controller.ReplaceAndWait(context.Background(), authority, "10.1.0.1/24", "eni-a", "eni-b", clock.Now().Add(time.Minute))
	if !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("noncanonical destination error = %v, want invalid input", err)
	}
	_, err = controller.ReplaceAndWait(context.Background(), authority, authority.RemotePrefixes[0], "eni-a", "eni-unknown", clock.Now().Add(time.Minute))
	if !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("unknown desired ENI error = %v, want unauthorized", err)
	}
	if api.describeRouteTablesCalls != 0 || api.replaceRouteCalls != 0 {
		t.Fatalf("AWS called for out-of-authority mutation: describe=%d replace=%d", api.describeRouteTablesCalls, api.replaceRouteCalls)
	}
}

func TestReplaceAndWaitMutatesOnlyOneExactPrefix(t *testing.T) {
	authority := testAuthority()
	clock := newFakeClock(time.Date(2026, time.September, 4, 15, 0, 0, 0, time.UTC))
	sleeper := &advancingSleeper{clock: clock}
	targets := map[string]string{
		authority.RemotePrefixes[0]: "eni-a",
		authority.RemotePrefixes[1]: "eni-a",
	}
	api := &fakeEC2{}
	api.describeRouteTablesFunc = func(_ context.Context, input *ec2.DescribeRouteTablesInput) (*ec2.DescribeRouteTablesOutput, error) {
		if len(input.RouteTableIds) != 1 || input.RouteTableIds[0] != authority.RouteTableID {
			t.Fatalf("unexpected DescribeRouteTables input: %+v", input)
		}
		return routeTableOutput(authority, targets), nil
	}
	api.replaceRouteFunc = func(_ context.Context, input *ec2.ReplaceRouteInput) (*ec2.ReplaceRouteOutput, error) {
		targets[aws.ToString(input.DestinationCidrBlock)] = aws.ToString(input.NetworkInterfaceId)
		return &ec2.ReplaceRouteOutput{}, nil
	}
	controller := newRouteController(api, clock, sleeper)

	result, err := controller.ReplaceAndWait(
		context.Background(),
		authority,
		authority.RemotePrefixes[0],
		"eni-a",
		"eni-b",
		clock.Now().Add(10*time.Second),
	)
	if err != nil {
		t.Fatalf("ReplaceAndWait: %v", err)
	}
	if result.Settlement != SettlementDesired || result.ObservedENIID != "eni-b" || !result.CallAttempted || result.CallAmbiguous {
		t.Fatalf("unexpected result: %+v", result)
	}
	if targets[authority.RemotePrefixes[0]] != "eni-b" || targets[authority.RemotePrefixes[1]] != "eni-a" {
		t.Fatalf("partial progress mutated wrong routes: %+v", targets)
	}
	if api.replaceRouteCalls != 1 || api.describeRouteTablesCalls != 3 {
		t.Fatalf("unexpected call counts: replace=%d describe=%d", api.replaceRouteCalls, api.describeRouteTablesCalls)
	}
	input := api.replaceRouteInputs[0]
	if aws.ToString(input.RouteTableId) != authority.RouteTableID || aws.ToString(input.DestinationCidrBlock) != authority.RemotePrefixes[0] || aws.ToString(input.NetworkInterfaceId) != "eni-b" {
		t.Fatalf("ReplaceRoute was not exact: %+v", input)
	}
	if input.DestinationIpv6CidrBlock != nil || input.DestinationPrefixListId != nil || input.GatewayId != nil || input.NatGatewayId != nil || input.TransitGatewayId != nil || input.VpcEndpointId != nil {
		t.Fatalf("ReplaceRoute included an unauthorized route shape: %+v", input)
	}
}

func TestReplaceAndWaitSettlesTimeoutAfterCommit(t *testing.T) {
	authority := testAuthority()
	clock := newFakeClock(time.Date(2026, time.September, 4, 16, 0, 0, 0, time.UTC))
	sleeper := &advancingSleeper{clock: clock}
	targets := map[string]string{
		authority.RemotePrefixes[0]: "eni-a",
		authority.RemotePrefixes[1]: "eni-a",
	}
	api := &fakeEC2{}
	api.describeRouteTablesFunc = func(context.Context, *ec2.DescribeRouteTablesInput) (*ec2.DescribeRouteTablesOutput, error) {
		return routeTableOutput(authority, targets), nil
	}
	api.replaceRouteFunc = func(_ context.Context, input *ec2.ReplaceRouteInput) (*ec2.ReplaceRouteOutput, error) {
		targets[aws.ToString(input.DestinationCidrBlock)] = aws.ToString(input.NetworkInterfaceId)
		return nil, context.DeadlineExceeded
	}
	controller := newRouteController(api, clock, sleeper)

	result, err := controller.ReplaceAndWait(context.Background(), authority, authority.RemotePrefixes[0], "eni-a", "eni-b", clock.Now().Add(10*time.Second))
	if err != nil {
		t.Fatalf("timeout-after-commit was not settled: %v", err)
	}
	if result.Settlement != SettlementDesired || !result.CallAmbiguous || result.ObservedENIID != "eni-b" {
		t.Fatalf("unexpected timeout settlement: %+v", result)
	}
	if api.describeRouteTablesCalls != 3 {
		t.Fatalf("ambiguous call was not stably polled: describe calls=%d", api.describeRouteTablesCalls)
	}
}

func TestReplaceAndWaitReportsPreviousSettlement(t *testing.T) {
	authority := testAuthority()
	clock := newFakeClock(time.Date(2026, time.September, 4, 17, 0, 0, 0, time.UTC))
	sleeper := &advancingSleeper{clock: clock}
	targets := map[string]string{
		authority.RemotePrefixes[0]: "eni-a",
		authority.RemotePrefixes[1]: "eni-a",
	}
	api := &fakeEC2{
		describeRouteTablesFunc: func(context.Context, *ec2.DescribeRouteTablesInput) (*ec2.DescribeRouteTablesOutput, error) {
			return routeTableOutput(authority, targets), nil
		},
		replaceRouteFunc: func(context.Context, *ec2.ReplaceRouteInput) (*ec2.ReplaceRouteOutput, error) {
			return nil, errors.New("untrusted SDK detail: SECRET-CREDENTIAL")
		},
	}
	controller := newRouteController(api, clock, sleeper)

	result, err := controller.ReplaceAndWait(context.Background(), authority, authority.RemotePrefixes[0], "eni-a", "eni-b", clock.Now().Add(10*time.Second))
	if !errors.Is(err, ErrAmbiguous) {
		t.Fatalf("ReplaceAndWait error = %v, want ambiguous", err)
	}
	var ambiguous *AmbiguousError
	if !errors.As(err, &ambiguous) || !ambiguous.CallFailed || len(ambiguous.Observations) == 0 {
		t.Fatalf("unexpected ambiguous error: %#v", err)
	}
	if strings.Contains(err.Error(), "SECRET-CREDENTIAL") || len(err.Error()) > MaxErrorMessageLength {
		t.Fatalf("error was not bounded and redacted: %q", err)
	}
	if result.Settlement != SettlementPrevious || result.ObservedENIID != "eni-a" || !result.CallAmbiguous {
		t.Fatalf("unexpected prior settlement: %+v", result)
	}
	if api.describeRouteTablesCalls != 3 {
		t.Fatalf("failed call was not stably polled: describe calls=%d", api.describeRouteTablesCalls)
	}
}

func TestReplaceAndWaitRecognizesPriorDesiredSettlement(t *testing.T) {
	authority := testAuthority()
	clock := newFakeClock(time.Date(2026, time.September, 4, 17, 30, 0, 0, time.UTC))
	targets := map[string]string{
		authority.RemotePrefixes[0]: "eni-b",
		authority.RemotePrefixes[1]: "eni-a",
	}
	api := &fakeEC2{
		describeRouteTablesFunc: func(context.Context, *ec2.DescribeRouteTablesInput) (*ec2.DescribeRouteTablesOutput, error) {
			return routeTableOutput(authority, targets), nil
		},
	}
	controller := newRouteController(api, clock, &advancingSleeper{clock: clock})

	result, err := controller.ReplaceAndWait(context.Background(), authority, authority.RemotePrefixes[0], "eni-a", "eni-b", clock.Now().Add(10*time.Second))
	if err != nil {
		t.Fatalf("ReplaceAndWait: %v", err)
	}
	if result.Settlement != SettlementDesired || result.CallAttempted || result.PreviousENIID != "eni-a" {
		t.Fatalf("unexpected prior desired result: %+v", result)
	}
	if api.replaceRouteCalls != 0 || api.describeRouteTablesCalls != 3 {
		t.Fatalf("prior settlement caused mutation: describe=%d replace=%d", api.describeRouteTablesCalls, api.replaceRouteCalls)
	}
}

func TestReplaceAndWaitDoesNotAcceptOneDesiredReadWithoutMutation(t *testing.T) {
	authority := testAuthority()
	clock := newFakeClock(time.Date(2026, time.September, 4, 17, 40, 0, 0, time.UTC))
	sequence := []string{"eni-b", "eni-a", "eni-a"}
	api := &fakeEC2{}
	api.describeRouteTablesFunc = func(context.Context, *ec2.DescribeRouteTablesInput) (*ec2.DescribeRouteTablesOutput, error) {
		index := min(api.describeRouteTablesCalls-1, len(sequence)-1)
		return routeTableOutput(authority, map[string]string{
			authority.RemotePrefixes[0]: sequence[index],
			authority.RemotePrefixes[1]: "eni-a",
		}), nil
	}
	controller := newRouteController(api, clock, &advancingSleeper{clock: clock})

	result, err := controller.ReplaceAndWait(
		context.Background(),
		authority,
		authority.RemotePrefixes[0],
		"eni-a",
		"eni-b",
		clock.Now().Add(10*time.Second),
	)
	if !errors.Is(err, ErrAmbiguous) || result.Settlement != SettlementPrevious {
		t.Fatalf("unstable no-mutation result/error = %+v/%v, want stable previous settlement", result, err)
	}
	if result.CallAttempted || api.replaceRouteCalls != 0 || api.describeRouteTablesCalls != 3 {
		t.Fatalf("unstable no-mutation path called ReplaceRoute or skipped readback: result=%+v describe=%d replace=%d", result, api.describeRouteTablesCalls, api.replaceRouteCalls)
	}
}

func TestReplaceAndWaitRejectsPreCallDriftFromDurablePrevious(t *testing.T) {
	authority := testAuthority()
	authority.Owners = append(authority.Owners, authority.Owners[1])
	authority.Owners[2].RouterID = "router-c"
	authority.Owners[2].StableNodeID = "node-c"
	authority.Owners[2].InstanceID = "i-c"
	authority.Owners[2].ENIID = "eni-c"
	authority.Owners[2].SubnetID = "subnet-c"
	authority.Owners[2].AvailabilityZone = "us-east-1c"
	clock := newFakeClock(time.Date(2026, time.September, 4, 17, 45, 0, 0, time.UTC))
	targets := map[string]string{
		authority.RemotePrefixes[0]: "eni-c",
		authority.RemotePrefixes[1]: "eni-a",
	}
	api := &fakeEC2{
		describeRouteTablesFunc: func(context.Context, *ec2.DescribeRouteTablesInput) (*ec2.DescribeRouteTablesOutput, error) {
			return routeTableOutput(authority, targets), nil
		},
	}
	controller := newRouteController(api, clock, &advancingSleeper{clock: clock})

	result, err := controller.ReplaceAndWait(
		context.Background(),
		authority,
		authority.RemotePrefixes[0],
		"eni-a",
		"eni-b",
		clock.Now().Add(10*time.Second),
	)
	if !errors.Is(err, ErrOscillation) {
		t.Fatalf("ReplaceAndWait error = %v, want pre-call drift rejection", err)
	}
	if result.PreviousENIID != "eni-a" || result.ObservedENIID != "eni-c" || result.CallAttempted {
		t.Fatalf("unexpected drift result: %+v", result)
	}
	if api.describeRouteTablesCalls != 1 || api.replaceRouteCalls != 0 {
		t.Fatalf("pre-call drift reached mutation: describe=%d replace=%d", api.describeRouteTablesCalls, api.replaceRouteCalls)
	}
}

func TestReplaceAndWaitDetectsOscillation(t *testing.T) {
	authority := testAuthority()
	clock := newFakeClock(time.Date(2026, time.September, 4, 18, 0, 0, 0, time.UTC))
	sleeper := &advancingSleeper{clock: clock}
	sequence := []string{"eni-a", "eni-b", "eni-a", "eni-b"}
	api := &fakeEC2{}
	api.describeRouteTablesFunc = func(context.Context, *ec2.DescribeRouteTablesInput) (*ec2.DescribeRouteTablesOutput, error) {
		index := api.describeRouteTablesCalls - 1
		if index >= len(sequence) {
			index = len(sequence) - 1
		}
		return routeTableOutput(authority, map[string]string{
			authority.RemotePrefixes[0]: sequence[index],
			authority.RemotePrefixes[1]: "eni-a",
		}), nil
	}
	api.replaceRouteFunc = func(context.Context, *ec2.ReplaceRouteInput) (*ec2.ReplaceRouteOutput, error) {
		return &ec2.ReplaceRouteOutput{}, nil
	}
	controller := newRouteController(api, clock, sleeper)

	result, err := controller.ReplaceAndWait(context.Background(), authority, authority.RemotePrefixes[0], "eni-a", "eni-b", clock.Now().Add(10*time.Second))
	if !errors.Is(err, ErrOscillation) {
		t.Fatalf("ReplaceAndWait error = %v, want oscillation", err)
	}
	var oscillation *OscillationError
	if !errors.As(err, &oscillation) || len(oscillation.Observations) < 3 {
		t.Fatalf("unexpected oscillation error: %#v", err)
	}
	if result.Settlement != "" || result.ObservedENIID != "eni-b" {
		t.Fatalf("unexpected oscillation result: %+v", result)
	}
	if api.describeRouteTablesCalls != 4 || sleeper.calls != 2 {
		t.Fatalf("unexpected oscillation polling: describe=%d sleeps=%d", api.describeRouteTablesCalls, sleeper.calls)
	}
}

func TestReplaceAndWaitCancellationAfterCallIsAmbiguous(t *testing.T) {
	authority := testAuthority()
	clock := newFakeClock(time.Date(2026, time.September, 4, 19, 0, 0, 0, time.UTC))
	ctx, cancel := context.WithCancel(context.Background())
	sleeper := &advancingSleeper{clock: clock}
	sleeper.beforeSleep = func(int) { cancel() }
	sequence := []string{"eni-a", "eni-b"}
	api := &fakeEC2{}
	api.describeRouteTablesFunc = func(context.Context, *ec2.DescribeRouteTablesInput) (*ec2.DescribeRouteTablesOutput, error) {
		index := min(api.describeRouteTablesCalls-1, len(sequence)-1)
		return routeTableOutput(authority, map[string]string{
			authority.RemotePrefixes[0]: sequence[index],
			authority.RemotePrefixes[1]: "eni-a",
		}), nil
	}
	api.replaceRouteFunc = func(context.Context, *ec2.ReplaceRouteInput) (*ec2.ReplaceRouteOutput, error) {
		return &ec2.ReplaceRouteOutput{}, nil
	}
	controller := newRouteController(api, clock, sleeper)

	result, err := controller.ReplaceAndWait(ctx, authority, authority.RemotePrefixes[0], "eni-a", "eni-b", clock.Now().Add(10*time.Second))
	if !errors.Is(err, context.Canceled) || !errors.Is(err, ErrAmbiguous) {
		t.Fatalf("ReplaceAndWait error = %v, want canceled ambiguous outcome", err)
	}
	var ambiguous *AmbiguousError
	if !errors.As(err, &ambiguous) {
		t.Fatalf("error type = %T, want *AmbiguousError", err)
	}
	if !result.CallAttempted || api.replaceRouteCalls != 1 || api.describeRouteTablesCalls != 2 {
		t.Fatalf("unexpected cancellation result/calls: result=%+v describe=%d replace=%d", result, api.describeRouteTablesCalls, api.replaceRouteCalls)
	}
}

func TestReplaceAndWaitBoundsPollingByDeadline(t *testing.T) {
	authority := testAuthority()
	clock := newFakeClock(time.Date(2026, time.September, 4, 20, 0, 0, 0, time.UTC))
	sleeper := &advancingSleeper{clock: clock}
	api := &fakeEC2{}
	api.describeRouteTablesFunc = func(context.Context, *ec2.DescribeRouteTablesInput) (*ec2.DescribeRouteTablesOutput, error) {
		if api.describeRouteTablesCalls == 1 {
			return routeTableOutput(authority, map[string]string{
				authority.RemotePrefixes[0]: "eni-a",
				authority.RemotePrefixes[1]: "eni-a",
			}), nil
		}
		return nil, errors.New("temporary read failure with SECRET response")
	}
	api.replaceRouteFunc = func(context.Context, *ec2.ReplaceRouteInput) (*ec2.ReplaceRouteOutput, error) {
		return &ec2.ReplaceRouteOutput{}, nil
	}
	controller := newRouteController(api, clock, sleeper)
	deadline := clock.Now().Add(3 * time.Second)

	result, err := controller.ReplaceAndWait(context.Background(), authority, authority.RemotePrefixes[0], "eni-a", "eni-b", deadline)
	if !errors.Is(err, ErrAmbiguous) || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("ReplaceAndWait error = %v, want deadline ambiguity", err)
	}
	if api.describeRouteTablesCalls != 5 || sleeper.calls != 4 {
		t.Fatalf("polling was not bounded: describe=%d sleeps=%d", api.describeRouteTablesCalls, sleeper.calls)
	}
	if result.CompletedAt.Before(deadline) || result.CallAttempted == false {
		t.Fatalf("unexpected bounded result: %+v", result)
	}
}

func TestReplaceAndWaitRejectsSuccessfulSettlementReadPastDeadline(t *testing.T) {
	authority := testAuthority()
	clock := newFakeClock(time.Date(2026, time.September, 4, 20, 30, 0, 0, time.UTC))
	sleeper := &advancingSleeper{clock: clock}
	targets := map[string]string{
		authority.RemotePrefixes[0]: "eni-a",
		authority.RemotePrefixes[1]: "eni-a",
	}
	api := &fakeEC2{}
	api.describeRouteTablesFunc = func(context.Context, *ec2.DescribeRouteTablesInput) (*ec2.DescribeRouteTablesOutput, error) {
		if api.describeRouteTablesCalls == 3 {
			clock.Advance(3 * time.Second)
		}
		return routeTableOutput(authority, targets), nil
	}
	api.replaceRouteFunc = func(_ context.Context, input *ec2.ReplaceRouteInput) (*ec2.ReplaceRouteOutput, error) {
		targets[aws.ToString(input.DestinationCidrBlock)] = aws.ToString(input.NetworkInterfaceId)
		return &ec2.ReplaceRouteOutput{}, nil
	}
	controller := newRouteController(api, clock, sleeper)
	deadline := clock.Now().Add(3 * time.Second)

	result, err := controller.ReplaceAndWait(context.Background(), authority, authority.RemotePrefixes[0], "eni-a", "eni-b", deadline)
	if !errors.Is(err, ErrAmbiguous) || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("ReplaceAndWait() error = %v, want post-call deadline ambiguity", err)
	}
	if result.Settlement != "" || result.CompletedAt.Before(deadline) || !result.CallAttempted {
		t.Fatalf("post-deadline settlement was accepted: %+v", result)
	}
	if api.describeRouteTablesCalls != 3 || api.replaceRouteCalls != 1 {
		t.Fatalf("post-deadline settlement calls = %d describes/%d replaces", api.describeRouteTablesCalls, api.replaceRouteCalls)
	}
}

func TestReplaceAndWaitRechecksDeadlineImmediatelyBeforeCall(t *testing.T) {
	authority := testAuthority()
	clock := newFakeClock(time.Date(2026, time.September, 4, 21, 0, 0, 0, time.UTC))
	deadline := clock.Now().Add(time.Second)
	api := &fakeEC2{}
	api.describeRouteTablesFunc = func(context.Context, *ec2.DescribeRouteTablesInput) (*ec2.DescribeRouteTablesOutput, error) {
		clock.Advance(2 * time.Second)
		return routeTableOutput(authority, map[string]string{
			authority.RemotePrefixes[0]: "eni-a",
			authority.RemotePrefixes[1]: "eni-a",
		}), nil
	}
	controller := newRouteController(api, clock, &advancingSleeper{clock: clock})

	result, err := controller.ReplaceAndWait(context.Background(), authority, authority.RemotePrefixes[0], "eni-a", "eni-b", deadline)
	if !errors.Is(err, ErrUnsafeDeadline) {
		t.Fatalf("ReplaceAndWait error = %v, want unsafe deadline", err)
	}
	if result.CallAttempted || api.replaceRouteCalls != 0 {
		t.Fatalf("mutation started past deadline: result=%+v calls=%d", result, api.replaceRouteCalls)
	}
}

func TestReplaceAndWaitBoundsRetainedObservations(t *testing.T) {
	authority := testAuthority()
	clock := newFakeClock(time.Date(2026, time.September, 4, 22, 0, 0, 0, time.UTC))
	sleeper := &advancingSleeper{clock: clock}
	api := &fakeEC2{}
	api.describeRouteTablesFunc = func(context.Context, *ec2.DescribeRouteTablesInput) (*ec2.DescribeRouteTablesOutput, error) {
		target := "eni-a"
		if api.describeRouteTablesCalls > 1 {
			target = "eni-b"
		}
		return routeTableOutput(authority, map[string]string{
			authority.RemotePrefixes[0]: target,
			authority.RemotePrefixes[1]: "eni-a",
		}), nil
	}
	api.replaceRouteFunc = func(context.Context, *ec2.ReplaceRouteInput) (*ec2.ReplaceRouteOutput, error) {
		return &ec2.ReplaceRouteOutput{}, nil
	}
	controller := newRouteController(api, clock, sleeper, WithStableReads(40))

	result, err := controller.ReplaceAndWait(context.Background(), authority, authority.RemotePrefixes[0], "eni-a", "eni-b", clock.Now().Add(time.Minute))
	if err != nil {
		t.Fatalf("ReplaceAndWait: %v", err)
	}
	if len(result.Observations) != MaxObservedRoutes {
		t.Fatalf("retained observations = %d, want bound %d", len(result.Observations), MaxObservedRoutes)
	}
}

func TestSnapshotBoundsAndRedactsAPIFailure(t *testing.T) {
	authority := testAuthority()
	api := &fakeEC2{
		describeRouteTablesFunc: func(ctx context.Context, _ *ec2.DescribeRouteTablesInput) (*ec2.DescribeRouteTablesOutput, error) {
			<-ctx.Done()
			return nil, errors.New("SECRET-CREDENTIAL\n" + strings.Repeat("x", 2048))
		},
	}
	controller, err := New(api, authority.Region, WithAPITimeout(10*time.Millisecond))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	started := time.Now()

	_, err = controller.Snapshot(context.Background(), authority)
	if !errors.Is(err, ErrAPI) {
		t.Fatalf("Snapshot error = %v, want API failure", err)
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("API call was not bounded: %s", elapsed)
	}
	if strings.Contains(err.Error(), "SECRET-CREDENTIAL") || len(err.Error()) > MaxErrorMessageLength {
		t.Fatalf("API error was not bounded and redacted: %q", err)
	}
}

func TestUnauthorizedObservationIsBoundedAndRedacted(t *testing.T) {
	authority := testAuthority()
	untrustedTarget := "eni-" + strings.Repeat("x", 200) + "\nSECRET"
	api := &fakeEC2{
		describeRouteTablesFunc: func(context.Context, *ec2.DescribeRouteTablesInput) (*ec2.DescribeRouteTablesOutput, error) {
			return routeTableOutput(authority, map[string]string{
				authority.RemotePrefixes[0]: untrustedTarget,
				authority.RemotePrefixes[1]: "eni-a",
			}), nil
		},
	}
	controller, err := New(api, authority.Region)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	_, err = controller.Snapshot(context.Background(), authority)
	var unauthorized *UnauthorizedError
	if !errors.As(err, &unauthorized) {
		t.Fatalf("Snapshot error = %v, want *UnauthorizedError", err)
	}
	if len(unauthorized.TargetENIID) > maxObservedFieldLength || strings.ContainsAny(unauthorized.TargetENIID, "\r\n") {
		t.Fatalf("target was not bounded and redacted: %q", unauthorized.TargetENIID)
	}
	if len(unauthorized.Observations) != 1 || len(unauthorized.Observations[0].TargetENIID) > maxObservedFieldLength {
		t.Fatalf("observations were not bounded: %+v", unauthorized.Observations)
	}
	if len(err.Error()) > MaxErrorMessageLength {
		t.Fatalf("error exceeds bound: %d", len(err.Error()))
	}
}
