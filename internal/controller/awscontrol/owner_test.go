package awscontrol

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

func TestValidateOwnerHealthy(t *testing.T) {
	authority := testAuthority()
	owner := authority.Owners[0]
	api := healthyOwnerFake(owner)
	now := time.Date(2026, time.September, 4, 12, 0, 0, 0, time.UTC)
	controller, err := New(api, authority.Region, WithClock(newFakeClock(now)))
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	validation, err := controller.ValidateOwner(context.Background(), authority, owner)
	if err != nil {
		t.Fatalf("ValidateOwner: %v", err)
	}
	if validation.ValidatedAt != now || validation.InstanceID != owner.InstanceID || validation.ENIID != owner.ENIID {
		t.Fatalf("unexpected validation: %+v", validation)
	}
	if validation.InstanceState != "running" || validation.SystemStatus != "ok" || validation.InstanceStatus != "ok" {
		t.Fatalf("unexpected health evidence: %+v", validation)
	}
	if !validation.InstanceSourceDestCheckDisabled || !validation.ENISourceDestCheckDisabled {
		t.Fatalf("source/destination check evidence = %+v", validation)
	}
	if api.describeInstancesCalls != 1 || api.describeInstanceStatusCalls != 1 || api.describeNetworkInterfacesCalls != 1 {
		t.Fatalf("unexpected call counts: instances=%d status=%d enis=%d", api.describeInstancesCalls, api.describeInstanceStatusCalls, api.describeNetworkInterfacesCalls)
	}
	if len(api.describeInstancesInput.InstanceIds) != 1 || api.describeInstancesInput.InstanceIds[0] != owner.InstanceID {
		t.Fatalf("DescribeInstances was not exact: %+v", api.describeInstancesInput)
	}
	if len(api.describeInstanceStatusInput.InstanceIds) != 1 || api.describeInstanceStatusInput.InstanceIds[0] != owner.InstanceID || !aws.ToBool(api.describeInstanceStatusInput.IncludeAllInstances) {
		t.Fatalf("DescribeInstanceStatus was not exact: %+v", api.describeInstanceStatusInput)
	}
	if len(api.describeNetworkInterfacesInput.NetworkInterfaceIds) != 1 || api.describeNetworkInterfacesInput.NetworkInterfaceIds[0] != owner.ENIID {
		t.Fatalf("DescribeNetworkInterfaces was not exact: %+v", api.describeNetworkInterfacesInput)
	}
}

func TestValidateOwnerRejectsIneligibleCandidate(t *testing.T) {
	tests := []struct {
		name     string
		mutate   func(*fakeEC2)
		check    string
		observed string
	}{
		{
			name: "instance stopped",
			mutate: func(api *fakeEC2) {
				api.describeInstancesOutput.Reservations[0].Instances[0].State.Name = types.InstanceStateNameStopped
			},
			check: "instance-state",
		},
		{
			name: "instance source destination check enabled",
			mutate: func(api *fakeEC2) {
				api.describeInstancesOutput.Reservations[0].Instances[0].SourceDestCheck = aws.Bool(true)
			},
			check:    "instance-source-destination-check",
			observed: "enabled",
		},
		{
			name: "instance source destination check missing",
			mutate: func(api *fakeEC2) {
				api.describeInstancesOutput.Reservations[0].Instances[0].SourceDestCheck = nil
			},
			check:    "instance-source-destination-check",
			observed: "missing",
		},
		{
			name: "instance VPC mismatch",
			mutate: func(api *fakeEC2) {
				api.describeInstancesOutput.Reservations[0].Instances[0].VpcId = aws.String("vpc-other")
			},
			check: "instance-vpc",
		},
		{
			name: "instance subnet mismatch",
			mutate: func(api *fakeEC2) {
				api.describeInstancesOutput.Reservations[0].Instances[0].SubnetId = aws.String("subnet-other")
			},
			check: "instance-subnet",
		},
		{
			name: "instance AZ mismatch",
			mutate: func(api *fakeEC2) {
				api.describeInstancesOutput.Reservations[0].Instances[0].Placement.AvailabilityZone = aws.String("us-east-1c")
			},
			check: "instance-availability-zone",
		},
		{
			name: "wrong primary ENI",
			mutate: func(api *fakeEC2) {
				api.describeInstancesOutput.Reservations[0].Instances[0].NetworkInterfaces[0].NetworkInterfaceId = aws.String("eni-other")
			},
			check: "instance-primary-eni",
		},
		{
			name: "instance primary ENI source destination check enabled",
			mutate: func(api *fakeEC2) {
				api.describeInstancesOutput.Reservations[0].Instances[0].NetworkInterfaces[0].SourceDestCheck = aws.Bool(true)
			},
			check:    "instance-primary-eni-source-destination-check",
			observed: "enabled",
		},
		{
			name: "instance primary ENI source destination check missing",
			mutate: func(api *fakeEC2) {
				api.describeInstancesOutput.Reservations[0].Instances[0].NetworkInterfaces[0].SourceDestCheck = nil
			},
			check:    "instance-primary-eni-source-destination-check",
			observed: "missing",
		},
		{
			name: "system check impaired",
			mutate: func(api *fakeEC2) {
				api.describeInstanceStatusOutput.InstanceStatuses[0].SystemStatus.Status = types.SummaryStatusImpaired
			},
			check: "system-status",
		},
		{
			name: "instance check impaired",
			mutate: func(api *fakeEC2) {
				api.describeInstanceStatusOutput.InstanceStatuses[0].InstanceStatus.Status = types.SummaryStatusImpaired
			},
			check: "instance-status",
		},
		{
			name: "ENI available",
			mutate: func(api *fakeEC2) {
				api.describeNetworkInterfacesOutput.NetworkInterfaces[0].Status = types.NetworkInterfaceStatusAvailable
			},
			check: "eni-status",
		},
		{
			name: "ENI source destination check enabled",
			mutate: func(api *fakeEC2) {
				api.describeNetworkInterfacesOutput.NetworkInterfaces[0].SourceDestCheck = aws.Bool(true)
			},
			check:    "eni-source-destination-check",
			observed: "enabled",
		},
		{
			name: "ENI source destination check missing",
			mutate: func(api *fakeEC2) {
				api.describeNetworkInterfacesOutput.NetworkInterfaces[0].SourceDestCheck = nil
			},
			check:    "eni-source-destination-check",
			observed: "missing",
		},
		{
			name: "ENI VPC mismatch",
			mutate: func(api *fakeEC2) {
				api.describeNetworkInterfacesOutput.NetworkInterfaces[0].VpcId = aws.String("vpc-other")
			},
			check: "eni-vpc",
		},
		{
			name: "ENI subnet mismatch",
			mutate: func(api *fakeEC2) {
				api.describeNetworkInterfacesOutput.NetworkInterfaces[0].SubnetId = aws.String("subnet-other")
			},
			check: "eni-subnet",
		},
		{
			name: "ENI AZ mismatch",
			mutate: func(api *fakeEC2) {
				api.describeNetworkInterfacesOutput.NetworkInterfaces[0].AvailabilityZone = aws.String("us-east-1c")
			},
			check: "eni-availability-zone",
		},
		{
			name: "ENI wrong instance",
			mutate: func(api *fakeEC2) {
				api.describeNetworkInterfacesOutput.NetworkInterfaces[0].Attachment.InstanceId = aws.String("i-other")
			},
			check: "eni-instance",
		},
		{
			name: "ENI not device zero",
			mutate: func(api *fakeEC2) {
				api.describeNetworkInterfacesOutput.NetworkInterfaces[0].Attachment.DeviceIndex = aws.Int32(1)
			},
			check: "eni-device-index",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			authority := testAuthority()
			owner := authority.Owners[0]
			api := healthyOwnerFake(owner)
			test.mutate(api)
			controller, err := New(api, authority.Region)
			if err != nil {
				t.Fatalf("New: %v", err)
			}

			_, err = controller.ValidateOwner(context.Background(), authority, owner)
			if !errors.Is(err, ErrOwnerIneligible) {
				t.Fatalf("ValidateOwner error = %v, want owner ineligible", err)
			}
			var ineligibleError *IneligibleError
			if !errors.As(err, &ineligibleError) || ineligibleError.Check != test.check {
				t.Fatalf("ValidateOwner error = %#v, want check %q", err, test.check)
			}
			if test.observed != "" && ineligibleError.Observed != test.observed {
				t.Fatalf("ValidateOwner observed = %q, want %q", ineligibleError.Observed, test.observed)
			}
		})
	}
}

func TestValidateOwnerRequiresExactAuthorityOwner(t *testing.T) {
	authority := testAuthority()
	owner := authority.Owners[0]
	owner.ENIID = "eni-b"
	api := healthyOwnerFake(authority.Owners[0])
	controller, err := New(api, authority.Region)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	_, err = controller.ValidateOwner(context.Background(), authority, owner)
	if !errors.Is(err, ErrOwnerIneligible) {
		t.Fatalf("ValidateOwner error = %v, want owner ineligible", err)
	}
	if api.describeInstancesCalls != 0 {
		t.Fatalf("AWS was queried for an unauthorized owner")
	}
}

func TestValidateOwnerHonorsCancellation(t *testing.T) {
	authority := testAuthority()
	api := healthyOwnerFake(authority.Owners[0])
	controller, err := New(api, authority.Region)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err = controller.ValidateOwner(ctx, authority, authority.Owners[0])
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("ValidateOwner error = %v, want context canceled", err)
	}
	if api.describeInstancesCalls != 0 {
		t.Fatalf("AWS was queried after cancellation")
	}
}
