package awscontrol

import (
	"context"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/jaxxstorm/envelope/internal/controller/model"
)

// ValidateOwner verifies the exact configured instance, status checks, and
// primary ENI. It never discovers or adopts an owner from AWS inventory.
func (c *Controller) ValidateOwner(ctx context.Context, authority model.DomainAuthority, owner model.OwnerAuthority) (OwnerValidation, error) {
	if err := requireController(c); err != nil {
		return OwnerValidation{}, err
	}
	if err := c.validateAuthority(ctx, authority); err != nil {
		return OwnerValidation{}, err
	}
	if err := requireExactOwner(authority, owner); err != nil {
		return OwnerValidation{}, err
	}
	if owner.Region != c.region {
		return OwnerValidation{}, ineligible(owner.InstanceID, "region", c.region, owner.Region)
	}

	instance, err := c.describeInstance(ctx, owner.InstanceID)
	if err != nil {
		return OwnerValidation{}, err
	}
	if instance.State == nil || instance.State.Name != types.InstanceStateNameRunning {
		return OwnerValidation{}, ineligible(owner.InstanceID, "instance-state", string(types.InstanceStateNameRunning), instanceState(instance))
	}
	if instance.SourceDestCheck == nil || aws.ToBool(instance.SourceDestCheck) {
		return OwnerValidation{}, ineligible(owner.InstanceID, "instance-source-destination-check", "disabled", sourceDestCheck(instance.SourceDestCheck))
	}
	if aws.ToString(instance.VpcId) != owner.VPCID {
		return OwnerValidation{}, ineligible(owner.InstanceID, "instance-vpc", owner.VPCID, aws.ToString(instance.VpcId))
	}
	if aws.ToString(instance.SubnetId) != owner.SubnetID {
		return OwnerValidation{}, ineligible(owner.InstanceID, "instance-subnet", owner.SubnetID, aws.ToString(instance.SubnetId))
	}
	if instance.Placement == nil || aws.ToString(instance.Placement.AvailabilityZone) != owner.AvailabilityZone {
		observed := ""
		if instance.Placement != nil {
			observed = aws.ToString(instance.Placement.AvailabilityZone)
		}
		return OwnerValidation{}, ineligible(owner.InstanceID, "instance-availability-zone", owner.AvailabilityZone, observed)
	}
	if err := validateInstancePrimaryENI(instance, owner); err != nil {
		return OwnerValidation{}, err
	}

	status, err := c.describeStatus(ctx, owner.InstanceID)
	if err != nil {
		return OwnerValidation{}, err
	}
	if status.InstanceState == nil || status.InstanceState.Name != types.InstanceStateNameRunning {
		observed := ""
		if status.InstanceState != nil {
			observed = string(status.InstanceState.Name)
		}
		return OwnerValidation{}, ineligible(owner.InstanceID, "status-instance-state", string(types.InstanceStateNameRunning), observed)
	}
	if aws.ToString(status.AvailabilityZone) != owner.AvailabilityZone {
		return OwnerValidation{}, ineligible(owner.InstanceID, "status-availability-zone", owner.AvailabilityZone, aws.ToString(status.AvailabilityZone))
	}
	if status.SystemStatus == nil || status.SystemStatus.Status != types.SummaryStatusOk {
		return OwnerValidation{}, ineligible(owner.InstanceID, "system-status", string(types.SummaryStatusOk), summaryStatus(status.SystemStatus))
	}
	if status.InstanceStatus == nil || status.InstanceStatus.Status != types.SummaryStatusOk {
		return OwnerValidation{}, ineligible(owner.InstanceID, "instance-status", string(types.SummaryStatusOk), summaryStatus(status.InstanceStatus))
	}

	networkInterface, err := c.describeNetworkInterface(ctx, owner.ENIID)
	if err != nil {
		return OwnerValidation{}, err
	}
	if networkInterface.Status != types.NetworkInterfaceStatusInUse {
		return OwnerValidation{}, ineligible(owner.ENIID, "eni-status", string(types.NetworkInterfaceStatusInUse), string(networkInterface.Status))
	}
	if networkInterface.SourceDestCheck == nil || aws.ToBool(networkInterface.SourceDestCheck) {
		return OwnerValidation{}, ineligible(owner.ENIID, "eni-source-destination-check", "disabled", sourceDestCheck(networkInterface.SourceDestCheck))
	}
	if aws.ToString(networkInterface.VpcId) != owner.VPCID {
		return OwnerValidation{}, ineligible(owner.ENIID, "eni-vpc", owner.VPCID, aws.ToString(networkInterface.VpcId))
	}
	if aws.ToString(networkInterface.SubnetId) != owner.SubnetID {
		return OwnerValidation{}, ineligible(owner.ENIID, "eni-subnet", owner.SubnetID, aws.ToString(networkInterface.SubnetId))
	}
	if aws.ToString(networkInterface.AvailabilityZone) != owner.AvailabilityZone {
		return OwnerValidation{}, ineligible(owner.ENIID, "eni-availability-zone", owner.AvailabilityZone, aws.ToString(networkInterface.AvailabilityZone))
	}
	if networkInterface.Attachment == nil {
		return OwnerValidation{}, ineligible(owner.ENIID, "eni-attachment", owner.InstanceID+" at device 0", "detached")
	}
	attachment := networkInterface.Attachment
	if attachment.Status != types.AttachmentStatusAttached {
		return OwnerValidation{}, ineligible(owner.ENIID, "eni-attachment-status", string(types.AttachmentStatusAttached), string(attachment.Status))
	}
	if aws.ToString(attachment.InstanceId) != owner.InstanceID {
		return OwnerValidation{}, ineligible(owner.ENIID, "eni-instance", owner.InstanceID, aws.ToString(attachment.InstanceId))
	}
	if attachment.DeviceIndex == nil || aws.ToInt32(attachment.DeviceIndex) != 0 {
		return OwnerValidation{}, ineligible(owner.ENIID, "eni-device-index", "0", deviceIndex(attachment.DeviceIndex))
	}

	return OwnerValidation{
		ValidatedAt:                     c.clock.Now(),
		Region:                          c.region,
		InstanceID:                      owner.InstanceID,
		InstanceState:                   string(instance.State.Name),
		SystemStatus:                    string(status.SystemStatus.Status),
		InstanceStatus:                  string(status.InstanceStatus.Status),
		ENIID:                           owner.ENIID,
		ENIStatus:                       string(networkInterface.Status),
		AttachmentStatus:                string(attachment.Status),
		InstanceSourceDestCheckDisabled: true,
		ENISourceDestCheckDisabled:      true,
		VPCID:                           owner.VPCID,
		SubnetID:                        owner.SubnetID,
		AvailabilityZone:                owner.AvailabilityZone,
	}, nil
}

func (c *Controller) describeInstance(ctx context.Context, instanceID string) (*types.Instance, error) {
	callContext, cancel, err := c.apiContext(ctx, time.Time{})
	if err != nil {
		return nil, err
	}
	defer cancel()
	output, callErr := c.api.DescribeInstances(callContext, &ec2.DescribeInstancesInput{InstanceIds: []string{instanceID}})
	if callErr != nil {
		return nil, apiFailure(ctx, "DescribeInstances", callErr)
	}
	var instances []*types.Instance
	if output != nil {
		for reservationIndex := range output.Reservations {
			for instanceIndex := range output.Reservations[reservationIndex].Instances {
				instance := &output.Reservations[reservationIndex].Instances[instanceIndex]
				instances = append(instances, instance)
			}
		}
	}
	if len(instances) != 1 || aws.ToString(instances[0].InstanceId) != instanceID {
		return nil, ineligible(instanceID, "instance-lookup", "one exact instance", exactCount(len(instances)))
	}
	return instances[0], nil
}

func (c *Controller) describeStatus(ctx context.Context, instanceID string) (*types.InstanceStatus, error) {
	callContext, cancel, err := c.apiContext(ctx, time.Time{})
	if err != nil {
		return nil, err
	}
	defer cancel()
	output, callErr := c.api.DescribeInstanceStatus(callContext, &ec2.DescribeInstanceStatusInput{
		IncludeAllInstances: aws.Bool(true),
		InstanceIds:         []string{instanceID},
	})
	if callErr != nil {
		return nil, apiFailure(ctx, "DescribeInstanceStatus", callErr)
	}
	if output == nil || len(output.InstanceStatuses) != 1 || aws.ToString(output.InstanceStatuses[0].InstanceId) != instanceID {
		count := 0
		if output != nil {
			count = len(output.InstanceStatuses)
		}
		return nil, ineligible(instanceID, "status-lookup", "one exact status", exactCount(count))
	}
	return &output.InstanceStatuses[0], nil
}

func (c *Controller) describeNetworkInterface(ctx context.Context, eniID string) (*types.NetworkInterface, error) {
	callContext, cancel, err := c.apiContext(ctx, time.Time{})
	if err != nil {
		return nil, err
	}
	defer cancel()
	output, callErr := c.api.DescribeNetworkInterfaces(callContext, &ec2.DescribeNetworkInterfacesInput{NetworkInterfaceIds: []string{eniID}})
	if callErr != nil {
		return nil, apiFailure(ctx, "DescribeNetworkInterfaces", callErr)
	}
	if output == nil || len(output.NetworkInterfaces) != 1 || aws.ToString(output.NetworkInterfaces[0].NetworkInterfaceId) != eniID {
		count := 0
		if output != nil {
			count = len(output.NetworkInterfaces)
		}
		return nil, ineligible(eniID, "eni-lookup", "one exact ENI", exactCount(count))
	}
	return &output.NetworkInterfaces[0], nil
}

func validateInstancePrimaryENI(instance *types.Instance, owner model.OwnerAuthority) error {
	primaryCount := 0
	primaryID := ""
	primaryStatus := ""
	for _, networkInterface := range instance.NetworkInterfaces {
		if networkInterface.Attachment == nil || networkInterface.Attachment.DeviceIndex == nil || aws.ToInt32(networkInterface.Attachment.DeviceIndex) != 0 {
			continue
		}
		primaryCount++
		primaryID = aws.ToString(networkInterface.NetworkInterfaceId)
		primaryStatus = string(networkInterface.Attachment.Status)
		if networkInterface.Attachment.Status != types.AttachmentStatusAttached {
			return ineligible(owner.InstanceID, "instance-primary-eni-status", string(types.AttachmentStatusAttached), primaryStatus)
		}
		if networkInterface.Status != types.NetworkInterfaceStatusInUse {
			return ineligible(owner.InstanceID, "instance-primary-eni-state", string(types.NetworkInterfaceStatusInUse), string(networkInterface.Status))
		}
		if networkInterface.SourceDestCheck == nil || aws.ToBool(networkInterface.SourceDestCheck) {
			return ineligible(owner.InstanceID, "instance-primary-eni-source-destination-check", "disabled", sourceDestCheck(networkInterface.SourceDestCheck))
		}
		if aws.ToString(networkInterface.VpcId) != owner.VPCID || aws.ToString(networkInterface.SubnetId) != owner.SubnetID {
			return ineligible(owner.InstanceID, "instance-primary-eni-network", owner.VPCID+"/"+owner.SubnetID, aws.ToString(networkInterface.VpcId)+"/"+aws.ToString(networkInterface.SubnetId))
		}
	}
	if primaryCount != 1 || primaryID != owner.ENIID {
		return ineligible(owner.InstanceID, "instance-primary-eni", owner.ENIID, primaryID)
	}
	return nil
}

func ineligible(resource, check, expected, observed string) error {
	return &IneligibleError{
		Resource: safeField(resource),
		Check:    safeField(check),
		Expected: safeField(expected),
		Observed: safeField(observed),
	}
}

func instanceState(instance *types.Instance) string {
	if instance == nil || instance.State == nil {
		return "missing"
	}
	return string(instance.State.Name)
}

func summaryStatus(summary *types.InstanceStatusSummary) string {
	if summary == nil {
		return "missing"
	}
	return string(summary.Status)
}

func deviceIndex(index *int32) string {
	if index == nil {
		return "missing"
	}
	return fmt.Sprintf("%d", aws.ToInt32(index))
}

func sourceDestCheck(enabled *bool) string {
	if enabled == nil {
		return "missing"
	}
	if aws.ToBool(enabled) {
		return "enabled"
	}
	return "disabled"
}

func exactCount(count int) string {
	return fmt.Sprintf("%d resources", count)
}
