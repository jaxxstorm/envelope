package awscontrol

import (
	"context"
	"errors"
	"net/netip"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/jaxxstorm/envelope/internal/controller/model"
)

// Snapshot returns the complete validated before-image for one route domain.
// Routes outside the domain's exact destination allowlist are not adopted.
func (c *Controller) Snapshot(ctx context.Context, authority model.DomainAuthority) (model.RouteSnapshot, error) {
	if err := requireController(c); err != nil {
		return model.RouteSnapshot{}, err
	}
	if err := c.validateAuthority(ctx, authority); err != nil {
		return model.RouteSnapshot{}, err
	}
	snapshot, _, err := c.readSnapshot(ctx, authority, time.Time{})
	return snapshot, err
}

// StableSnapshot returns a complete snapshot only after the configured number
// of consecutive authoritative reads agree. Reads are separated by the
// configured poll interval and are bounded by deadline.
func (c *Controller) StableSnapshot(
	ctx context.Context,
	authority model.DomainAuthority,
	deadline time.Time,
) (model.RouteSnapshot, error) {
	if err := requireController(c); err != nil {
		return model.RouteSnapshot{}, err
	}
	if err := c.validateAuthority(ctx, authority); err != nil {
		return model.RouteSnapshot{}, err
	}
	operationContext, cancelOperation, err := c.operationContext(ctx, deadline)
	if err != nil {
		return model.RouteSnapshot{}, err
	}
	defer cancelOperation()

	candidate, _, err := c.readSnapshot(operationContext, authority, deadline)
	if err != nil {
		return model.RouteSnapshot{}, err
	}
	if deadlineReached(ctx, operationContext, c.clock, deadline) {
		if callerErr := ctx.Err(); callerErr != nil {
			return model.RouteSnapshot{}, callerErr
		}
		return model.RouteSnapshot{}, unstableReadback("readback deadline reached")
	}
	stableReads := 1
	transitions := 0
	deadlinePollClamped := false
	for stableReads < c.stableReads {
		remaining := deadline.Sub(c.clock.Now())
		if remaining <= 0 {
			return model.RouteSnapshot{}, unstableReadback("readback deadline reached")
		}
		wait := pollWait(c.pollInterval, remaining, c.apiTimeout, &deadlinePollClamped)
		if err := c.sleeper.Sleep(operationContext, wait); err != nil {
			if callerErr := ctx.Err(); callerErr != nil {
				return model.RouteSnapshot{}, callerErr
			}
			return model.RouteSnapshot{}, unstableReadback("readback deadline reached")
		}
		if !c.clock.Now().Before(deadline) {
			return model.RouteSnapshot{}, unstableReadback("readback deadline reached")
		}

		next, _, readErr := c.readSnapshot(operationContext, authority, deadline)
		if readErr != nil {
			if callerErr := ctx.Err(); callerErr != nil {
				return model.RouteSnapshot{}, callerErr
			}
			return model.RouteSnapshot{}, readErr
		}
		if deadlineReached(ctx, operationContext, c.clock, deadline) {
			if callerErr := ctx.Err(); callerErr != nil {
				return model.RouteSnapshot{}, callerErr
			}
			return model.RouteSnapshot{}, unstableReadback("readback deadline reached")
		}
		if matchingSnapshotEntries(candidate, next) && next.CapturedAt.After(candidate.CapturedAt) {
			stableReads++
			candidate = next
			continue
		}

		transitions++
		if transitions >= c.oscillationLimit {
			return model.RouteSnapshot{}, unstableReadback("route snapshot changed repeatedly")
		}
		candidate = next
		stableReads = 1
	}
	return candidate, nil
}

// ReplaceAndWait replaces one exact authority route and polls authoritative
// route-table reads until the desired or previous target is stable. deadline is
// both the convergence bound and the caller's lease-safe mutation boundary.
// expectedPreviousENI is the target from the caller's durable before-image;
// drift to any other target is rejected before ReplaceRoute is called.
func (c *Controller) ReplaceAndWait(
	ctx context.Context,
	authority model.DomainAuthority,
	destinationPrefix string,
	expectedPreviousENI string,
	desiredENI string,
	deadline time.Time,
) (ReplaceResult, error) {
	result := ReplaceResult{
		DestinationPrefix: destinationPrefix,
		DesiredENIID:      desiredENI,
		PreviousENIID:     expectedPreviousENI,
	}
	if err := requireController(c); err != nil {
		return result, err
	}
	result.StartedAt = c.clock.Now()
	if err := c.validateAuthority(ctx, authority); err != nil {
		return result, err
	}
	if !exactPrefix(authority.RemotePrefixes, destinationPrefix) {
		return result, &InputError{Field: "destination prefix", Problem: "outside exact authority"}
	}
	if !authority.AllowsENI(desiredENI) {
		return result, &UnauthorizedError{
			DestinationPrefix: safeField(destinationPrefix),
			TargetENIID:       safeField(desiredENI),
		}
	}
	if !authority.AllowsENI(expectedPreviousENI) {
		return result, &UnauthorizedError{
			DestinationPrefix: safeField(destinationPrefix),
			TargetENIID:       safeField(expectedPreviousENI),
		}
	}

	operationContext, cancelOperation, err := c.operationContext(ctx, deadline)
	if err != nil {
		return result, err
	}
	defer cancelOperation()

	before, _, err := c.readSnapshot(operationContext, authority, deadline)
	if err != nil {
		if deadlineReached(ctx, operationContext, c.clock, deadline) {
			return result, preCallDeadlineError(ctx, deadline)
		}
		return result, err
	}
	result.Before = before
	previous, found := snapshotRoute(before, destinationPrefix)
	if !found {
		return result, ineligible(destinationPrefix, "route-presence", "one exact route", "missing")
	}
	result.ObservedENIID = previous.TargetENIID
	result.Observations = appendObservations(result.Observations, RouteObservation{
		ObservedAt:        before.CapturedAt,
		DestinationPrefix: previous.DestinationPrefix,
		TargetENIID:       previous.TargetENIID,
		State:             previous.State,
		Origin:            previous.Origin,
	})
	if previous.TargetENIID != expectedPreviousENI && previous.TargetENIID != desiredENI {
		result.CompletedAt = c.clock.Now()
		return result, newOscillationError(result)
	}
	if previous.TargetENIID == desiredENI {
		return c.pollSettlement(ctx, operationContext, authority, deadline, result)
	}

	// This second deadline check is intentionally immediately before the only
	// external mutation, after all potentially slow validation reads.
	if err := ctx.Err(); err != nil {
		return result, err
	}
	if err := operationContext.Err(); err != nil || !c.clock.Now().Before(deadline) {
		return result, preCallDeadlineError(ctx, deadline)
	}

	callContext, cancelCall, err := c.apiContext(operationContext, deadline)
	if err != nil {
		return result, preCallDeadlineError(ctx, deadline)
	}
	result.CallAttempted = true
	_, replaceErr := c.api.ReplaceRoute(callContext, &ec2.ReplaceRouteInput{
		DestinationCidrBlock: aws.String(destinationPrefix),
		NetworkInterfaceId:   aws.String(desiredENI),
		RouteTableId:         aws.String(authority.RouteTableID),
	})
	cancelCall()
	if replaceErr != nil {
		result.CallAmbiguous = true
	}

	if err := ctx.Err(); err != nil {
		result.CompletedAt = c.clock.Now()
		return result, newAmbiguousError(result, "caller canceled settlement", err)
	}
	if deadlineReached(ctx, operationContext, c.clock, deadline) {
		result.CompletedAt = c.clock.Now()
		return result, newAmbiguousError(result, "settlement deadline reached after mutation", context.DeadlineExceeded)
	}
	return c.pollSettlement(ctx, operationContext, authority, deadline, result)
}

func (c *Controller) pollSettlement(
	callerContext context.Context,
	operationContext context.Context,
	authority model.DomainAuthority,
	deadline time.Time,
	result ReplaceResult,
) (ReplaceResult, error) {
	lastTarget := ""
	stableReads := 0
	transitions := 0
	deadlinePollClamped := false

	for {
		if err := callerContext.Err(); err != nil {
			result.CompletedAt = c.clock.Now()
			return result, newAmbiguousError(result, "caller canceled settlement", err)
		}
		if deadlineReached(callerContext, operationContext, c.clock, deadline) {
			result.CompletedAt = c.clock.Now()
			return result, newAmbiguousError(result, "settlement deadline reached", context.DeadlineExceeded)
		}

		snapshot, observations, err := c.readSnapshot(operationContext, authority, deadline)
		result.Observations = appendObservations(result.Observations, observations...)
		if err == nil && deadlineReached(callerContext, operationContext, c.clock, deadline) {
			result.CompletedAt = c.clock.Now()
			if callerError := callerContext.Err(); callerError != nil {
				return result, newAmbiguousError(result, "caller canceled settlement", callerError)
			}
			return result, newAmbiguousError(result, "settlement deadline reached", context.DeadlineExceeded)
		}
		if err != nil {
			var unauthorized *UnauthorizedError
			if errors.As(err, &unauthorized) {
				unauthorized.Observations = cloneObservations(result.Observations)
				result.CompletedAt = c.clock.Now()
				return result, unauthorized
			}
			if callerError := callerContext.Err(); callerError != nil {
				result.CompletedAt = c.clock.Now()
				return result, newAmbiguousError(result, "caller canceled settlement", callerError)
			}
			if deadlineReached(callerContext, operationContext, c.clock, deadline) {
				result.CompletedAt = c.clock.Now()
				return result, newAmbiguousError(result, "settlement deadline reached", context.DeadlineExceeded)
			}
			lastTarget = ""
			stableReads = 0
		} else {
			route, found := snapshotRoute(snapshot, result.DestinationPrefix)
			if !found {
				lastTarget = ""
				stableReads = 0
			} else {
				result.ObservedENIID = route.TargetENIID
				if route.TargetENIID != result.PreviousENIID && route.TargetENIID != result.DesiredENIID {
					result.CompletedAt = c.clock.Now()
					return result, newOscillationError(result)
				}
				if lastTarget == route.TargetENIID {
					stableReads++
				} else {
					if lastTarget != "" {
						transitions++
					}
					lastTarget = route.TargetENIID
					stableReads = 1
				}
				if transitions >= c.oscillationLimit {
					result.CompletedAt = c.clock.Now()
					return result, newOscillationError(result)
				}
				if stableReads >= c.stableReads {
					result.CompletedAt = c.clock.Now()
					if route.TargetENIID == result.DesiredENIID {
						result.Settlement = SettlementDesired
						return result, nil
					}
					result.Settlement = SettlementPrevious
					return result, newAmbiguousError(result, "mutation settled on previous target", nil)
				}
			}
		}

		remaining := deadline.Sub(c.clock.Now())
		if remaining <= 0 {
			result.CompletedAt = c.clock.Now()
			return result, newAmbiguousError(result, "settlement deadline reached", context.DeadlineExceeded)
		}
		wait := pollWait(c.pollInterval, remaining, c.apiTimeout, &deadlinePollClamped)
		if err := c.sleeper.Sleep(operationContext, wait); err != nil {
			result.CompletedAt = c.clock.Now()
			cause := context.DeadlineExceeded
			reason := "settlement wait ended"
			if callerError := callerContext.Err(); callerError != nil {
				cause = callerError
				reason = "caller canceled settlement"
			}
			return result, newAmbiguousError(result, reason, cause)
		}
	}
}

func pollWait(interval, remaining, readBudget time.Duration, deadlineClampUsed *bool) time.Duration {
	// Preserve one normal API-call budget when possible. Splitting the remaining
	// time only once avoids an instantaneous-error loop that repeatedly halves it.
	reserve := readBudget
	if reserve <= 0 || reserve >= remaining {
		reserve = remaining / 2
	}
	maximumWait := remaining - reserve
	if maximumWait > 0 && interval <= maximumWait {
		return interval
	}
	if maximumWait > 0 && deadlineClampUsed != nil && !*deadlineClampUsed {
		*deadlineClampUsed = true
		return maximumWait
	}
	if interval < remaining {
		return interval
	}
	return remaining
}

func (c *Controller) readSnapshot(
	ctx context.Context,
	authority model.DomainAuthority,
	deadline time.Time,
) (model.RouteSnapshot, []RouteObservation, error) {
	callContext, cancel, err := c.apiContext(ctx, deadline)
	if err != nil {
		return model.RouteSnapshot{}, nil, err
	}
	defer cancel()
	output, callErr := c.api.DescribeRouteTables(callContext, &ec2.DescribeRouteTablesInput{
		RouteTableIds: []string{authority.RouteTableID},
	})
	if callErr != nil {
		return model.RouteSnapshot{}, nil, apiFailure(ctx, "DescribeRouteTables", callErr)
	}
	if output == nil || len(output.RouteTables) != 1 || aws.ToString(output.RouteTables[0].RouteTableId) != authority.RouteTableID {
		count := 0
		if output != nil {
			count = len(output.RouteTables)
		}
		return model.RouteSnapshot{}, nil, ineligible(authority.RouteTableID, "route-table-lookup", "one exact route table", exactCount(count))
	}
	routeTable := output.RouteTables[0]
	if aws.ToString(routeTable.VpcId) != authority.VPCID {
		return model.RouteSnapshot{}, nil, ineligible(authority.RouteTableID, "route-table-vpc", authority.VPCID, aws.ToString(routeTable.VpcId))
	}
	if err := validateAssociations(routeTable, authority); err != nil {
		return model.RouteSnapshot{}, nil, err
	}

	capturedAt := c.clock.Now()
	expected := make(map[string]struct{}, len(authority.RemotePrefixes))
	expectedNetworks := make([]netip.Prefix, 0, len(authority.RemotePrefixes))
	for _, prefix := range authority.RemotePrefixes {
		expected[prefix] = struct{}{}
		expectedNetwork, _ := netip.ParsePrefix(prefix)
		expectedNetworks = append(expectedNetworks, expectedNetwork)
	}
	routes := make(map[string]model.RouteSnapshotEntry, len(expected))
	observations := make([]RouteObservation, 0, len(expected))
	for routeIndex := range routeTable.Routes {
		route := &routeTable.Routes[routeIndex]
		if route.DestinationPrefixListId != nil {
			return model.RouteSnapshot{}, observations, ineligible(
				authority.RouteTableID,
				"route-destination-prefix-list",
				"no prefix-list destinations",
				aws.ToString(route.DestinationPrefixListId),
			)
		}
		rawDestination := aws.ToString(route.DestinationCidrBlock)
		canonicalDestination, belongsToAuthority, canonical := authorityDestination(rawDestination, expected, expectedNetworks)
		if !belongsToAuthority {
			continue
		}
		observation := observeRoute(capturedAt, canonicalDestination, route)
		observations = appendObservations(observations, observation)
		if !canonical {
			return model.RouteSnapshot{}, observations, ineligible(canonicalDestination, "route-destination", "canonical CIDR", rawDestination)
		}
		if _, duplicate := routes[canonicalDestination]; duplicate {
			return model.RouteSnapshot{}, observations, ineligible(canonicalDestination, "route-count", "one exact route", "duplicate")
		}
		entry, err := validateRoute(authority, canonicalDestination, route, observation)
		if err != nil {
			return model.RouteSnapshot{}, observations, err
		}
		routes[canonicalDestination] = entry
	}

	snapshot := model.RouteSnapshot{
		RouteTableID: authority.RouteTableID,
		CapturedAt:   capturedAt,
		Routes:       make([]model.RouteSnapshotEntry, 0, len(authority.RemotePrefixes)),
	}
	for _, prefix := range authority.RemotePrefixes {
		route, found := routes[prefix]
		if !found {
			return model.RouteSnapshot{}, observations, ineligible(prefix, "route-presence", "one exact route", "missing")
		}
		snapshot.Routes = append(snapshot.Routes, route)
	}
	if err := snapshot.Validate(authority); err != nil {
		return model.RouteSnapshot{}, observations, ineligible(authority.RouteTableID, "route-snapshot", "valid exact snapshot", "invalid")
	}
	return snapshot, observations, nil
}

func validateAssociations(routeTable types.RouteTable, authority model.DomainAuthority) error {
	activeNonMain := make([]types.RouteTableAssociation, 0, 1)
	activeMain := 0
	for _, association := range routeTable.Associations {
		if association.AssociationState == nil || association.AssociationState.State != types.RouteTableAssociationStateCodeAssociated {
			continue
		}
		if association.Main == nil {
			return ineligible(authority.RouteTableID, "route-table-association", "explicit non-main association", "main flag missing")
		}
		if aws.ToBool(association.Main) {
			activeMain++
		} else {
			activeNonMain = append(activeNonMain, association)
		}
	}
	if len(activeNonMain) != 1 || activeMain != 0 {
		return ineligible(authority.RouteTableID, "route-table-association", "exactly one active non-main association", associationCount(len(activeNonMain), activeMain))
	}
	association := activeNonMain[0]
	if aws.ToString(association.SubnetId) != authority.GWLBESubnetID {
		return ineligible(authority.RouteTableID, "route-table-association-subnet", authority.GWLBESubnetID, aws.ToString(association.SubnetId))
	}
	if aws.ToString(association.RouteTableAssociationId) != authority.RouteTableAssociationID {
		return ineligible(authority.RouteTableID, "route-table-association-id", authority.RouteTableAssociationID, aws.ToString(association.RouteTableAssociationId))
	}
	if aws.ToString(association.RouteTableId) != authority.RouteTableID || aws.ToString(association.GatewayId) != "" {
		return ineligible(authority.RouteTableID, "route-table-association-shape", "exact subnet association", "different association shape")
	}
	return nil
}

func validateRoute(
	authority model.DomainAuthority,
	destination string,
	route *types.Route,
	observation RouteObservation,
) (model.RouteSnapshotEntry, error) {
	target := aws.ToString(route.NetworkInterfaceId)
	if target == "" || routeTargetCount(route) != 1 {
		return model.RouteSnapshotEntry{}, &UnauthorizedError{
			DestinationPrefix: safeField(destination),
			TargetENIID:       "non-eni-target",
			Observations:      []RouteObservation{sanitizedObservation(observation)},
		}
	}
	if !authority.AllowsENI(target) {
		return model.RouteSnapshotEntry{}, &UnauthorizedError{
			DestinationPrefix: safeField(destination),
			TargetENIID:       safeField(target),
			Observations:      []RouteObservation{sanitizedObservation(observation)},
		}
	}
	if reflectedInstance := aws.ToString(route.InstanceId); reflectedInstance != "" {
		owner, found := authorityOwnerByENI(authority, target)
		if !found || reflectedInstance != owner.InstanceID {
			return model.RouteSnapshotEntry{}, &UnauthorizedError{
				DestinationPrefix: safeField(destination),
				TargetENIID:       safeField(target),
				Observations:      []RouteObservation{sanitizedObservation(observation)},
			}
		}
	}
	if route.State != types.RouteStateActive {
		return model.RouteSnapshotEntry{}, ineligible(destination, "route-state", string(types.RouteStateActive), string(route.State))
	}
	if route.Origin != types.RouteOriginCreateRoute {
		return model.RouteSnapshotEntry{}, ineligible(destination, "route-origin", string(types.RouteOriginCreateRoute), string(route.Origin))
	}
	return model.RouteSnapshotEntry{
		DestinationPrefix: destination,
		TargetENIID:       target,
		State:             string(route.State),
		Origin:            string(route.Origin),
	}, nil
}

func routeTargetCount(route *types.Route) int {
	values := []*string{
		route.CarrierGatewayId,
		route.CoreNetworkArn,
		route.EgressOnlyInternetGatewayId,
		route.GatewayId,
		route.IpAddress,
		route.LocalGatewayId,
		route.NatGatewayId,
		route.NetworkInterfaceId,
		route.OdbNetworkArn,
		route.TransitGatewayId,
		route.VpcPeeringConnectionId,
	}
	count := 0
	for _, value := range values {
		if aws.ToString(value) != "" {
			count++
		}
	}
	return count
}

func authorityDestination(raw string, expected map[string]struct{}, expectedNetworks []netip.Prefix) (string, bool, bool) {
	prefix, err := netip.ParsePrefix(raw)
	if err != nil || !prefix.Addr().Is4() {
		return raw, raw != "", false
	}
	canonical := prefix.Masked().String()
	canonicalInput := prefix == prefix.Masked() && raw == canonical
	overlapsAuthority := false
	shadowsAuthority := false
	for _, expectedNetwork := range expectedNetworks {
		if prefix.Overlaps(expectedNetwork) {
			overlapsAuthority = true
			if prefix.Bits() >= expectedNetwork.Bits() {
				shadowsAuthority = true
			}
		}
	}
	if overlapsAuthority && !canonicalInput {
		return canonical, true, false
	}
	if !shadowsAuthority {
		return "", false, false
	}
	_, exact := expected[canonical]
	return canonical, true, exact
}

func authorityOwnerByENI(authority model.DomainAuthority, eniID string) (model.OwnerAuthority, bool) {
	for _, owner := range authority.Owners {
		if owner.ENIID == eniID {
			return owner, true
		}
	}
	return model.OwnerAuthority{}, false
}

func observeRoute(at time.Time, destination string, route *types.Route) RouteObservation {
	return sanitizedObservation(RouteObservation{
		ObservedAt:        at,
		DestinationPrefix: destination,
		TargetENIID:       aws.ToString(route.NetworkInterfaceId),
		State:             string(route.State),
		Origin:            string(route.Origin),
	})
}

func exactPrefix(prefixes []string, candidate string) bool {
	prefix, err := netip.ParsePrefix(candidate)
	if err != nil || !prefix.Addr().Is4() || prefix != prefix.Masked() || prefix.String() != candidate {
		return false
	}
	for _, allowed := range prefixes {
		if candidate == allowed {
			return true
		}
	}
	return false
}

func snapshotRoute(snapshot model.RouteSnapshot, destination string) (model.RouteSnapshotEntry, bool) {
	for _, route := range snapshot.Routes {
		if route.DestinationPrefix == destination {
			return route, true
		}
	}
	return model.RouteSnapshotEntry{}, false
}

func matchingSnapshotEntries(first, second model.RouteSnapshot) bool {
	if first.RouteTableID != second.RouteTableID || len(first.Routes) != len(second.Routes) {
		return false
	}
	for index := range first.Routes {
		if first.Routes[index] != second.Routes[index] {
			return false
		}
	}
	return true
}

func deadlineReached(callerContext, operationContext context.Context, clock Clock, deadline time.Time) bool {
	return callerContext.Err() != nil || operationContext.Err() != nil || !clock.Now().Before(deadline)
}

func preCallDeadlineError(callerContext context.Context, deadline time.Time) error {
	if err := callerContext.Err(); err != nil {
		return err
	}
	return &UnsafeDeadlineError{Deadline: deadline}
}

func newAmbiguousError(result ReplaceResult, reason string, cause error) *AmbiguousError {
	return &AmbiguousError{
		DestinationPrefix: safeField(result.DestinationPrefix),
		PreviousENIID:     safeField(result.PreviousENIID),
		DesiredENIID:      safeField(result.DesiredENIID),
		Reason:            safeField(reason),
		CallFailed:        result.CallAmbiguous,
		Observations:      cloneObservations(result.Observations),
		cause:             cause,
	}
}

func newOscillationError(result ReplaceResult) *OscillationError {
	return &OscillationError{
		DestinationPrefix: safeField(result.DestinationPrefix),
		PreviousENIID:     safeField(result.PreviousENIID),
		DesiredENIID:      safeField(result.DesiredENIID),
		Observations:      cloneObservations(result.Observations),
	}
}

func unstableReadback(reason string) *UnstableReadbackError {
	return &UnstableReadbackError{Reason: safeField(reason)}
}

func associationCount(nonMain, main int) string {
	return boundedErrorf("%d non-main and %d main", nonMain, main)
}
