// Package awscontrol validates EC2 owner eligibility and reconciles exact,
// allowlisted route targets without exposing AWS SDK types to the reconciler.
package awscontrol

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/jaxxstorm/envelope/internal/controller/model"
)

const (
	defaultAPITimeout       = 5 * time.Second
	defaultPollInterval     = 250 * time.Millisecond
	defaultStableReads      = 2
	defaultOscillationLimit = 2
)

// EC2API is the complete AWS surface used by Controller. *ec2.Client satisfies
// this interface, and tests can provide a narrow fake.
type EC2API interface {
	DescribeInstances(context.Context, *ec2.DescribeInstancesInput, ...func(*ec2.Options)) (*ec2.DescribeInstancesOutput, error)
	DescribeInstanceStatus(context.Context, *ec2.DescribeInstanceStatusInput, ...func(*ec2.Options)) (*ec2.DescribeInstanceStatusOutput, error)
	DescribeNetworkInterfaces(context.Context, *ec2.DescribeNetworkInterfacesInput, ...func(*ec2.Options)) (*ec2.DescribeNetworkInterfacesOutput, error)
	DescribeRouteTables(context.Context, *ec2.DescribeRouteTablesInput, ...func(*ec2.Options)) (*ec2.DescribeRouteTablesOutput, error)
	ReplaceRoute(context.Context, *ec2.ReplaceRouteInput, ...func(*ec2.Options)) (*ec2.ReplaceRouteOutput, error)
}

var _ EC2API = (*ec2.Client)(nil)

// Clock supplies wall time used for result timestamps and hard-deadline checks.
type Clock interface {
	Now() time.Time
}

// Sleeper performs cancelable convergence waits.
type Sleeper interface {
	Sleep(context.Context, time.Duration) error
}

type realClock struct{}

func (realClock) Now() time.Time { return time.Now() }

type realSleeper struct{}

func (realSleeper) Sleep(ctx context.Context, duration time.Duration) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

// Option configures bounded API calls and convergence polling.
type Option func(*Controller) error

// WithClock injects the clock used for timestamps and deadline checks.
func WithClock(clock Clock) Option {
	return func(controller *Controller) error {
		if isNil(clock) {
			return errors.New("awscontrol: clock is nil")
		}
		controller.clock = clock
		return nil
	}
}

// WithSleeper injects the cancelable poll sleeper.
func WithSleeper(sleeper Sleeper) Option {
	return func(controller *Controller) error {
		if isNil(sleeper) {
			return errors.New("awscontrol: sleeper is nil")
		}
		controller.sleeper = sleeper
		return nil
	}
}

// WithAPITimeout bounds every individual EC2 request.
func WithAPITimeout(timeout time.Duration) Option {
	return func(controller *Controller) error {
		if timeout <= 0 {
			return errors.New("awscontrol: API timeout must be positive")
		}
		controller.apiTimeout = timeout
		return nil
	}
}

// WithPollInterval configures the delay between authoritative route reads.
func WithPollInterval(interval time.Duration) Option {
	return func(controller *Controller) error {
		if interval <= 0 {
			return errors.New("awscontrol: poll interval must be positive")
		}
		controller.pollInterval = interval
		return nil
	}
}

// WithStableReads sets the number of consecutive identical reads required for
// route settlement.
func WithStableReads(reads int) Option {
	return func(controller *Controller) error {
		if reads < 2 {
			return errors.New("awscontrol: stable reads must be at least two")
		}
		controller.stableReads = reads
		return nil
	}
}

// WithOscillationLimit sets the number of target reversals that fail closed.
func WithOscillationLimit(transitions int) Option {
	return func(controller *Controller) error {
		if transitions < 1 {
			return errors.New("awscontrol: oscillation limit must be positive")
		}
		controller.oscillationLimit = transitions
		return nil
	}
}

// Controller binds one EC2 client to the exact Region it was configured for.
type Controller struct {
	api              EC2API
	region           string
	clock            Clock
	sleeper          Sleeper
	apiTimeout       time.Duration
	pollInterval     time.Duration
	stableReads      int
	oscillationLimit int
}

// New constructs a bounded EC2 controller. region must be the Region used to
// configure api; every authority and owner is checked against this binding.
func New(api EC2API, region string, options ...Option) (*Controller, error) {
	if isNil(api) {
		return nil, errors.New("awscontrol: EC2 API is nil")
	}
	if err := validateRegion(region); err != nil {
		return nil, err
	}
	controller := &Controller{
		api:              api,
		region:           region,
		clock:            realClock{},
		sleeper:          realSleeper{},
		apiTimeout:       defaultAPITimeout,
		pollInterval:     defaultPollInterval,
		stableReads:      defaultStableReads,
		oscillationLimit: defaultOscillationLimit,
	}
	for _, option := range options {
		if option == nil {
			return nil, errors.New("awscontrol: option is nil")
		}
		if err := option(controller); err != nil {
			return nil, err
		}
	}
	return controller, nil
}

func validateRegion(region string) error {
	if region == "" || region != strings.TrimSpace(region) || len(region) > maxObservedFieldLength {
		return errors.New("awscontrol: Region is invalid")
	}
	parts := strings.Split(region, "-")
	if len(parts) < 3 || region[0] < 'a' || region[0] > 'z' {
		return errors.New("awscontrol: Region is invalid")
	}
	for index, part := range parts {
		if part == "" {
			return errors.New("awscontrol: Region is invalid")
		}
		for _, character := range part {
			letter := character >= 'a' && character <= 'z'
			digit := character >= '0' && character <= '9'
			if !letter && !digit || index == len(parts)-1 && !digit {
				return errors.New("awscontrol: Region is invalid")
			}
		}
	}
	return nil
}

func (c *Controller) validateAuthority(ctx context.Context, authority model.DomainAuthority) error {
	if ctx == nil {
		return &InputError{Field: "context", Problem: "nil"}
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := authority.Validate(); err != nil {
		return &InputError{Field: "authority", Problem: "invalid"}
	}
	if authority.Region != c.region {
		return ineligible(authority.DomainID, "region", c.region, authority.Region)
	}
	return nil
}

func (c *Controller) apiContext(ctx context.Context, deadline time.Time) (context.Context, context.CancelFunc, error) {
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	timeout := c.apiTimeout
	if !deadline.IsZero() {
		remaining := deadline.Sub(c.clock.Now())
		if remaining <= 0 {
			return nil, nil, context.DeadlineExceeded
		}
		if remaining < timeout {
			timeout = remaining
		}
	}
	callContext, cancel := context.WithTimeout(ctx, timeout)
	return callContext, cancel, nil
}

func (c *Controller) operationContext(ctx context.Context, deadline time.Time) (context.Context, context.CancelFunc, error) {
	if ctx == nil {
		return nil, nil, &InputError{Field: "context", Problem: "nil"}
	}
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	if deadline.IsZero() {
		return nil, nil, &InputError{Field: "deadline", Problem: "zero"}
	}
	remaining := deadline.Sub(c.clock.Now())
	if remaining <= 0 {
		return nil, nil, &UnsafeDeadlineError{Deadline: deadline}
	}
	operationContext, cancel := context.WithTimeout(ctx, remaining)
	return operationContext, cancel, nil
}

func apiFailure(ctx context.Context, operation string, _ error) error {
	if contextError := ctx.Err(); contextError != nil {
		return contextError
	}
	return &APIError{Operation: operation}
}

func requireExactOwner(authority model.DomainAuthority, owner model.OwnerAuthority) error {
	configured, found := authority.OwnerByStableNode(owner.StableNodeID)
	if !found || configured != owner {
		return ineligible(owner.RouterID, "owner-authority", "exact configured owner", "outside authority")
	}
	return nil
}

func requireController(controller *Controller) error {
	if controller == nil || isNil(controller.api) || isNil(controller.clock) || isNil(controller.sleeper) {
		return fmt.Errorf("awscontrol: controller is not initialized")
	}
	return nil
}

func isNil(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}
