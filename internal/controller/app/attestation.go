package app

import (
	"context"
	"time"

	"github.com/jaxxstorm/envelope/internal/controller/attestation"
	"github.com/jaxxstorm/envelope/internal/controller/awscontrol"
	"github.com/jaxxstorm/envelope/internal/controller/model"
	"github.com/jaxxstorm/envelope/internal/controller/reconcile"
)

type attestedRoutes struct {
	reconcile.RouteController
	check func(context.Context, model.DomainAuthority, model.OwnerAuthority) (time.Time, error)
}

func (r attestedRoutes) ValidateOwner(ctx context.Context, a model.DomainAuthority, o model.OwnerAuthority) (awscontrol.OwnerValidation, error) {
	validation, err := r.RouteController.ValidateOwner(ctx, a, o)
	if err != nil {
		return validation, err
	}
	expires, err := r.check(ctx, a, o)
	if err != nil || !expires.After(time.Now()) {
		return awscontrol.OwnerValidation{}, attestation.ErrRejected
	}
	return validation, nil
}

func (r attestedRoutes) StableSnapshot(ctx context.Context, a model.DomainAuthority, deadline time.Time) (model.RouteSnapshot, error) {
	reader, ok := r.RouteController.(interface {
		StableSnapshot(context.Context, model.DomainAuthority, time.Time) (model.RouteSnapshot, error)
	})
	if !ok {
		return model.RouteSnapshot{}, attestation.ErrRejected
	}
	return reader.StableSnapshot(ctx, a, deadline)
}

func (r attestedRoutes) ReplaceAndWait(ctx context.Context, a model.DomainAuthority, prefix, previous, desired string, deadline time.Time) (awscontrol.ReplaceResult, error) {
	var owner model.OwnerAuthority
	for _, candidate := range a.Owners {
		if candidate.ENIID == desired {
			owner = candidate
		}
	}
	if owner.RouterID == "" {
		return awscontrol.ReplaceResult{}, attestation.ErrRejected
	}
	call, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	expires, err := r.check(call, a, owner)
	if err != nil || call.Err() != nil || !expires.After(time.Now()) {
		return awscontrol.ReplaceResult{}, attestation.ErrRejected
	}
	mutator, ok := r.RouteController.(interface {
		ReplaceAndWait(context.Context, model.DomainAuthority, string, string, string, time.Time) (awscontrol.ReplaceResult, error)
	})
	if !ok {
		return awscontrol.ReplaceResult{}, ErrRunnerMutationDisabled
	}
	return mutator.ReplaceAndWait(call, a, prefix, previous, desired, deadline)
}
