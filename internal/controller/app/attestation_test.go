package app

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jaxxstorm/envelope/internal/controller/attestation"
	"github.com/jaxxstorm/envelope/internal/controller/awscontrol"
	"github.com/jaxxstorm/envelope/internal/controller/config"
	"github.com/jaxxstorm/envelope/internal/controller/model"
)

type countedAttestationRoutes struct {
	fakeRouteController
	mutations int
}

func (r *countedAttestationRoutes) ReplaceAndWait(context.Context, model.DomainAuthority, string, string, string, time.Time) (awscontrol.ReplaceResult, error) {
	r.mutations++
	return awscontrol.ReplaceResult{}, nil
}

func TestRuntimeAttestationGatesEligibilityAndEveryRouteCall(t *testing.T) {
	topology, err := config.ParseFile("../../../deploy/terraform/envelope-controller/tests/fixtures/topology.json")
	if err != nil {
		t.Fatal(err)
	}
	authority, err := topology.DomainAuthority(topology.Domains[0].ID)
	if err != nil {
		t.Fatal(err)
	}
	owner := authority.Owners[0]
	for _, mode := range []string{"fresh", "expired", "rejected", "changed-before-call"} {
		t.Run(mode, func(t *testing.T) {
			cloud := &countedAttestationRoutes{}
			checks := 0
			routes := attestedRoutes{RouteController: cloud, check: func(_ context.Context, a model.DomainAuthority, o model.OwnerAuthority) (time.Time, error) {
				checks++
				if a.TopologyHash != authority.TopologyHash || o != owner {
					t.Fatal("attestation scope changed")
				}
				if mode == "rejected" || (mode == "changed-before-call" && checks > 1) {
					return time.Time{}, attestation.ErrRejected
				}
				if mode == "expired" {
					return time.Now().Add(-time.Second), nil
				}
				return time.Now().Add(time.Minute), nil
			}}
			_, eligibilityErr := routes.ValidateOwner(context.Background(), authority, owner)
			_, mutationErr := routes.ReplaceAndWait(context.Background(), authority, authority.RemotePrefixes[0], authority.Owners[1].ENIID, owner.ENIID, time.Now().Add(time.Minute))
			if mode == "fresh" {
				if eligibilityErr != nil || mutationErr != nil || cloud.mutations != 1 {
					t.Fatal("fresh attestation failed")
				}
			} else {
				if !errors.Is(mutationErr, attestation.ErrRejected) || cloud.mutations != 0 {
					t.Fatal("ineligible router received route mutation")
				}
				if mode == "changed-before-call" && eligibilityErr != nil {
					t.Fatal("initial valid attestation rejected")
				}
			}
			if checks != 2 {
				t.Fatalf("cached attestation reused: %d", checks)
			}
		})
	}
}
