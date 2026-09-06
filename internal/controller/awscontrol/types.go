package awscontrol

import (
	"time"

	"github.com/jaxxstorm/envelope/internal/controller/model"
)

// OwnerValidation is the provider-independent evidence returned for an
// eligible owner.
type OwnerValidation struct {
	ValidatedAt                     time.Time `json:"validated_at"`
	Region                          string    `json:"region"`
	InstanceID                      string    `json:"instance_id"`
	InstanceState                   string    `json:"instance_state"`
	SystemStatus                    string    `json:"system_status"`
	InstanceStatus                  string    `json:"instance_status"`
	ENIID                           string    `json:"eni_id"`
	ENIStatus                       string    `json:"eni_status"`
	AttachmentStatus                string    `json:"attachment_status"`
	InstanceSourceDestCheckDisabled bool      `json:"instance_source_destination_check_disabled"`
	ENISourceDestCheckDisabled      bool      `json:"eni_source_destination_check_disabled"`
	VPCID                           string    `json:"vpc_id"`
	SubnetID                        string    `json:"subnet_id"`
	AvailabilityZone                string    `json:"availability_zone"`
}

// RouteObservation is a bounded, redacted authoritative route read. Error
// values retain at most MaxObservedRoutes observations.
type RouteObservation struct {
	ObservedAt        time.Time `json:"observed_at"`
	DestinationPrefix string    `json:"destination_prefix"`
	TargetENIID       string    `json:"target_eni_id,omitempty"`
	State             string    `json:"state,omitempty"`
	Origin            string    `json:"origin,omitempty"`
}

// Settlement identifies the target on which post-call reads stabilized.
type Settlement string

const (
	SettlementDesired  Settlement = "desired"
	SettlementPrevious Settlement = "previous"
)

// ReplaceResult describes one exact-prefix mutation attempt without retaining
// an AWS response or raw AWS error.
type ReplaceResult struct {
	StartedAt         time.Time           `json:"started_at"`
	CompletedAt       time.Time           `json:"completed_at,omitempty"`
	DestinationPrefix string              `json:"destination_prefix"`
	DesiredENIID      string              `json:"desired_eni_id"`
	PreviousENIID     string              `json:"previous_eni_id,omitempty"`
	ObservedENIID     string              `json:"observed_eni_id,omitempty"`
	CallAttempted     bool                `json:"call_attempted"`
	CallAmbiguous     bool                `json:"call_ambiguous"`
	Settlement        Settlement          `json:"settlement,omitempty"`
	Before            model.RouteSnapshot `json:"before"`
	Observations      []RouteObservation  `json:"observations,omitempty"`
}
