package store

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/jaxxstorm/envelope/internal/controller/model"
)

// DeploymentLock has no TTL and no automatic takeover. A lost response or dead
// deployment process must not allow a second external rollout to overlap it.
type DeploymentLock struct {
	DeploymentID string `json:"deployment_id"`
	TopologyHash string `json:"topology_hash"`
	OperationID  string `json:"operation_id"`
	Kind         string `json:"kind"`
	Phase        string `json:"phase"`
	ReplicaID    string `json:"replica_id,omitempty"`
}

func (l DeploymentLock) Validate() error {
	if (ObservationScope{DeploymentID: l.DeploymentID, TopologyHash: l.TopologyHash}).Validate() != nil || validateIdentifier("operation", l.OperationID) != nil {
		return ErrConflict
	}
	switch l.Kind {
	case "activate", "deactivate", "migrate", "rollout":
	default:
		return ErrConflict
	}
	switch l.Phase {
	case "locked", "quiescent", "applying", "verified", "complete":
	default:
		return ErrConflict
	}
	if l.Kind == "rollout" && validateIdentifier("replica", l.ReplicaID) != nil {
		return ErrConflict
	}
	return nil
}

func lifecycleKey(deployment string) map[string]types.AttributeValue {
	return map[string]types.AttributeValue{"pk": stringAttribute("lifecycle#" + deployment), "sk": stringAttribute("lock")}
}

func lockPayload(lock DeploymentLock) string {
	payload, _ := json.Marshal(lock)
	return string(payload)
}

func (s *DynamoDBStore) BeginDeployment(ctx context.Context, lock DeploymentLock) error {
	if lock.Validate() != nil || lock.Phase != "locked" {
		return ErrConflict
	}
	item := lifecycleKey(lock.DeploymentID)
	item["payload"], item["phase"] = stringAttribute(lockPayload(lock)), stringAttribute(lock.Phase)
	_, err := s.putItem(ctx, &dynamodb.PutItemInput{TableName: aws.String(s.tableName), Item: item,
		ConditionExpression:       aws.String("attribute_not_exists(#pk) OR #phase = :complete"),
		ExpressionAttributeNames:  map[string]string{"#pk": "pk", "#phase": "phase"},
		ExpressionAttributeValues: map[string]types.AttributeValue{":complete": stringAttribute("complete")}})
	if err != nil {
		return ErrConflict
	}
	return nil
}

func (s *DynamoDBStore) ReadDeployment(ctx context.Context, deployment string) (DeploymentLock, error) {
	if validateIdentifier("deployment", deployment) != nil {
		return DeploymentLock{}, ErrConflict
	}
	output, err := s.getItem(ctx, &dynamodb.GetItemInput{TableName: aws.String(s.tableName), Key: lifecycleKey(deployment), ConsistentRead: aws.Bool(true)})
	if err != nil || output == nil || len(output.Item) != 4 {
		return DeploymentLock{}, ErrConflict
	}
	var lock DeploymentLock
	payload, err := requiredStringAttribute(output.Item, "payload")
	if err != nil || strictJSONDecode([]byte(payload), &lock) != nil || lock.Validate() != nil || lock.DeploymentID != deployment ||
		requireStringValue(output.Item, "pk", "lifecycle#"+deployment) != nil || requireStringValue(output.Item, "sk", "lock") != nil || requireStringValue(output.Item, "phase", lock.Phase) != nil {
		return DeploymentLock{}, ErrConflict
	}
	return lock, nil
}

func (s *DynamoDBStore) AdvanceDeployment(ctx context.Context, before, after DeploymentLock) error {
	unchanged := after
	unchanged.Phase = before.Phase
	if before.Validate() != nil || after.Validate() != nil || before.Phase == "complete" || unchanged != before {
		return ErrConflict
	}
	item := lifecycleKey(before.DeploymentID)
	item["payload"], item["phase"] = stringAttribute(lockPayload(after)), stringAttribute(after.Phase)
	_, err := s.putItem(ctx, &dynamodb.PutItemInput{TableName: aws.String(s.tableName), Item: item,
		ConditionExpression: aws.String("#payload = :before"), ExpressionAttributeNames: map[string]string{"#payload": "payload"},
		ExpressionAttributeValues: map[string]types.AttributeValue{":before": stringAttribute(lockPayload(before))}})
	if err != nil {
		return ErrConflict
	}
	return nil
}

// RewriteDeploymentDomains is deployment-only, not part of the controller Store
// interface. The exact lock and complete old documents guard one atomic rewrite.
// The operation never accepts a changed journal except stable quiescent migration.
func (s *DynamoDBStore) RewriteDeploymentDomains(ctx context.Context, lock DeploymentLock, before, after []*model.DomainState) error {
	api, ok := s.api.(interface {
		TransactWriteItems(context.Context, *dynamodb.TransactWriteItemsInput, ...func(*dynamodb.Options)) (*dynamodb.TransactWriteItemsOutput, error)
	})
	if !ok || lock.Validate() != nil || lock.Phase == "complete" || len(before) == 0 || len(before) > 32 || len(before) != len(after) {
		return ErrConflict
	}
	items := []types.TransactWriteItem{{ConditionCheck: &types.ConditionCheck{TableName: aws.String(s.tableName), Key: lifecycleKey(lock.DeploymentID),
		ConditionExpression: aws.String("#payload = :lock"), ExpressionAttributeNames: map[string]string{"#payload": "payload"}, ExpressionAttributeValues: map[string]types.AttributeValue{":lock": stringAttribute(lockPayload(lock))}}}}
	seen := map[string]bool{}
	for i, old := range before {
		next := after[i]
		if old == nil || next == nil || old.Validate() != nil || next.Validate() != nil || old.Authority.DeploymentID != lock.DeploymentID || old.Authority.TopologyHash != lock.TopologyHash ||
			next.Authority.DeploymentID != lock.DeploymentID || next.Authority.DomainID != old.Authority.DomainID || seen[old.Authority.DomainID] || next.Revision != old.Revision || next.FenceTerm != old.FenceTerm {
			return ErrConflict
		}
		seen[old.Authority.DomainID] = true
		copy := next.Clone()
		copy.Activated, copy.UpdatedAt = old.Activated, old.UpdatedAt
		switch lock.Kind {
		case "activate":
			copy.Lease = old.Lease
			if len(before) != 1 || old.Activated || !next.Activated || old.Phase != model.PhaseStable || next.Lease != nil || (old.Lease != nil && old.Lease.ExpiresAt.After(s.clock.Now())) || !reflect.DeepEqual(copy, old) {
				return ErrConflict
			}
		case "deactivate":
			if next.Activated || !reflect.DeepEqual(copy, old) {
				return ErrConflict
			}
		case "migrate":
			if lock.Phase == "locked" {
				if next.Activated || !reflect.DeepEqual(copy, old) {
					return ErrConflict
				}
				break
			}
			if lock.Phase != "quiescent" || old.Activated || next.Activated || old.Phase != model.PhaseStable || old.Intent != nil || old.Error != nil || next.Phase != model.PhaseStable || next.Lease != nil ||
				(old.Lease != nil && old.Lease.ExpiresAt.After(s.clock.Now())) || next.Authority.TopologyHash == old.Authority.TopologyHash {
				return ErrConflict
			}
		default:
			return ErrConflict
		}
		record, err := s.loadDomainRecord(ctx, old.Authority.DeploymentID, old.Authority.DomainID)
		if err != nil || !reflect.DeepEqual(record.state, old) {
			return ErrConflict
		}
		version, err := incrementItemVersion(record.itemVersion)
		if err != nil || uint64(old.Revision) == ^uint64(0) {
			return ErrConflict
		}
		candidate := next.Clone()
		candidate.Revision++
		if candidate.Validate() != nil {
			return ErrConflict
		}
		item, err := encodeDomainItem(candidate, version)
		if err != nil {
			return ErrConflict
		}
		items = append(items, types.TransactWriteItem{Put: &types.Put{TableName: aws.String(s.tableName), Item: item,
			ConditionExpression: aws.String("#payload = :old AND #version = :version"), ExpressionAttributeNames: map[string]string{"#payload": "payload", "#version": "item_version"},
			ExpressionAttributeValues: map[string]types.AttributeValue{":old": stringAttribute(record.payload), ":version": numberAttribute(record.itemVersion)}}})
	}
	call, cancel := context.WithTimeout(ctx, s.apiTimeout)
	defer cancel()
	_, err := api.TransactWriteItems(call, &dynamodb.TransactWriteItemsInput{TransactItems: items})
	if err != nil || call.Err() != nil {
		return errors.New("deployment transaction uncertain or rejected; retain lock and inspect journals")
	}
	return nil
}
