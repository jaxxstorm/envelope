package store

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"reflect"
	"sort"
	"strconv"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/jaxxstorm/envelope/internal/controller/model"
	"github.com/jaxxstorm/envelope/internal/controller/strictjson"
)

const (
	dynamoDBItemLimit          = 400 * 1024
	maxObservationResults      = 100
	maxObservationListingBytes = 4 * 1024 * 1024
	itemSchemaVersion          = uint64(1)

	attributePartitionKey       = "pk"
	attributeSortKey            = "sk"
	attributeSchemaVersion      = "schema_version"
	attributeRecordType         = "record_type"
	attributeDeploymentID       = "deployment_id"
	attributeDomainID           = "domain_id"
	attributeControllerID       = "controller_id"
	attributeTopologyHash       = "topology_hash"
	attributeDocumentRevision   = "document_revision"
	attributeItemVersion        = "item_version"
	attributeFenceTerm          = "fence_term"
	attributeLeaseHolder        = "lease_holder"
	attributeLeaseFenceTerm     = "lease_fence_term"
	attributeLeaseRecordVersion = "lease_record_version"
	attributeLeaseExpiresAt     = "lease_expires_at_unix_nano"
	attributeSequence           = "sequence"
	attributeTTL                = "ttl"
	attributePayload            = "payload"

	recordTypeDomain      = "domain"
	recordTypeObservation = "observation"
)

var (
	domainBaseAttributes = map[string]struct{}{
		attributePartitionKey:     {},
		attributeSortKey:          {},
		attributeSchemaVersion:    {},
		attributeRecordType:       {},
		attributeDeploymentID:     {},
		attributeDomainID:         {},
		attributeTopologyHash:     {},
		attributeDocumentRevision: {},
		attributeItemVersion:      {},
		attributeFenceTerm:        {},
		attributePayload:          {},
	}
	domainLeaseAttributes = []string{
		attributeLeaseHolder,
		attributeLeaseFenceTerm,
		attributeLeaseRecordVersion,
		attributeLeaseExpiresAt,
	}
	observationAttributes = map[string]struct{}{
		attributePartitionKey:  {},
		attributeSortKey:       {},
		attributeSchemaVersion: {},
		attributeRecordType:    {},
		attributeDeploymentID:  {},
		attributeControllerID:  {},
		attributeTopologyHash:  {},
		attributeSequence:      {},
		attributeTTL:           {},
		attributePayload:       {},
	}
)

// dynamoDBAPI is the subset of the AWS SDK client used by DynamoDBStore.
type dynamoDBAPI interface {
	GetItem(context.Context, *dynamodb.GetItemInput, ...func(*dynamodb.Options)) (*dynamodb.GetItemOutput, error)
	PutItem(context.Context, *dynamodb.PutItemInput, ...func(*dynamodb.Options)) (*dynamodb.PutItemOutput, error)
}

// DynamoDBStore is the production Store backed by one DynamoDB table. A domain
// payload and its conditionable lease metadata share one item; item_version
// serializes lease and state changes without changing the document revision.
type DynamoDBStore struct {
	api              dynamoDBAPI
	tableName        string
	clock            Clock
	apiTimeout       time.Duration
	allowedObservers map[observationKey]struct{}
}

type dynamoDomainRecord struct {
	state       *model.DomainState
	itemVersion uint64
	payload     string
}

var (
	_ Store       = (*DynamoDBStore)(nil)
	_ dynamoDBAPI = (*dynamodb.Client)(nil)
)

// NewDynamoDBStore creates a store for a table with string partition and sort
// keys named "pk" and "sk". apiTimeout bounds each individual GetItem or
// PutItem invocation. Adapter-owned deadlines return ErrAPITimeout; cancellation
// or deadlines inherited from the caller retain their context error identity.
// The table TTL attribute, when enabled, must be named "ttl"; only observation
// items contain it.
func NewDynamoDBStore(api dynamoDBAPI, tableName string, clock Clock, apiTimeout time.Duration, allowedObservers ...ObserverIdentity) (*DynamoDBStore, error) {
	if api == nil {
		return nil, errors.New("store: DynamoDB API is nil")
	}
	if err := validateIdentifier("DynamoDB table", tableName); err != nil {
		return nil, fmt.Errorf("store: %w", err)
	}
	if clock == nil {
		return nil, errors.New("store: clock is nil")
	}
	if apiTimeout <= 0 {
		return nil, errors.New("store: DynamoDB API timeout must be positive")
	}

	allowed := make(map[observationKey]struct{}, len(allowedObservers))
	counts := make(map[ObservationScope]int)
	for index, observer := range allowedObservers {
		if err := observer.Validate(); err != nil {
			return nil, fmt.Errorf("store: allowed observer %d: %w", index, err)
		}
		key := observationKey{
			deploymentID: observer.DeploymentID,
			topologyHash: observer.TopologyHash,
			controllerID: observer.ControllerID,
		}
		if _, exists := allowed[key]; exists {
			return nil, fmt.Errorf("store: duplicate allowed observer %q for deployment %q and topology %q", observer.ControllerID, observer.DeploymentID, observer.TopologyHash)
		}
		allowed[key] = struct{}{}

		scope := ObservationScope{DeploymentID: observer.DeploymentID, TopologyHash: observer.TopologyHash}
		counts[scope]++
		if counts[scope] > maxObservationResults {
			return nil, fmt.Errorf("store: observation scope %q/%q exceeds %d allowed controllers", scope.DeploymentID, scope.TopologyHash, maxObservationResults)
		}
	}

	return &DynamoDBStore{
		api:              api,
		tableName:        tableName,
		clock:            clock,
		apiTimeout:       apiTimeout,
		allowedObservers: allowed,
	}, nil
}

func (s *DynamoDBStore) getItem(ctx context.Context, input *dynamodb.GetItemInput) (*dynamodb.GetItemOutput, error) {
	callContext, cancel := context.WithTimeout(ctx, s.apiTimeout)
	defer cancel()
	output, err := s.api.GetItem(callContext, input)
	if callerErr := ctx.Err(); callerErr != nil {
		return nil, callerErr
	}
	if callErr := callContext.Err(); callErr != nil {
		return nil, &APITimeoutError{Operation: "DynamoDB GetItem"}
	}
	return output, err
}

func (s *DynamoDBStore) putItem(ctx context.Context, input *dynamodb.PutItemInput) (*dynamodb.PutItemOutput, error) {
	callContext, cancel := context.WithTimeout(ctx, s.apiTimeout)
	defer cancel()
	output, err := s.api.PutItem(callContext, input)
	if callerErr := ctx.Err(); callerErr != nil {
		return nil, callerErr
	}
	if callErr := callContext.Err(); callErr != nil {
		return nil, &APITimeoutError{Operation: "DynamoDB PutItem"}
	}
	return output, err
}

func (s *DynamoDBStore) CreateDomain(ctx context.Context, initial *model.DomainState) (*model.DomainState, error) {
	if err := contextError(ctx); err != nil {
		return nil, err
	}
	if initial == nil {
		return nil, errors.New("store: initial domain state is nil")
	}
	candidate := initial.Clone()
	if err := candidate.Validate(); err != nil {
		return nil, fmt.Errorf("store: validate initial domain state: %w", err)
	}
	if candidate.Revision != 1 {
		return nil, errors.New("store: initial domain revision must be one")
	}
	if candidate.FenceTerm != 0 || candidate.Lease != nil {
		return nil, errors.New("store: initial domain state must be lease-free at fence zero")
	}
	if candidate.Phase != model.PhaseStable {
		return nil, errors.New("store: initial domain state must be stable")
	}

	ref := DomainRefFor(candidate.Authority)
	if err := ref.Validate(); err != nil {
		return nil, fmt.Errorf("store: validate initial domain identity: %w", err)
	}
	item, err := encodeDomainItem(candidate, 1)
	if err != nil {
		return nil, fmt.Errorf("store: encode domain %s: %w", ref, err)
	}

	_, err = s.putItem(ctx, &dynamodb.PutItemInput{
		TableName:           aws.String(s.tableName),
		Item:                item,
		ConditionExpression: aws.String("attribute_not_exists(#pk)"),
		ExpressionAttributeNames: map[string]string{
			"#pk": attributePartitionKey,
		},
		ReturnValuesOnConditionCheckFailure: types.ReturnValuesOnConditionCheckFailureAllOld,
	})
	if err == nil {
		return candidate.Clone(), nil
	}
	existingItem, conditional := conditionalFailureItem(err)
	if !conditional {
		return nil, fmt.Errorf("store: create domain %s: %w", ref, err)
	}

	existing, loadErr := s.domainAfterConditionalFailure(ctx, ref, existingItem)
	if loadErr == nil {
		if existing.state.Authority.TopologyHash != ref.TopologyHash {
			return nil, topologyMismatch("domain "+ref.String(), existing.state.Authority.TopologyHash, ref.TopologyHash)
		}
	} else if !errors.Is(loadErr, ErrNotFound) {
		return nil, loadErr
	}
	return nil, &ConflictError{Resource: "domain " + ref.String()}
}

func (s *DynamoDBStore) LoadDomain(ctx context.Context, ref DomainRef) (*model.DomainState, error) {
	if err := contextError(ctx); err != nil {
		return nil, err
	}
	if err := ref.Validate(); err != nil {
		return nil, fmt.Errorf("store: validate domain reference: %w", err)
	}

	record, err := s.loadDomainRecord(ctx, ref.DeploymentID, ref.DomainID)
	if err != nil {
		return nil, err
	}
	if record.state.Authority.TopologyHash != ref.TopologyHash {
		return nil, topologyMismatch("domain "+ref.String(), record.state.Authority.TopologyHash, ref.TopologyHash)
	}
	return record.state.Clone(), nil
}

func (s *DynamoDBStore) CompareAndSwapDomain(ctx context.Context, ref DomainRef, expectedRevision model.DocumentRevision, token LeaseToken, next *model.DomainState) (*model.DomainState, error) {
	if err := contextError(ctx); err != nil {
		return nil, err
	}
	if err := ref.Validate(); err != nil {
		return nil, fmt.Errorf("store: validate domain reference: %w", err)
	}
	if expectedRevision == 0 {
		return nil, errors.New("store: expected domain revision must be positive")
	}
	if err := token.Validate(); err != nil {
		return nil, fmt.Errorf("store: validate lease token: %w", err)
	}
	if next == nil {
		return nil, errors.New("store: next domain state is nil")
	}
	candidate := next.Clone()
	if candidate.Revision != expectedRevision {
		return nil, &ConflictError{
			Resource: "candidate domain revision",
			Expected: fmt.Sprint(expectedRevision),
			Actual:   fmt.Sprint(candidate.Revision),
		}
	}
	if candidate.Authority.TopologyHash != ref.TopologyHash {
		return nil, topologyMismatch("candidate domain "+ref.String(), ref.TopologyHash, candidate.Authority.TopologyHash)
	}
	if candidate.Authority.DeploymentID != ref.DeploymentID || candidate.Authority.DomainID != ref.DomainID {
		return nil, errors.New("store: candidate domain identity does not match its reference")
	}

	current, err := s.loadDomainForWrite(ctx, ref)
	if err != nil {
		return nil, err
	}
	if current.state.Revision != expectedRevision {
		return nil, domainRevisionConflict(ref, expectedRevision, current.state.Revision)
	}
	now := s.clock.Now()
	if !leaseMatches(current.state.Lease, token) || !leaseActive(current.state.Lease, now) {
		return nil, leaseLost(ref, token, current.state.Lease)
	}
	if !reflect.DeepEqual(candidate.Authority, current.state.Authority) {
		return nil, &ConflictError{Resource: "immutable authority for domain " + ref.String()}
	}
	if candidate.Activated != current.state.Activated {
		return nil, ErrDomainInactive
	}
	if candidate.FenceTerm != current.state.FenceTerm || !reflect.DeepEqual(candidate.Lease, current.state.Lease) {
		return nil, leaseLost(ref, token, current.state.Lease)
	}
	if candidate.UpdatedAt.Before(current.state.UpdatedAt) {
		return nil, &ConflictError{
			Resource: "domain " + ref.String() + " update timestamp",
			Expected: "at or after " + current.state.UpdatedAt.Format(time.RFC3339Nano),
			Actual:   candidate.UpdatedAt.Format(time.RFC3339Nano),
		}
	}
	if current.state.Revision == model.DocumentRevision(math.MaxUint64) {
		return nil, errors.New("store: domain revision exhausted")
	}
	itemVersion, err := incrementItemVersion(current.itemVersion)
	if err != nil {
		return nil, err
	}
	candidate.Revision = current.state.Revision + 1
	if err := candidate.Validate(); err != nil {
		return nil, fmt.Errorf("store: validate domain update: %w", err)
	}
	item, err := encodeDomainItem(candidate, itemVersion)
	if err != nil {
		return nil, fmt.Errorf("store: encode domain %s update: %w", ref, err)
	}
	nowUnixNano, err := checkedUnixNano(now)
	if err != nil {
		return nil, fmt.Errorf("store: encode lease comparison time: %w", err)
	}

	_, err = s.putItem(ctx, &dynamodb.PutItemInput{
		TableName: aws.String(s.tableName),
		Item:      item,
		ConditionExpression: aws.String(
			"#record_type = :record_type AND #topology_hash = :topology_hash AND #item_version = :item_version AND #document_revision = :document_revision AND #fence_term = :fence_term AND #lease_holder = :lease_holder AND #lease_fence_term = :lease_fence_term AND #lease_record_version = :lease_record_version AND #lease_expires_at > :now",
		),
		ExpressionAttributeNames: domainConditionNames(
			attributeLeaseHolder,
			attributeLeaseFenceTerm,
			attributeLeaseRecordVersion,
			attributeLeaseExpiresAt,
		),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":record_type":          stringAttribute(recordTypeDomain),
			":topology_hash":        stringAttribute(ref.TopologyHash),
			":item_version":         numberAttribute(current.itemVersion),
			":document_revision":    numberAttribute(uint64(expectedRevision)),
			":fence_term":           numberAttribute(uint64(token.FenceTerm)),
			":lease_holder":         stringAttribute(token.HolderID),
			":lease_fence_term":     numberAttribute(uint64(token.FenceTerm)),
			":lease_record_version": numberAttribute(token.RecordVersion),
			":now":                  signedNumberAttribute(nowUnixNano),
		},
		ReturnValuesOnConditionCheckFailure: types.ReturnValuesOnConditionCheckFailureAllOld,
	})
	if err == nil {
		return candidate.Clone(), nil
	}
	existingItem, conditional := conditionalFailureItem(err)
	if !conditional {
		return nil, fmt.Errorf("store: compare and swap domain %s: %w", ref, err)
	}

	existing, loadErr := s.domainAfterConditionalFailure(ctx, ref, existingItem)
	if loadErr != nil {
		if errors.Is(loadErr, ErrNotFound) {
			return nil, loadErr
		}
		return nil, loadErr
	}
	if existing.state.Authority.TopologyHash != ref.TopologyHash {
		return nil, topologyMismatch("domain "+ref.String(), existing.state.Authority.TopologyHash, ref.TopologyHash)
	}
	if existing.state.Revision != expectedRevision {
		return nil, domainRevisionConflict(ref, expectedRevision, existing.state.Revision)
	}
	if !leaseMatches(existing.state.Lease, token) || !leaseActive(existing.state.Lease, now) {
		return nil, leaseLost(ref, token, existing.state.Lease)
	}
	return nil, &ConflictError{Resource: "domain " + ref.String() + " item version"}
}

func (s *DynamoDBStore) AcquireLease(ctx context.Context, ref DomainRef, holderID string, duration time.Duration) (*model.Lease, error) {
	if err := validateLeaseRequest(ctx, ref, holderID, duration); err != nil {
		return nil, err
	}
	current, err := s.loadDomainForWrite(ctx, ref)
	if err != nil {
		return nil, err
	}
	if current.state.Lease != nil {
		return nil, leaseHeld(ref, current.state.Lease)
	}
	if current.state.FenceTerm == model.FenceTerm(math.MaxUint64) {
		return nil, errors.New("store: lease fence term exhausted")
	}
	itemVersion, err := incrementItemVersion(current.itemVersion)
	if err != nil {
		return nil, err
	}
	now := s.clock.Now()
	lease := &model.Lease{
		HolderID:      holderID,
		FenceTerm:     current.state.FenceTerm + 1,
		RecordVersion: 1,
		AcquiredAt:    now,
		RenewedAt:     now,
		ExpiresAt:     now.Add(duration),
	}
	candidate, err := domainWithLease(current.state, lease)
	if err != nil {
		return nil, err
	}
	item, err := encodeDomainItem(candidate, itemVersion)
	if err != nil {
		return nil, fmt.Errorf("store: encode acquired lease for %s: %w", ref, err)
	}

	_, err = s.putItem(ctx, &dynamodb.PutItemInput{
		TableName: aws.String(s.tableName),
		Item:      item,
		ConditionExpression: aws.String(
			"#record_type = :record_type AND #topology_hash = :topology_hash AND #item_version = :item_version AND #document_revision = :document_revision AND #fence_term = :fence_term AND attribute_not_exists(#lease_holder) AND attribute_not_exists(#lease_fence_term) AND attribute_not_exists(#lease_record_version) AND attribute_not_exists(#lease_expires_at)",
		),
		ExpressionAttributeNames: domainConditionNames(
			attributeLeaseHolder,
			attributeLeaseFenceTerm,
			attributeLeaseRecordVersion,
			attributeLeaseExpiresAt,
		),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":record_type":       stringAttribute(recordTypeDomain),
			":topology_hash":     stringAttribute(ref.TopologyHash),
			":item_version":      numberAttribute(current.itemVersion),
			":document_revision": numberAttribute(uint64(current.state.Revision)),
			":fence_term":        numberAttribute(uint64(current.state.FenceTerm)),
		},
		ReturnValuesOnConditionCheckFailure: types.ReturnValuesOnConditionCheckFailureAllOld,
	})
	if err == nil {
		return lease.Clone(), nil
	}
	existingItem, conditional := conditionalFailureItem(err)
	if !conditional {
		return nil, fmt.Errorf("store: acquire lease for %s: %w", ref, err)
	}
	existing, loadErr := s.domainAfterConditionalFailure(ctx, ref, existingItem)
	if loadErr != nil {
		return nil, loadErr
	}
	if existing.state.Authority.TopologyHash != ref.TopologyHash {
		return nil, topologyMismatch("domain "+ref.String(), existing.state.Authority.TopologyHash, ref.TopologyHash)
	}
	if existing.state.Lease != nil {
		return nil, leaseHeld(ref, existing.state.Lease)
	}
	return nil, &ConflictError{Resource: "domain " + ref.String() + " item version"}
}

func (s *DynamoDBStore) TakeoverLease(ctx context.Context, ref DomainRef, holderID string, expectedRecordVersion uint64, duration time.Duration) (*model.Lease, error) {
	if err := validateLeaseRequest(ctx, ref, holderID, duration); err != nil {
		return nil, err
	}
	if expectedRecordVersion == 0 {
		return nil, errors.New("store: expected lease record version must be positive")
	}
	current, err := s.loadDomainForWrite(ctx, ref)
	if err != nil {
		return nil, err
	}
	if current.state.Lease == nil {
		return nil, &NotFoundError{Resource: "lease", Key: ref.String()}
	}
	if current.state.Lease.RecordVersion != expectedRecordVersion {
		return nil, leaseVersionConflict(ref, expectedRecordVersion, current.state.Lease.RecordVersion)
	}
	if current.state.FenceTerm == model.FenceTerm(math.MaxUint64) {
		return nil, errors.New("store: lease fence term exhausted")
	}
	if current.state.Lease.RecordVersion == math.MaxUint64 {
		return nil, errors.New("store: lease record version exhausted")
	}
	itemVersion, err := incrementItemVersion(current.itemVersion)
	if err != nil {
		return nil, err
	}
	now := s.clock.Now()
	lease := &model.Lease{
		HolderID:      holderID,
		FenceTerm:     current.state.FenceTerm + 1,
		RecordVersion: current.state.Lease.RecordVersion + 1,
		AcquiredAt:    now,
		RenewedAt:     now,
		ExpiresAt:     now.Add(duration),
	}
	candidate, err := domainWithLease(current.state, lease)
	if err != nil {
		return nil, err
	}
	item, err := encodeDomainItem(candidate, itemVersion)
	if err != nil {
		return nil, fmt.Errorf("store: encode takeover lease for %s: %w", ref, err)
	}

	_, err = s.putItem(ctx, &dynamodb.PutItemInput{
		TableName: aws.String(s.tableName),
		Item:      item,
		ConditionExpression: aws.String(
			"#record_type = :record_type AND #topology_hash = :topology_hash AND #item_version = :item_version AND #document_revision = :document_revision AND #fence_term = :fence_term AND #lease_record_version = :expected_lease_record_version",
		),
		ExpressionAttributeNames: domainConditionNames(attributeLeaseRecordVersion),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":record_type":                   stringAttribute(recordTypeDomain),
			":topology_hash":                 stringAttribute(ref.TopologyHash),
			":item_version":                  numberAttribute(current.itemVersion),
			":document_revision":             numberAttribute(uint64(current.state.Revision)),
			":fence_term":                    numberAttribute(uint64(current.state.FenceTerm)),
			":expected_lease_record_version": numberAttribute(expectedRecordVersion),
		},
		ReturnValuesOnConditionCheckFailure: types.ReturnValuesOnConditionCheckFailureAllOld,
	})
	if err == nil {
		return lease.Clone(), nil
	}
	existingItem, conditional := conditionalFailureItem(err)
	if !conditional {
		return nil, fmt.Errorf("store: take over lease for %s: %w", ref, err)
	}
	existing, loadErr := s.domainAfterConditionalFailure(ctx, ref, existingItem)
	if loadErr != nil {
		return nil, loadErr
	}
	if existing.state.Authority.TopologyHash != ref.TopologyHash {
		return nil, topologyMismatch("domain "+ref.String(), existing.state.Authority.TopologyHash, ref.TopologyHash)
	}
	if existing.state.Lease == nil {
		return nil, &NotFoundError{Resource: "lease", Key: ref.String()}
	}
	if existing.state.Lease.RecordVersion != expectedRecordVersion {
		return nil, leaseVersionConflict(ref, expectedRecordVersion, existing.state.Lease.RecordVersion)
	}
	return nil, &ConflictError{Resource: "domain " + ref.String() + " item version"}
}

func (s *DynamoDBStore) RenewLease(ctx context.Context, ref DomainRef, token LeaseToken, duration time.Duration) (*model.Lease, error) {
	if err := contextError(ctx); err != nil {
		return nil, err
	}
	if err := ref.Validate(); err != nil {
		return nil, fmt.Errorf("store: validate domain reference: %w", err)
	}
	if err := token.Validate(); err != nil {
		return nil, fmt.Errorf("store: validate lease token: %w", err)
	}
	if duration <= 0 {
		return nil, errors.New("store: lease duration must be positive")
	}
	current, err := s.loadDomainForWrite(ctx, ref)
	if err != nil {
		return nil, err
	}
	now := s.clock.Now()
	if !leaseMatches(current.state.Lease, token) || !leaseActive(current.state.Lease, now) {
		return nil, leaseLost(ref, token, current.state.Lease)
	}
	if current.state.Lease.RecordVersion == math.MaxUint64 {
		return nil, errors.New("store: lease record version exhausted")
	}
	itemVersion, err := incrementItemVersion(current.itemVersion)
	if err != nil {
		return nil, err
	}
	lease := current.state.Lease.Clone()
	lease.RecordVersion++
	lease.RenewedAt = now
	lease.ExpiresAt = now.Add(duration)
	candidate, err := domainWithLease(current.state, lease)
	if err != nil {
		return nil, err
	}
	item, err := encodeDomainItem(candidate, itemVersion)
	if err != nil {
		return nil, fmt.Errorf("store: encode renewed lease for %s: %w", ref, err)
	}
	nowUnixNano, err := checkedUnixNano(now)
	if err != nil {
		return nil, fmt.Errorf("store: encode lease comparison time: %w", err)
	}

	_, err = s.putItem(ctx, &dynamodb.PutItemInput{
		TableName: aws.String(s.tableName),
		Item:      item,
		ConditionExpression: aws.String(
			"#record_type = :record_type AND #topology_hash = :topology_hash AND #item_version = :item_version AND #document_revision = :document_revision AND #fence_term = :fence_term AND #lease_holder = :lease_holder AND #lease_fence_term = :lease_fence_term AND #lease_record_version = :lease_record_version AND #lease_expires_at > :now",
		),
		ExpressionAttributeNames: domainConditionNames(
			attributeLeaseHolder,
			attributeLeaseFenceTerm,
			attributeLeaseRecordVersion,
			attributeLeaseExpiresAt,
		),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":record_type":          stringAttribute(recordTypeDomain),
			":topology_hash":        stringAttribute(ref.TopologyHash),
			":item_version":         numberAttribute(current.itemVersion),
			":document_revision":    numberAttribute(uint64(current.state.Revision)),
			":fence_term":           numberAttribute(uint64(token.FenceTerm)),
			":lease_holder":         stringAttribute(token.HolderID),
			":lease_fence_term":     numberAttribute(uint64(token.FenceTerm)),
			":lease_record_version": numberAttribute(token.RecordVersion),
			":now":                  signedNumberAttribute(nowUnixNano),
		},
		ReturnValuesOnConditionCheckFailure: types.ReturnValuesOnConditionCheckFailureAllOld,
	})
	if err == nil {
		return lease.Clone(), nil
	}
	existingItem, conditional := conditionalFailureItem(err)
	if !conditional {
		return nil, fmt.Errorf("store: renew lease for %s: %w", ref, err)
	}
	existing, loadErr := s.domainAfterConditionalFailure(ctx, ref, existingItem)
	if loadErr != nil {
		if errors.Is(loadErr, ErrNotFound) {
			return nil, leaseLost(ref, token, nil)
		}
		return nil, loadErr
	}
	if existing.state.Authority.TopologyHash != ref.TopologyHash {
		return nil, topologyMismatch("domain "+ref.String(), existing.state.Authority.TopologyHash, ref.TopologyHash)
	}
	if !leaseMatches(existing.state.Lease, token) || !leaseActive(existing.state.Lease, now) {
		return nil, leaseLost(ref, token, existing.state.Lease)
	}
	return nil, &ConflictError{Resource: "domain " + ref.String() + " item version"}
}

func (s *DynamoDBStore) PublishObservation(ctx context.Context, deploymentID string, observation *model.Observation) (*model.Observation, error) {
	if err := contextError(ctx); err != nil {
		return nil, err
	}
	if err := validateIdentifier("deployment ID", deploymentID); err != nil {
		return nil, fmt.Errorf("store: %w", err)
	}
	if observation == nil {
		return nil, errors.New("store: observation is nil")
	}
	candidate := observation.Clone()
	if err := candidate.Validate(); err != nil {
		return nil, fmt.Errorf("store: validate observation: %w", err)
	}
	key := observationKey{
		deploymentID: deploymentID,
		topologyHash: candidate.TopologyHash,
		controllerID: candidate.ControllerID,
	}
	if _, allowed := s.allowedObservers[key]; !allowed {
		if expected, found := s.allowedTopology(deploymentID, candidate.ControllerID); found {
			return nil, topologyMismatch("observation from controller "+candidate.ControllerID, expected, candidate.TopologyHash)
		}
		return nil, fmt.Errorf("store: controller %q is not allowed to publish observations for deployment %q and topology %q", candidate.ControllerID, deploymentID, candidate.TopologyHash)
	}
	item, err := encodeObservationItem(deploymentID, candidate)
	if err != nil {
		return nil, fmt.Errorf("store: encode observation from controller %s: %w", candidate.ControllerID, err)
	}

	_, err = s.putItem(ctx, &dynamodb.PutItemInput{
		TableName: aws.String(s.tableName),
		Item:      item,
		ConditionExpression: aws.String(
			"attribute_not_exists(#pk) OR (#record_type = :record_type AND #topology_hash = :topology_hash AND #sequence < :sequence)",
		),
		ExpressionAttributeNames: map[string]string{
			"#pk":            attributePartitionKey,
			"#record_type":   attributeRecordType,
			"#topology_hash": attributeTopologyHash,
			"#sequence":      attributeSequence,
		},
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":record_type":   stringAttribute(recordTypeObservation),
			":topology_hash": stringAttribute(candidate.TopologyHash),
			":sequence":      numberAttribute(candidate.Sequence),
		},
		ReturnValuesOnConditionCheckFailure: types.ReturnValuesOnConditionCheckFailureAllOld,
	})
	if err == nil {
		return candidate.Clone(), nil
	}
	existingItem, conditional := conditionalFailureItem(err)
	if !conditional {
		return nil, fmt.Errorf("store: publish observation from controller %s: %w", candidate.ControllerID, err)
	}
	existing, loadErr := s.observationAfterConditionalFailure(ctx, deploymentID, candidate.TopologyHash, candidate.ControllerID, existingItem)
	if loadErr != nil {
		if errors.Is(loadErr, ErrNotFound) {
			return nil, &ConflictError{Resource: "observation sequence for controller " + candidate.ControllerID}
		}
		return nil, loadErr
	}
	if existing.TopologyHash != candidate.TopologyHash {
		return nil, topologyMismatch("observation from controller "+candidate.ControllerID, existing.TopologyHash, candidate.TopologyHash)
	}
	return nil, &ConflictError{
		Resource: "observation sequence for controller " + candidate.ControllerID,
		Expected: fmt.Sprintf(">%d", existing.Sequence),
		Actual:   fmt.Sprint(candidate.Sequence),
	}
}

func (s *DynamoDBStore) ListObservations(ctx context.Context, scope ObservationScope) ([]*model.Observation, error) {
	if err := contextError(ctx); err != nil {
		return nil, err
	}
	if err := scope.Validate(); err != nil {
		return nil, fmt.Errorf("store: validate observation scope: %w", err)
	}
	controllers := s.allowedControllers(scope)
	results := make([]*model.Observation, 0, len(controllers))
	totalBytes := 0

	for _, controllerID := range controllers {
		output, err := s.getItem(ctx, &dynamodb.GetItemInput{
			TableName:      aws.String(s.tableName),
			Key:            observationItemKey(scope.DeploymentID, scope.TopologyHash, controllerID),
			ConsistentRead: aws.Bool(true),
		})
		if err != nil {
			return nil, fmt.Errorf("store: list observation for controller %s in deployment %s and topology %s: %w", controllerID, scope.DeploymentID, scope.TopologyHash, err)
		}
		if output == nil {
			return nil, errors.New("store: list observations: DynamoDB returned a nil response")
		}
		if len(output.Item) == 0 {
			continue
		}
		size, err := dynamoItemSize(output.Item)
		if err != nil {
			return nil, fmt.Errorf("store: inspect observation item for controller %s: %w", controllerID, err)
		}
		totalBytes += size
		if totalBytes > maxObservationListingBytes {
			return nil, fmt.Errorf("store: observation listing exceeds %d bytes", maxObservationListingBytes)
		}
		observation, err := decodeObservationItem(output.Item, scope.DeploymentID, scope.TopologyHash, controllerID)
		if err != nil {
			return nil, fmt.Errorf("store: decode listed observation for controller %s: %w", controllerID, err)
		}
		results = append(results, observation.Clone())
	}

	return results, nil
}

func (s *DynamoDBStore) loadDomainForWrite(ctx context.Context, ref DomainRef) (*dynamoDomainRecord, error) {
	record, err := s.loadDomainRecord(ctx, ref.DeploymentID, ref.DomainID)
	if err != nil {
		return nil, err
	}
	if record.state.Authority.TopologyHash != ref.TopologyHash {
		return nil, topologyMismatch("domain "+ref.String(), record.state.Authority.TopologyHash, ref.TopologyHash)
	}
	if !record.state.Activated {
		return nil, ErrDomainInactive
	}
	return record, nil
}

func (s *DynamoDBStore) loadDomainRecord(ctx context.Context, deploymentID, domainID string) (*dynamoDomainRecord, error) {
	output, err := s.getItem(ctx, &dynamodb.GetItemInput{
		TableName:      aws.String(s.tableName),
		Key:            domainItemKey(deploymentID, domainID),
		ConsistentRead: aws.Bool(true),
	})
	if err != nil {
		return nil, fmt.Errorf("store: load domain %s/%s: %w", deploymentID, domainID, err)
	}
	if output == nil {
		return nil, errors.New("store: load domain: DynamoDB returned a nil response")
	}
	if len(output.Item) == 0 {
		return nil, &NotFoundError{Resource: "domain", Key: deploymentID + "/" + domainID}
	}
	record, err := decodeDomainItem(output.Item, deploymentID, domainID)
	if err != nil {
		return nil, fmt.Errorf("store: decode domain %s/%s: %w", deploymentID, domainID, err)
	}
	return record, nil
}

func (s *DynamoDBStore) domainAfterConditionalFailure(ctx context.Context, ref DomainRef, item map[string]types.AttributeValue) (*dynamoDomainRecord, error) {
	if len(item) == 0 {
		return s.loadDomainRecord(ctx, ref.DeploymentID, ref.DomainID)
	}
	record, err := decodeDomainItem(item, ref.DeploymentID, ref.DomainID)
	if err != nil {
		return nil, fmt.Errorf("store: decode condition-failure domain %s: %w", ref, err)
	}
	return record, nil
}

func (s *DynamoDBStore) loadObservation(ctx context.Context, deploymentID, topologyHash, controllerID string) (*model.Observation, error) {
	output, err := s.getItem(ctx, &dynamodb.GetItemInput{
		TableName:      aws.String(s.tableName),
		Key:            observationItemKey(deploymentID, topologyHash, controllerID),
		ConsistentRead: aws.Bool(true),
	})
	if err != nil {
		return nil, fmt.Errorf("store: load observation for controller %s: %w", controllerID, err)
	}
	if output == nil {
		return nil, errors.New("store: load observation: DynamoDB returned a nil response")
	}
	if len(output.Item) == 0 {
		return nil, &NotFoundError{Resource: "observation", Key: deploymentID + "/" + topologyHash + "/" + controllerID}
	}
	observation, err := decodeObservationItem(output.Item, deploymentID, topologyHash, controllerID)
	if err != nil {
		return nil, fmt.Errorf("store: decode observation for controller %s: %w", controllerID, err)
	}
	return observation, nil
}

func (s *DynamoDBStore) observationAfterConditionalFailure(ctx context.Context, deploymentID, topologyHash, controllerID string, item map[string]types.AttributeValue) (*model.Observation, error) {
	if len(item) == 0 {
		return s.loadObservation(ctx, deploymentID, topologyHash, controllerID)
	}
	observation, err := decodeObservationItem(item, deploymentID, topologyHash, controllerID)
	if err != nil {
		return nil, fmt.Errorf("store: decode condition-failure observation for controller %s: %w", controllerID, err)
	}
	return observation, nil
}

func (s *DynamoDBStore) allowedTopology(deploymentID, controllerID string) (string, bool) {
	topologies := make([]string, 0, 1)
	for key := range s.allowedObservers {
		if key.deploymentID == deploymentID && key.controllerID == controllerID {
			topologies = append(topologies, key.topologyHash)
		}
	}
	if len(topologies) == 0 {
		return "", false
	}
	sort.Strings(topologies)
	return topologies[0], true
}

func (s *DynamoDBStore) allowedControllers(scope ObservationScope) []string {
	controllers := make([]string, 0)
	for key := range s.allowedObservers {
		if key.deploymentID == scope.DeploymentID && key.topologyHash == scope.TopologyHash {
			controllers = append(controllers, key.controllerID)
		}
	}
	sort.Strings(controllers)
	return controllers
}

func encodeDomainItem(state *model.DomainState, itemVersion uint64) (map[string]types.AttributeValue, error) {
	if state == nil {
		return nil, errors.New("domain state is nil")
	}
	if itemVersion == 0 {
		return nil, errors.New("item version must be positive")
	}
	payload, err := json.Marshal(state)
	if err != nil {
		return nil, fmt.Errorf("marshal JSON payload: %w", err)
	}
	item := map[string]types.AttributeValue{
		attributePartitionKey:     stringAttribute(domainPartitionKey(state.Authority.DeploymentID)),
		attributeSortKey:          stringAttribute(domainSortKey(state.Authority.DomainID)),
		attributeSchemaVersion:    numberAttribute(itemSchemaVersion),
		attributeRecordType:       stringAttribute(recordTypeDomain),
		attributeDeploymentID:     stringAttribute(state.Authority.DeploymentID),
		attributeDomainID:         stringAttribute(state.Authority.DomainID),
		attributeTopologyHash:     stringAttribute(state.Authority.TopologyHash),
		attributeDocumentRevision: numberAttribute(uint64(state.Revision)),
		attributeItemVersion:      numberAttribute(itemVersion),
		attributeFenceTerm:        numberAttribute(uint64(state.FenceTerm)),
		attributePayload:          stringAttribute(string(payload)),
	}
	if state.Lease != nil {
		expiresAt, err := checkedUnixNano(state.Lease.ExpiresAt)
		if err != nil {
			return nil, fmt.Errorf("lease expiry: %w", err)
		}
		item[attributeLeaseHolder] = stringAttribute(state.Lease.HolderID)
		item[attributeLeaseFenceTerm] = numberAttribute(uint64(state.Lease.FenceTerm))
		item[attributeLeaseRecordVersion] = numberAttribute(state.Lease.RecordVersion)
		item[attributeLeaseExpiresAt] = signedNumberAttribute(expiresAt)
	}
	if err := validateDynamoItemSize(item); err != nil {
		return nil, err
	}
	return item, nil
}

func decodeDomainItem(item map[string]types.AttributeValue, deploymentID, domainID string) (*dynamoDomainRecord, error) {
	if err := validateDynamoItemSize(item); err != nil {
		return nil, err
	}
	allowed := make(map[string]struct{}, len(domainBaseAttributes)+len(domainLeaseAttributes))
	for name := range domainBaseAttributes {
		allowed[name] = struct{}{}
	}
	for _, name := range domainLeaseAttributes {
		allowed[name] = struct{}{}
	}
	if err := validateAttributeSet(item, allowed, domainBaseAttributes); err != nil {
		return nil, err
	}
	if err := requireStringValue(item, attributePartitionKey, domainPartitionKey(deploymentID)); err != nil {
		return nil, err
	}
	if err := requireStringValue(item, attributeSortKey, domainSortKey(domainID)); err != nil {
		return nil, err
	}
	if err := requireNumberValue(item, attributeSchemaVersion, itemSchemaVersion); err != nil {
		return nil, err
	}
	if err := requireStringValue(item, attributeRecordType, recordTypeDomain); err != nil {
		return nil, err
	}
	if err := requireStringValue(item, attributeDeploymentID, deploymentID); err != nil {
		return nil, err
	}
	if err := requireStringValue(item, attributeDomainID, domainID); err != nil {
		return nil, err
	}

	payload, err := requiredStringAttribute(item, attributePayload)
	if err != nil {
		return nil, err
	}
	var state model.DomainState
	if err := strictJSONDecode([]byte(payload), &state); err != nil {
		return nil, fmt.Errorf("decode JSON payload: %w", err)
	}
	if err := state.Validate(); err != nil {
		return nil, fmt.Errorf("validate JSON payload: %w", err)
	}
	if state.Authority.DeploymentID != deploymentID || state.Authority.DomainID != domainID {
		return nil, errors.New("JSON payload domain identity does not match item key")
	}

	topologyHash, err := requiredStringAttribute(item, attributeTopologyHash)
	if err != nil {
		return nil, err
	}
	if topologyHash != state.Authority.TopologyHash {
		return nil, errors.New("topology hash metadata does not match JSON payload")
	}
	revision, err := requiredUintAttribute(item, attributeDocumentRevision)
	if err != nil {
		return nil, err
	}
	if revision != uint64(state.Revision) {
		return nil, errors.New("document revision metadata does not match JSON payload")
	}
	itemVersion, err := requiredUintAttribute(item, attributeItemVersion)
	if err != nil {
		return nil, err
	}
	if itemVersion == 0 {
		return nil, errors.New("item version must be positive")
	}
	fenceTerm, err := requiredUintAttribute(item, attributeFenceTerm)
	if err != nil {
		return nil, err
	}
	if fenceTerm != uint64(state.FenceTerm) {
		return nil, errors.New("fence term metadata does not match JSON payload")
	}

	presentLeaseAttributes := 0
	for _, name := range domainLeaseAttributes {
		if _, present := item[name]; present {
			presentLeaseAttributes++
		}
	}
	if state.Lease == nil {
		if presentLeaseAttributes != 0 {
			return nil, errors.New("lease metadata is present for a lease-free JSON payload")
		}
	} else {
		if presentLeaseAttributes != len(domainLeaseAttributes) {
			return nil, errors.New("lease metadata is incomplete")
		}
		holder, err := requiredStringAttribute(item, attributeLeaseHolder)
		if err != nil {
			return nil, err
		}
		leaseFence, err := requiredUintAttribute(item, attributeLeaseFenceTerm)
		if err != nil {
			return nil, err
		}
		leaseVersion, err := requiredUintAttribute(item, attributeLeaseRecordVersion)
		if err != nil {
			return nil, err
		}
		expiresAt, err := requiredIntAttribute(item, attributeLeaseExpiresAt)
		if err != nil {
			return nil, err
		}
		expectedExpiry, err := checkedUnixNano(state.Lease.ExpiresAt)
		if err != nil {
			return nil, fmt.Errorf("JSON lease expiry: %w", err)
		}
		if holder != state.Lease.HolderID || leaseFence != uint64(state.Lease.FenceTerm) || leaseVersion != state.Lease.RecordVersion || expiresAt != expectedExpiry {
			return nil, errors.New("lease metadata does not match JSON payload")
		}
	}

	return &dynamoDomainRecord{state: state.Clone(), itemVersion: itemVersion, payload: payload}, nil
}

func encodeObservationItem(deploymentID string, observation *model.Observation) (map[string]types.AttributeValue, error) {
	if observation == nil {
		return nil, errors.New("observation is nil")
	}
	payload, err := json.Marshal(observation)
	if err != nil {
		return nil, fmt.Errorf("marshal JSON payload: %w", err)
	}
	item := map[string]types.AttributeValue{
		attributePartitionKey:  stringAttribute(observationPartitionKey(deploymentID, observation.TopologyHash, observation.ControllerID)),
		attributeSortKey:       stringAttribute(observationSortKey(observation.ControllerID)),
		attributeSchemaVersion: numberAttribute(itemSchemaVersion),
		attributeRecordType:    stringAttribute(recordTypeObservation),
		attributeDeploymentID:  stringAttribute(deploymentID),
		attributeControllerID:  stringAttribute(observation.ControllerID),
		attributeTopologyHash:  stringAttribute(observation.TopologyHash),
		attributeSequence:      numberAttribute(observation.Sequence),
		attributeTTL:           signedNumberAttribute(observation.ExpiresAt.Unix()),
		attributePayload:       stringAttribute(string(payload)),
	}
	if err := validateDynamoItemSize(item); err != nil {
		return nil, err
	}
	return item, nil
}

func decodeObservationItem(item map[string]types.AttributeValue, deploymentID, topologyHash, controllerID string) (*model.Observation, error) {
	if err := validateDynamoItemSize(item); err != nil {
		return nil, err
	}
	if err := validateAttributeSet(item, observationAttributes, observationAttributes); err != nil {
		return nil, err
	}
	if err := requireStringValue(item, attributePartitionKey, observationPartitionKey(deploymentID, topologyHash, controllerID)); err != nil {
		return nil, err
	}
	if err := requireNumberValue(item, attributeSchemaVersion, itemSchemaVersion); err != nil {
		return nil, err
	}
	if err := requireStringValue(item, attributeRecordType, recordTypeObservation); err != nil {
		return nil, err
	}
	if err := requireStringValue(item, attributeDeploymentID, deploymentID); err != nil {
		return nil, err
	}
	if err := requireStringValue(item, attributeTopologyHash, topologyHash); err != nil {
		return nil, err
	}

	payload, err := requiredStringAttribute(item, attributePayload)
	if err != nil {
		return nil, err
	}
	var observation model.Observation
	if err := strictJSONDecode([]byte(payload), &observation); err != nil {
		return nil, fmt.Errorf("decode JSON payload: %w", err)
	}
	if err := observation.Validate(); err != nil {
		return nil, fmt.Errorf("validate JSON payload: %w", err)
	}
	if observation.ControllerID != controllerID {
		return nil, errors.New("JSON payload controller identity does not match requested key")
	}
	if observation.TopologyHash != topologyHash {
		return nil, errors.New("JSON payload topology does not match requested key")
	}
	if err := requireStringValue(item, attributeSortKey, observationSortKey(controllerID)); err != nil {
		return nil, err
	}
	if err := requireStringValue(item, attributeControllerID, controllerID); err != nil {
		return nil, err
	}
	if err := requireStringValue(item, attributeTopologyHash, observation.TopologyHash); err != nil {
		return nil, err
	}
	if err := requireNumberValue(item, attributeSequence, observation.Sequence); err != nil {
		return nil, errors.New("sequence metadata does not match JSON payload")
	}
	ttl, err := requiredIntAttribute(item, attributeTTL)
	if err != nil {
		return nil, err
	}
	if ttl != observation.ExpiresAt.Unix() {
		return nil, errors.New("TTL metadata does not match JSON payload expiry")
	}
	return observation.Clone(), nil
}

func domainWithLease(current *model.DomainState, lease *model.Lease) (*model.DomainState, error) {
	if err := lease.Validate(); err != nil {
		return nil, fmt.Errorf("store: validate lease: %w", err)
	}
	candidate := current.Clone()
	candidate.FenceTerm = lease.FenceTerm
	candidate.Lease = lease.Clone()
	if candidate.UpdatedAt.Before(lease.RenewedAt) {
		candidate.UpdatedAt = lease.RenewedAt
	}
	if err := candidate.Validate(); err != nil {
		return nil, fmt.Errorf("store: validate leased domain state: %w", err)
	}
	return candidate, nil
}

func domainConditionNames(additional ...string) map[string]string {
	names := map[string]string{
		"#record_type":       attributeRecordType,
		"#topology_hash":     attributeTopologyHash,
		"#item_version":      attributeItemVersion,
		"#document_revision": attributeDocumentRevision,
		"#fence_term":        attributeFenceTerm,
	}
	for _, attribute := range additional {
		placeholder := "#" + attribute
		if attribute == attributeLeaseExpiresAt {
			placeholder = "#lease_expires_at"
		}
		names[placeholder] = attribute
	}
	return names
}

func conditionalFailureItem(err error) (map[string]types.AttributeValue, bool) {
	var conditional *types.ConditionalCheckFailedException
	if !errors.As(err, &conditional) {
		return nil, false
	}
	return conditional.Item, true
}

func domainRevisionConflict(ref DomainRef, expected, actual model.DocumentRevision) error {
	return &ConflictError{
		Resource: "domain " + ref.String() + " revision",
		Expected: fmt.Sprint(expected),
		Actual:   fmt.Sprint(actual),
	}
}

func leaseVersionConflict(ref DomainRef, expected, actual uint64) error {
	return &ConflictError{
		Resource: "lease " + ref.String() + " record version",
		Expected: fmt.Sprint(expected),
		Actual:   fmt.Sprint(actual),
	}
}

func incrementItemVersion(version uint64) (uint64, error) {
	if version == math.MaxUint64 {
		return 0, errors.New("store: DynamoDB item version exhausted")
	}
	return version + 1, nil
}

func checkedUnixNano(value time.Time) (int64, error) {
	nanoseconds := value.UnixNano()
	if !time.Unix(0, nanoseconds).Equal(value) {
		return 0, fmt.Errorf("timestamp %s is outside Unix-nanosecond range", value.Format(time.RFC3339Nano))
	}
	return nanoseconds, nil
}

func strictJSONDecode(payload []byte, target any) error {
	if err := strictjson.Validate(payload, dynamoDBItemLimit); err != nil {
		switch {
		case errors.Is(err, strictjson.ErrTrailingValue):
			return errors.New("multiple JSON values")
		case errors.Is(err, strictjson.ErrTrailingData):
			return fmt.Errorf("trailing JSON data: %w", err)
		default:
			return err
		}
	}

	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("multiple JSON values")
		}
		return fmt.Errorf("trailing JSON data: %w", err)
	}
	return nil
}

func validateDynamoItemSize(item map[string]types.AttributeValue) error {
	size, err := dynamoItemSize(item)
	if err != nil {
		return err
	}
	if size > dynamoDBItemLimit {
		return fmt.Errorf("DynamoDB item is %d bytes; limit is %d", size, dynamoDBItemLimit)
	}
	return nil
}

func dynamoItemSize(item map[string]types.AttributeValue) (int, error) {
	size := 0
	for name, attribute := range item {
		// One byte per attribute keeps the estimate conservative for DynamoDB's
		// compact number encoding and type overhead.
		size += len(name) + 1
		switch value := attribute.(type) {
		case *types.AttributeValueMemberS:
			if value == nil {
				return 0, fmt.Errorf("attribute %q has a nil string value", name)
			}
			size += len(value.Value)
		case *types.AttributeValueMemberN:
			if value == nil {
				return 0, fmt.Errorf("attribute %q has a nil number value", name)
			}
			size += len(value.Value)
		case *types.AttributeValueMemberB:
			if value == nil {
				return 0, fmt.Errorf("attribute %q has a nil binary value", name)
			}
			size += len(value.Value)
		default:
			return 0, fmt.Errorf("attribute %q has unsupported type %T", name, attribute)
		}
	}
	return size, nil
}

func validateAttributeSet(item map[string]types.AttributeValue, allowed, required map[string]struct{}) error {
	for name := range item {
		if _, ok := allowed[name]; !ok {
			return fmt.Errorf("unknown DynamoDB attribute %q", name)
		}
	}
	for name := range required {
		if _, ok := item[name]; !ok {
			return fmt.Errorf("missing DynamoDB attribute %q", name)
		}
	}
	return nil
}

func requiredStringAttribute(item map[string]types.AttributeValue, name string) (string, error) {
	attribute, ok := item[name]
	if !ok {
		return "", fmt.Errorf("missing DynamoDB attribute %q", name)
	}
	value, ok := attribute.(*types.AttributeValueMemberS)
	if !ok || value == nil {
		return "", fmt.Errorf("DynamoDB attribute %q has type %T; want string", name, attribute)
	}
	return value.Value, nil
}

func requiredUintAttribute(item map[string]types.AttributeValue, name string) (uint64, error) {
	attribute, ok := item[name]
	if !ok {
		return 0, fmt.Errorf("missing DynamoDB attribute %q", name)
	}
	value, ok := attribute.(*types.AttributeValueMemberN)
	if !ok || value == nil {
		return 0, fmt.Errorf("DynamoDB attribute %q has type %T; want number", name, attribute)
	}
	parsed, err := strconv.ParseUint(value.Value, 10, 64)
	if err != nil || strconv.FormatUint(parsed, 10) != value.Value {
		return 0, fmt.Errorf("DynamoDB attribute %q is not a canonical unsigned integer", name)
	}
	return parsed, nil
}

func requiredIntAttribute(item map[string]types.AttributeValue, name string) (int64, error) {
	attribute, ok := item[name]
	if !ok {
		return 0, fmt.Errorf("missing DynamoDB attribute %q", name)
	}
	value, ok := attribute.(*types.AttributeValueMemberN)
	if !ok || value == nil {
		return 0, fmt.Errorf("DynamoDB attribute %q has type %T; want number", name, attribute)
	}
	parsed, err := strconv.ParseInt(value.Value, 10, 64)
	if err != nil || strconv.FormatInt(parsed, 10) != value.Value {
		return 0, fmt.Errorf("DynamoDB attribute %q is not a canonical integer", name)
	}
	return parsed, nil
}

func requireStringValue(item map[string]types.AttributeValue, name, expected string) error {
	actual, err := requiredStringAttribute(item, name)
	if err != nil {
		return err
	}
	if actual != expected {
		return fmt.Errorf("DynamoDB attribute %q is %q; want %q", name, actual, expected)
	}
	return nil
}

func requireNumberValue(item map[string]types.AttributeValue, name string, expected uint64) error {
	actual, err := requiredUintAttribute(item, name)
	if err != nil {
		return err
	}
	if actual != expected {
		return fmt.Errorf("DynamoDB attribute %q is %d; want %d", name, actual, expected)
	}
	return nil
}

func stringAttribute(value string) types.AttributeValue {
	return &types.AttributeValueMemberS{Value: value}
}

func numberAttribute(value uint64) types.AttributeValue {
	return &types.AttributeValueMemberN{Value: strconv.FormatUint(value, 10)}
}

func signedNumberAttribute(value int64) types.AttributeValue {
	return &types.AttributeValueMemberN{Value: strconv.FormatInt(value, 10)}
}

func domainItemKey(deploymentID, domainID string) map[string]types.AttributeValue {
	return map[string]types.AttributeValue{
		attributePartitionKey: stringAttribute(domainPartitionKey(deploymentID)),
		attributeSortKey:      stringAttribute(domainSortKey(domainID)),
	}
}

func observationItemKey(deploymentID, topologyHash, controllerID string) map[string]types.AttributeValue {
	return map[string]types.AttributeValue{
		attributePartitionKey: stringAttribute(observationPartitionKey(deploymentID, topologyHash, controllerID)),
		attributeSortKey:      stringAttribute(observationSortKey(controllerID)),
	}
}

func domainPartitionKey(deploymentID string) string {
	return "deployment#" + deploymentID
}

func domainSortKey(domainID string) string {
	return "domain#" + domainID
}

func observationPartitionKey(deploymentID, topologyHash, controllerID string) string {
	return "observations#" + deploymentID + "#" + topologyHash + "#" + controllerID
}

func observationSortKey(controllerID string) string {
	return "controller#" + controllerID
}
