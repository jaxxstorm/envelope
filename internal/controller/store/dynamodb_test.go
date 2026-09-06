package store

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/jaxxstorm/envelope/internal/controller/model"
)

var (
	dynamoTestTime     = time.Date(2026, time.September, 4, 12, 0, 0, 0, time.UTC)
	dynamoTopologyHash = strings.Repeat("a", 64)
	dynamoOtherHash    = strings.Repeat("b", 64)
)

func TestDynamoDBStoreDomainAndLeaseRoundTrip(t *testing.T) {
	api := newFakeDynamoDB()
	clock := NewFakeClock(dynamoTestTime)
	dynamo := newDynamoDBStoreForTest(t, api, clock)
	ctx := context.Background()
	initial := dynamoInitialState()
	wantInitial := initial.Clone()

	created, err := dynamo.CreateDomain(ctx, &initial)
	if err != nil {
		t.Fatalf("CreateDomain() error = %v", err)
	}
	initial.Authority.RemotePrefixes[0] = "192.0.2.0/24"
	created.Authority.Owners[0].ENIID = "eni-mutated"
	loaded, err := dynamo.LoadDomain(ctx, dynamoDomainRef())
	if err != nil {
		t.Fatalf("LoadDomain() error = %v", err)
	}
	if !reflect.DeepEqual(loaded, wantInitial) {
		t.Fatalf("LoadDomain() = %#v, want %#v", loaded, wantInitial)
	}

	lease, err := dynamo.AcquireLease(ctx, dynamoDomainRef(), "controller-a", time.Minute)
	if err != nil {
		t.Fatalf("AcquireLease() error = %v", err)
	}
	if lease.HolderID != "controller-a" || lease.FenceTerm != 1 || lease.RecordVersion != 1 {
		t.Fatalf("AcquireLease() = %#v", lease)
	}
	acquireToken := LeaseTokenFor(lease)
	lease.HolderID = "mutated-result"

	clock.Advance(10 * time.Second)
	renewed, err := dynamo.RenewLease(ctx, dynamoDomainRef(), acquireToken, time.Minute)
	if err != nil {
		t.Fatalf("RenewLease() error = %v", err)
	}
	if renewed.FenceTerm != 1 || renewed.RecordVersion != 2 || !renewed.ExpiresAt.Equal(dynamoTestTime.Add(70*time.Second)) {
		t.Fatalf("RenewLease() = %#v", renewed)
	}

	next, err := dynamo.LoadDomain(ctx, dynamoDomainRef())
	if err != nil {
		t.Fatalf("LoadDomain() before CAS error = %v", err)
	}
	dynamoMakeOwnerObserved(next, clock.Now())
	saved, err := dynamo.CompareAndSwapDomain(ctx, dynamoDomainRef(), next.Revision, LeaseTokenFor(renewed), next)
	if err != nil {
		t.Fatalf("CompareAndSwapDomain() error = %v", err)
	}
	if saved.Revision != 2 || saved.Phase != model.PhaseOwnerObserved {
		t.Fatalf("CompareAndSwapDomain() = %#v", saved)
	}
	saved.Authority.RemotePrefixes[0] = "198.51.100.0/24"

	taken, err := dynamo.TakeoverLease(ctx, dynamoDomainRef(), "controller-b", renewed.RecordVersion, time.Minute)
	if err != nil {
		t.Fatalf("TakeoverLease() error = %v", err)
	}
	if taken.HolderID != "controller-b" || taken.FenceTerm != 2 || taken.RecordVersion != 3 {
		t.Fatalf("TakeoverLease() = %#v", taken)
	}
	taken.HolderID = "mutated-result"

	current, err := dynamo.LoadDomain(ctx, dynamoDomainRef())
	if err != nil {
		t.Fatalf("final LoadDomain() error = %v", err)
	}
	if current.Revision != 2 || current.Phase != model.PhaseOwnerObserved || current.FenceTerm != 2 || current.Lease.HolderID != "controller-b" {
		t.Fatalf("final domain = %#v", current)
	}
	if current.Authority.RemotePrefixes[0] != "10.1.0.0/24" {
		t.Fatal("DynamoDB store shared model storage with an input or result")
	}

	puts, gets := api.calls()
	if len(puts) != 5 {
		t.Fatalf("PutItem call count = %d, want 5", len(puts))
	}
	requireExpressionContains(t, puts[0].ConditionExpression, "attribute_not_exists(#pk)")
	requireExpressionContains(t, puts[1].ConditionExpression, "attribute_not_exists(#lease_holder)", "#item_version = :item_version")
	requireExpressionContains(t, puts[2].ConditionExpression, "#lease_holder = :lease_holder", "#lease_fence_term = :lease_fence_term", "#lease_record_version = :lease_record_version", "#lease_expires_at > :now")
	requireExpressionContains(t, puts[3].ConditionExpression, "#document_revision = :document_revision", "#topology_hash = :topology_hash", "#lease_expires_at > :now")
	requireExpressionContains(t, puts[4].ConditionExpression, "#lease_record_version = :expected_lease_record_version", "#item_version = :item_version")
	for index, put := range puts {
		if put.ReturnValuesOnConditionCheckFailure != types.ReturnValuesOnConditionCheckFailureAllOld {
			t.Fatalf("PutItem call %d does not request the condition-failure item", index)
		}
		requireNoUnusedExpressionNames(t, put)
	}
	for index, get := range gets {
		if get.ConsistentRead == nil || !*get.ConsistentRead {
			t.Fatalf("GetItem call %d is not strongly consistent", index)
		}
	}
}

func TestDynamoDBStoreConditionalFailuresAreTyped(t *testing.T) {
	t.Run("create conflict and topology mismatch", func(t *testing.T) {
		api := newFakeDynamoDB()
		dynamo := newDynamoDBStoreForTest(t, api, NewFakeClock(dynamoTestTime))
		initial := dynamoInitialState()
		if _, err := dynamo.CreateDomain(context.Background(), &initial); err != nil {
			t.Fatalf("initial CreateDomain() error = %v", err)
		}
		_, err := dynamo.CreateDomain(context.Background(), &initial)
		requireDynamoTypedError[*ConflictError](t, err, ErrConflict)

		other := dynamoInitialState()
		other.Authority.TopologyHash = dynamoOtherHash
		_, err = dynamo.CreateDomain(context.Background(), &other)
		requireDynamoTypedError[*TopologyMismatchError](t, err, ErrTopologyMismatch)
	})

	t.Run("acquire loses an atomic race", func(t *testing.T) {
		api := newFakeDynamoDB()
		clock := NewFakeClock(dynamoTestTime)
		dynamo := newDynamoDBStoreForTest(t, api, clock)
		createDynamoDomain(t, dynamo)

		api.beforePut = func(fake *fakeDynamoDB, input *dynamodb.PutItemInput) {
			if !strings.Contains(stringValue(input.ConditionExpression), "attribute_not_exists(#lease_holder)") {
				return
			}
			key := fakeItemKey(input.Item)
			current, err := decodeDomainItem(fake.items[key], "deployment-a", "domain-a")
			if err != nil {
				t.Fatalf("decode seeded domain: %v", err)
			}
			lease := &model.Lease{
				HolderID:      "controller-winner",
				FenceTerm:     current.state.FenceTerm + 1,
				RecordVersion: 1,
				AcquiredAt:    dynamoTestTime,
				RenewedAt:     dynamoTestTime,
				ExpiresAt:     dynamoTestTime.Add(time.Minute),
			}
			candidate, err := domainWithLease(current.state, lease)
			if err != nil {
				t.Fatalf("build competing lease: %v", err)
			}
			fake.items[key], err = encodeDomainItem(candidate, current.itemVersion+1)
			if err != nil {
				t.Fatalf("encode competing lease: %v", err)
			}
			fake.beforePut = nil
		}

		_, err := dynamo.AcquireLease(context.Background(), dynamoDomainRef(), "controller-loser", time.Minute)
		held := requireDynamoTypedError[*LeaseHeldError](t, err, ErrLeaseHeld)
		if held.Lease == nil || held.Lease.HolderID != "controller-winner" {
			t.Fatalf("LeaseHeldError.Lease = %#v", held.Lease)
		}
		held.Lease.HolderID = "mutated-error"
		current, err := dynamo.LoadDomain(context.Background(), dynamoDomainRef())
		if err != nil {
			t.Fatalf("LoadDomain() error = %v", err)
		}
		if current.Lease.HolderID != "controller-winner" {
			t.Fatal("conditional error shared durable lease storage")
		}
	})

	t.Run("CAS loses a document revision race", func(t *testing.T) {
		api := newFakeDynamoDB()
		clock := NewFakeClock(dynamoTestTime)
		dynamo := newDynamoDBStoreForTest(t, api, clock)
		createDynamoDomain(t, dynamo)
		lease, err := dynamo.AcquireLease(context.Background(), dynamoDomainRef(), "controller-a", time.Minute)
		if err != nil {
			t.Fatalf("AcquireLease() error = %v", err)
		}
		next, err := dynamo.LoadDomain(context.Background(), dynamoDomainRef())
		if err != nil {
			t.Fatalf("LoadDomain() error = %v", err)
		}
		dynamoMakeOwnerObserved(next, dynamoTestTime)

		api.beforePut = func(fake *fakeDynamoDB, input *dynamodb.PutItemInput) {
			if !strings.Contains(stringValue(input.ConditionExpression), "#lease_expires_at > :now") {
				return
			}
			fake.items[fakeItemKey(input.Item)] = cloneDynamoItem(input.Item)
			fake.beforePut = nil
		}
		_, err = dynamo.CompareAndSwapDomain(context.Background(), dynamoDomainRef(), next.Revision, LeaseTokenFor(lease), next)
		requireDynamoTypedError[*ConflictError](t, err, ErrConflict)
	})

	t.Run("renew loses an exact lease race", func(t *testing.T) {
		api := newFakeDynamoDB()
		clock := NewFakeClock(dynamoTestTime)
		dynamo := newDynamoDBStoreForTest(t, api, clock)
		createDynamoDomain(t, dynamo)
		lease, err := dynamo.AcquireLease(context.Background(), dynamoDomainRef(), "controller-a", time.Minute)
		if err != nil {
			t.Fatalf("AcquireLease() error = %v", err)
		}

		api.beforePut = func(fake *fakeDynamoDB, input *dynamodb.PutItemInput) {
			if !strings.Contains(stringValue(input.ConditionExpression), "#lease_holder = :lease_holder") {
				return
			}
			fake.items[fakeItemKey(input.Item)] = cloneDynamoItem(input.Item)
			fake.beforePut = nil
		}
		_, err = dynamo.RenewLease(context.Background(), dynamoDomainRef(), LeaseTokenFor(lease), time.Minute)
		requireDynamoTypedError[*LeaseLostError](t, err, ErrLeaseLost)
	})

	t.Run("takeover loses a record version race", func(t *testing.T) {
		api := newFakeDynamoDB()
		clock := NewFakeClock(dynamoTestTime)
		dynamo := newDynamoDBStoreForTest(t, api, clock)
		createDynamoDomain(t, dynamo)
		lease, err := dynamo.AcquireLease(context.Background(), dynamoDomainRef(), "controller-a", time.Minute)
		if err != nil {
			t.Fatalf("AcquireLease() error = %v", err)
		}

		api.beforePut = func(fake *fakeDynamoDB, input *dynamodb.PutItemInput) {
			if !strings.Contains(stringValue(input.ConditionExpression), ":expected_lease_record_version") {
				return
			}
			fake.items[fakeItemKey(input.Item)] = cloneDynamoItem(input.Item)
			fake.beforePut = nil
		}
		_, err = dynamo.TakeoverLease(context.Background(), dynamoDomainRef(), "controller-b", lease.RecordVersion, time.Minute)
		requireDynamoTypedError[*ConflictError](t, err, ErrConflict)
	})

	t.Run("expired lease cannot renew or write state", func(t *testing.T) {
		api := newFakeDynamoDB()
		clock := NewFakeClock(dynamoTestTime)
		dynamo := newDynamoDBStoreForTest(t, api, clock)
		createDynamoDomain(t, dynamo)
		lease, err := dynamo.AcquireLease(context.Background(), dynamoDomainRef(), "controller-a", time.Minute)
		if err != nil {
			t.Fatalf("AcquireLease() error = %v", err)
		}
		next, err := dynamo.LoadDomain(context.Background(), dynamoDomainRef())
		if err != nil {
			t.Fatalf("LoadDomain() error = %v", err)
		}
		clock.Advance(time.Minute)
		_, err = dynamo.RenewLease(context.Background(), dynamoDomainRef(), LeaseTokenFor(lease), time.Minute)
		requireDynamoTypedError[*LeaseLostError](t, err, ErrLeaseLost)
		dynamoMakeOwnerObserved(next, clock.Now())
		_, err = dynamo.CompareAndSwapDomain(context.Background(), dynamoDomainRef(), next.Revision, LeaseTokenFor(lease), next)
		requireDynamoTypedError[*LeaseLostError](t, err, ErrLeaseLost)
		puts, _ := api.calls()
		if len(puts) != 2 {
			t.Fatalf("expired lease operations made conditional writes: got %d PutItem calls, want 2", len(puts))
		}
	})

	t.Run("observation condition fallback reads the claimed partition", func(t *testing.T) {
		api := newFakeDynamoDB()
		api.omitConditionFailureItem = true
		dynamo := newDynamoDBStoreForTest(t, api, NewFakeClock(dynamoTestTime), dynamoObserverIdentity("controller-a"))
		observation := dynamoObservation("controller-a", dynamoTopologyHash, 1, dynamoTestTime)
		if _, err := dynamo.PublishObservation(context.Background(), "deployment-a", &observation); err != nil {
			t.Fatalf("initial PublishObservation() error = %v", err)
		}
		_, err := dynamo.PublishObservation(context.Background(), "deployment-a", &observation)
		requireDynamoTypedError[*ConflictError](t, err, ErrConflict)

		_, gets := api.calls()
		if len(gets) != 1 {
			t.Fatalf("condition-failure GetItem count = %d, want 1", len(gets))
		}
		if !reflect.DeepEqual(gets[0].Key, observationItemKey("deployment-a", dynamoTopologyHash, "controller-a")) {
			t.Fatalf("condition-failure GetItem key = %#v, want controller-a observation key", gets[0].Key)
		}
		if gets[0].ConsistentRead == nil || !*gets[0].ConsistentRead {
			t.Fatal("condition-failure GetItem is not strongly consistent")
		}
	})
}

func TestDynamoDBStoreRejectsWrongTopologyAndInvalidItems(t *testing.T) {
	t.Run("wrong topology", func(t *testing.T) {
		api := newFakeDynamoDB()
		dynamo := newDynamoDBStoreForTest(t, api, NewFakeClock(dynamoTestTime), dynamoObserverIdentity("controller-a"))
		createDynamoDomain(t, dynamo)

		wrongRef := dynamoDomainRef()
		wrongRef.TopologyHash = dynamoOtherHash
		_, err := dynamo.LoadDomain(context.Background(), wrongRef)
		requireDynamoTypedError[*TopologyMismatchError](t, err, ErrTopologyMismatch)

		wrongObservation := dynamoObservation("controller-a", dynamoOtherHash, 1, dynamoTestTime)
		_, err = dynamo.PublishObservation(context.Background(), "deployment-a", &wrongObservation)
		requireDynamoTypedError[*TopologyMismatchError](t, err, ErrTopologyMismatch)
	})

	t.Run("unknown JSON field", func(t *testing.T) {
		api := newFakeDynamoDB()
		dynamo := newDynamoDBStoreForTest(t, api, NewFakeClock(dynamoTestTime))
		state := dynamoInitialState()
		item, err := encodeDomainItem(&state, 1)
		if err != nil {
			t.Fatalf("encodeDomainItem() error = %v", err)
		}
		item[attributePayload] = stringAttribute(`{"unknown":true}`)
		api.seed(item)
		if _, err := dynamo.LoadDomain(context.Background(), dynamoDomainRef()); err == nil || !strings.Contains(err.Error(), "unknown field") {
			t.Fatalf("LoadDomain() error = %v, want unknown-field error", err)
		}
	})

	t.Run("duplicate nested domain JSON field", func(t *testing.T) {
		api := newFakeDynamoDB()
		dynamo := newDynamoDBStoreForTest(t, api, NewFakeClock(dynamoTestTime))
		state := dynamoInitialState()
		item, err := encodeDomainItem(&state, 1)
		if err != nil {
			t.Fatalf("encodeDomainItem() error = %v", err)
		}
		payload := fakeStringAttribute(item[attributePayload])
		duplicate := strings.Replace(payload, `"domain_id":"domain-a"`, `"domain_id":"domain-a","domain_id":"domain-a"`, 1)
		if duplicate == payload {
			t.Fatal("failed to construct duplicate nested domain field")
		}
		item[attributePayload] = stringAttribute(duplicate)
		api.seed(item)

		_, err = dynamo.LoadDomain(context.Background(), dynamoDomainRef())
		if err == nil || !strings.Contains(err.Error(), "duplicate JSON object member") {
			t.Fatalf("LoadDomain() error = %v, want duplicate-member error", err)
		}
	})

	t.Run("duplicate nested observation JSON field", func(t *testing.T) {
		api := newFakeDynamoDB()
		dynamo := newDynamoDBStoreForTest(t, api, NewFakeClock(dynamoTestTime), dynamoObserverIdentity("controller-a"))
		observation := dynamoObservation("controller-a", dynamoTopologyHash, 1, dynamoTestTime)
		item, err := encodeObservationItem("deployment-a", &observation)
		if err != nil {
			t.Fatalf("encodeObservationItem() error = %v", err)
		}
		payload := fakeStringAttribute(item[attributePayload])
		duplicate := strings.Replace(payload, `"stable_node_id":"node-a"`, `"stable_node_id":"node-a","stable_node_id":"node-a"`, 1)
		if duplicate == payload {
			t.Fatal("failed to construct duplicate nested observation field")
		}
		item[attributePayload] = stringAttribute(duplicate)
		api.seed(item)

		_, err = dynamo.ListObservations(context.Background(), ObservationScope{DeploymentID: "deployment-a", TopologyHash: dynamoTopologyHash})
		if err == nil || !strings.Contains(err.Error(), "duplicate JSON object member") {
			t.Fatalf("ListObservations() error = %v, want duplicate-member error", err)
		}
	})

	t.Run("metadata and payload mismatch", func(t *testing.T) {
		api := newFakeDynamoDB()
		dynamo := newDynamoDBStoreForTest(t, api, NewFakeClock(dynamoTestTime))
		state := dynamoInitialState()
		item, err := encodeDomainItem(&state, 1)
		if err != nil {
			t.Fatalf("encodeDomainItem() error = %v", err)
		}
		item[attributeDocumentRevision] = numberAttribute(2)
		api.seed(item)
		if _, err := dynamo.LoadDomain(context.Background(), dynamoDomainRef()); err == nil || !strings.Contains(err.Error(), "revision metadata") {
			t.Fatalf("LoadDomain() error = %v, want metadata mismatch", err)
		}
	})

	t.Run("oversize read item", func(t *testing.T) {
		api := newFakeDynamoDB()
		dynamo := newDynamoDBStoreForTest(t, api, NewFakeClock(dynamoTestTime))
		state := dynamoInitialState()
		item, err := encodeDomainItem(&state, 1)
		if err != nil {
			t.Fatalf("encodeDomainItem() error = %v", err)
		}
		item[attributePayload] = stringAttribute(strings.Repeat("x", dynamoDBItemLimit))
		api.seed(item)
		if _, err := dynamo.LoadDomain(context.Background(), dynamoDomainRef()); err == nil || !strings.Contains(err.Error(), "limit") {
			t.Fatalf("LoadDomain() error = %v, want item-size error", err)
		}
	})

	t.Run("oversize publication is rejected before I/O", func(t *testing.T) {
		api := newFakeDynamoDB()
		dynamo := newDynamoDBStoreForTest(t, api, NewFakeClock(dynamoTestTime), dynamoObserverIdentity("controller-a"))
		observation := dynamoObservation("controller-a", dynamoTopologyHash, 1, dynamoTestTime)
		for index := 0; index < 5000; index++ {
			observation.Domains[fmt.Sprintf("domain-%04d", index)] = dynamoOwnerObservation()
		}
		if _, err := dynamo.PublishObservation(context.Background(), "deployment-a", &observation); err == nil || !strings.Contains(err.Error(), "limit") {
			t.Fatalf("PublishObservation() error = %v, want item-size error", err)
		}
		puts, _ := api.calls()
		if len(puts) != 0 {
			t.Fatalf("oversize publication made %d PutItem calls", len(puts))
		}
	})

	t.Run("observation payload identity must match its partition", func(t *testing.T) {
		api := newFakeDynamoDB()
		dynamo := newDynamoDBStoreForTest(t, api, NewFakeClock(dynamoTestTime), dynamoObserverIdentity("controller-a"), dynamoObserverIdentity("controller-b"))
		observation := dynamoObservation("controller-b", dynamoTopologyHash, 1, dynamoTestTime)
		item, err := encodeObservationItem("deployment-a", &observation)
		if err != nil {
			t.Fatalf("encodeObservationItem() error = %v", err)
		}
		item[attributePartitionKey] = stringAttribute(observationPartitionKey("deployment-a", dynamoTopologyHash, "controller-a"))
		item[attributeSortKey] = stringAttribute(observationSortKey("controller-a"))
		api.seed(item)

		_, err = dynamo.ListObservations(context.Background(), ObservationScope{DeploymentID: "deployment-a", TopologyHash: dynamoTopologyHash})
		if err == nil || !strings.Contains(err.Error(), "controller identity") {
			t.Fatalf("ListObservations() error = %v, want controller identity mismatch", err)
		}
	})
}

func TestDynamoDBStoreObservationMonotonicityTTLAndStrongGets(t *testing.T) {
	api := newFakeDynamoDB()
	clock := NewFakeClock(dynamoTestTime)
	dynamo := newDynamoDBStoreForTest(t, api, clock, dynamoObserverIdentity("controller-b"), dynamoObserverIdentity("controller-a"))
	ctx := context.Background()
	empty, err := dynamo.ListObservations(ctx, ObservationScope{DeploymentID: "deployment-a", TopologyHash: dynamoTopologyHash})
	if err != nil {
		t.Fatalf("empty ListObservations() error = %v", err)
	}
	if len(empty) != 0 {
		t.Fatalf("empty ListObservations() returned %d observations", len(empty))
	}

	first := dynamoObservation("controller-a", dynamoTopologyHash, 1, dynamoTestTime)
	published, err := dynamo.PublishObservation(ctx, "deployment-a", &first)
	if err != nil {
		t.Fatalf("PublishObservation(sequence 1) error = %v", err)
	}
	first.Domains["domain-a"] = model.OwnerObservation{}
	published.Domains["domain-a"] = model.OwnerObservation{}
	_, err = dynamo.PublishObservation(ctx, "deployment-a", &first)
	requireDynamoTypedError[*ConflictError](t, err, ErrConflict)

	second := dynamoObservation("controller-a", dynamoTopologyHash, 2, dynamoTestTime.Add(time.Second))
	if _, err := dynamo.PublishObservation(ctx, "deployment-a", &second); err != nil {
		t.Fatalf("PublishObservation(sequence 2) error = %v", err)
	}
	expired := dynamoObservation("controller-b", dynamoTopologyHash, 1, dynamoTestTime.Add(-2*time.Minute))
	if _, err := dynamo.PublishObservation(ctx, "deployment-a", &expired); err != nil {
		t.Fatalf("PublishObservation(expired) error = %v", err)
	}

	listed, err := dynamo.ListObservations(ctx, ObservationScope{DeploymentID: "deployment-a", TopologyHash: dynamoTopologyHash})
	if err != nil {
		t.Fatalf("ListObservations() error = %v", err)
	}
	if len(listed) != 2 || listed[0].ControllerID != "controller-a" || listed[0].Sequence != 2 || listed[1].ControllerID != "controller-b" {
		t.Fatalf("ListObservations() = %#v", listed)
	}
	if listed[1].ExpiresAt.After(clock.Now()) {
		t.Fatalf("expired observation unexpectedly became fresh: %#v", listed[1])
	}
	listed[0].Domains["domain-a"] = model.OwnerObservation{}
	relisted, err := dynamo.ListObservations(ctx, ObservationScope{DeploymentID: "deployment-a", TopologyHash: dynamoTopologyHash})
	if err != nil {
		t.Fatalf("second ListObservations() error = %v", err)
	}
	if relisted[0].Domains["domain-a"].StableNodeID != "node-a" {
		t.Fatal("ListObservations() returned shared storage")
	}

	puts, gets := api.calls()
	if len(puts) != 4 {
		t.Fatalf("observation PutItem count = %d, want 4", len(puts))
	}
	wantPutControllers := []string{"controller-a", "controller-a", "controller-a", "controller-b"}
	for index, put := range puts {
		if !strings.Contains(stringValue(put.ConditionExpression), "#sequence < :sequence") {
			t.Fatalf("observation condition = %q", stringValue(put.ConditionExpression))
		}
		if strings.Contains(stringValue(put.ConditionExpression), "ttl") || strings.Contains(stringValue(put.ConditionExpression), "expires") {
			t.Fatalf("observation correctness condition uses TTL/expiry: %q", stringValue(put.ConditionExpression))
		}
		wantPartition := "observations#deployment-a#" + dynamoTopologyHash + "#" + wantPutControllers[index]
		if got := fakeStringAttribute(put.Item[attributePartitionKey]); got != wantPartition {
			t.Fatalf("observation PutItem %d partition key = %q, want %q", index, got, wantPartition)
		}
	}
	ttl, err := requiredIntAttribute(puts[0].Item, attributeTTL)
	if err != nil {
		t.Fatalf("observation TTL: %v", err)
	}
	if ttl != dynamoTestTime.Add(time.Minute).Unix() {
		t.Fatalf("observation TTL = %d, want %d", ttl, dynamoTestTime.Add(time.Minute).Unix())
	}
	if len(gets) != 6 {
		t.Fatalf("observation GetItem count = %d, want 6", len(gets))
	}
	wantGetControllers := []string{"controller-a", "controller-b", "controller-a", "controller-b", "controller-a", "controller-b"}
	for index, get := range gets {
		if get.ConsistentRead == nil || !*get.ConsistentRead {
			t.Fatalf("observation GetItem call %d is not strongly consistent", index)
		}
		controllerID := wantGetControllers[index]
		wantPartition := "observations#deployment-a#" + dynamoTopologyHash + "#" + controllerID
		if len(get.Key) != 2 || fakeStringAttribute(get.Key[attributePartitionKey]) != wantPartition || fakeStringAttribute(get.Key[attributeSortKey]) != "controller#"+controllerID {
			t.Fatalf("observation GetItem call %d key = %#v, want partition %q and controller sort key", index, get.Key, wantPartition)
		}
	}
}

func TestDynamoDBStoreBoundsObservationGetItemCalls(t *testing.T) {
	observers := make([]ObserverIdentity, 0, maxObservationResults)
	for index := range maxObservationResults {
		observers = append(observers, dynamoObserverIdentity(fmt.Sprintf("controller-%03d", index)))
	}
	api := newFakeDynamoDB()
	dynamo := newDynamoDBStoreForTest(t, api, NewFakeClock(dynamoTestTime), observers...)

	listed, err := dynamo.ListObservations(context.Background(), ObservationScope{DeploymentID: "deployment-a", TopologyHash: dynamoTopologyHash})
	if err != nil {
		t.Fatalf("ListObservations() error = %v", err)
	}
	if len(listed) != 0 {
		t.Fatalf("ListObservations() returned %d observations from an empty table", len(listed))
	}
	_, gets := api.calls()
	if len(gets) != maxObservationResults {
		t.Fatalf("GetItem call count = %d, want configured bound %d", len(gets), maxObservationResults)
	}

	tooMany := append(append([]ObserverIdentity(nil), observers...), dynamoObserverIdentity(fmt.Sprintf("controller-%03d", maxObservationResults)))
	if _, err := NewDynamoDBStore(newFakeDynamoDB(), "controller-state", NewFakeClock(dynamoTestTime), time.Second, tooMany...); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("NewDynamoDBStore() error = %v, want configured observer bound error", err)
	}
}

func TestDynamoDBStoreAppliesTimeoutToEveryAPIAttempt(t *testing.T) {
	api := &deadlineRecordingDynamoDB{delegate: newFakeDynamoDB()}
	clock := NewFakeClock(dynamoTestTime)
	const timeout = time.Second
	dynamo, err := NewDynamoDBStore(
		api,
		"controller-state",
		clock,
		timeout,
		dynamoObserverIdentity("controller-a"),
		dynamoObserverIdentity("controller-b"),
	)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	initial := dynamoInitialState()
	if _, err := dynamo.CreateDomain(ctx, &initial); err != nil {
		t.Fatal(err)
	}
	if _, err := dynamo.LoadDomain(ctx, dynamoDomainRef()); err != nil {
		t.Fatal(err)
	}
	lease, err := dynamo.AcquireLease(ctx, dynamoDomainRef(), "controller-a", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	clock.Advance(time.Second)
	lease, err = dynamo.RenewLease(ctx, dynamoDomainRef(), LeaseTokenFor(lease), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	state, err := dynamo.LoadDomain(ctx, dynamoDomainRef())
	if err != nil {
		t.Fatal(err)
	}
	dynamoMakeOwnerObserved(state, clock.Now())
	if _, err := dynamo.CompareAndSwapDomain(ctx, dynamoDomainRef(), state.Revision, LeaseTokenFor(lease), state); err != nil {
		t.Fatal(err)
	}
	if _, err := dynamo.TakeoverLease(ctx, dynamoDomainRef(), "controller-b", lease.RecordVersion, time.Minute); err != nil {
		t.Fatal(err)
	}
	observation := dynamoObservation("controller-a", dynamoTopologyHash, 1, clock.Now())
	if _, err := dynamo.PublishObservation(ctx, "deployment-a", &observation); err != nil {
		t.Fatal(err)
	}
	if _, err := dynamo.ListObservations(ctx, ObservationScope{DeploymentID: "deployment-a", TopologyHash: dynamoTopologyHash}); err != nil {
		t.Fatal(err)
	}

	remaining := api.remainingTimeouts()
	if len(remaining) != 14 {
		t.Fatalf("recorded API attempts = %d, want all load/list/publication/lease/CAS attempts", len(remaining))
	}
	for index, value := range remaining {
		if value <= 0 || value > timeout {
			t.Errorf("API attempt %d timeout = %s, want within (0, %s]", index, value, timeout)
		}
	}
}

func TestDynamoDBStoreDistinguishesAPITimeoutFromCallerContext(t *testing.T) {
	if _, err := NewDynamoDBStore(newFakeDynamoDB(), "controller-state", NewFakeClock(dynamoTestTime), 0); err == nil || !strings.Contains(err.Error(), "timeout") {
		t.Fatalf("NewDynamoDBStore() error = %v, want timeout validation error", err)
	}

	t.Run("store timeout", func(t *testing.T) {
		api := &blockingDynamoDB{started: make(chan struct{})}
		dynamo, err := NewDynamoDBStore(api, "controller-state", NewFakeClock(dynamoTestTime), 20*time.Millisecond)
		if err != nil {
			t.Fatal(err)
		}
		_, err = dynamo.LoadDomain(context.Background(), dynamoDomainRef())
		requireStoreAPITimeout(t, err, "DynamoDB GetItem")
	})

	t.Run("caller cancellation", func(t *testing.T) {
		api := &blockingDynamoDB{started: make(chan struct{})}
		dynamo, err := NewDynamoDBStore(api, "controller-state", NewFakeClock(dynamoTestTime), time.Second)
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		result := make(chan error, 1)
		go func() {
			_, loadErr := dynamo.LoadDomain(ctx, dynamoDomainRef())
			result <- loadErr
		}()
		<-api.started
		cancel()
		if err := <-result; !errors.Is(err, context.Canceled) || errors.Is(err, ErrAPITimeout) {
			t.Fatalf("LoadDomain() error = %v, want caller cancellation only", err)
		}
	})

	t.Run("caller deadline", func(t *testing.T) {
		api := &blockingDynamoDB{started: make(chan struct{})}
		dynamo, err := NewDynamoDBStore(api, "controller-state", NewFakeClock(dynamoTestTime), time.Second)
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
		defer cancel()
		_, err = dynamo.LoadDomain(ctx, dynamoDomainRef())
		if !errors.Is(err, context.DeadlineExceeded) || errors.Is(err, ErrAPITimeout) {
			t.Fatalf("LoadDomain() error = %v, want caller deadline only", err)
		}
	})
}

func TestDynamoDBStoreTimesOutWrites(t *testing.T) {
	api := &blockingDynamoDB{started: make(chan struct{})}
	dynamo, err := NewDynamoDBStore(api, "controller-state", NewFakeClock(dynamoTestTime), 20*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	initial := dynamoInitialState()
	_, err = dynamo.CreateDomain(context.Background(), &initial)
	requireStoreAPITimeout(t, err, "DynamoDB PutItem")
}

func TestDynamoDBStoreReturnsAmbiguousTransportErrorsWithoutPretendingSuccess(t *testing.T) {
	transportErr := errors.New("connection reset after request write")
	api := newFakeDynamoDB()
	api.putError = transportErr
	api.applyPutBeforeError = true
	dynamo := newDynamoDBStoreForTest(t, api, NewFakeClock(dynamoTestTime))
	initial := dynamoInitialState()
	created, err := dynamo.CreateDomain(context.Background(), &initial)
	if created != nil || !errors.Is(err, transportErr) {
		t.Fatalf("CreateDomain() = (%#v, %v), want wrapped transport error", created, err)
	}
	if api.itemCount() != 1 {
		t.Fatal("fake did not simulate an applied write with a lost response")
	}

	api.putError = nil
	current, err := dynamo.LoadDomain(context.Background(), dynamoDomainRef())
	if err != nil {
		t.Fatalf("LoadDomain() after ambiguous create error = %v", err)
	}
	api.putError = transportErr
	lease, err := dynamo.AcquireLease(context.Background(), dynamoDomainRef(), "controller-a", time.Minute)
	if lease != nil || !errors.Is(err, transportErr) {
		t.Fatalf("AcquireLease() = (%#v, %v), want wrapped transport error", lease, err)
	}
	api.putError = nil
	current, err = dynamo.LoadDomain(context.Background(), dynamoDomainRef())
	if err != nil {
		t.Fatalf("LoadDomain() error = %v", err)
	}
	if current.Lease == nil || current.Lease.HolderID != "controller-a" {
		t.Fatalf("fake did not retain the ambiguously applied lease: %#v", current)
	}
}

type fakeDynamoDB struct {
	mu                       sync.Mutex
	items                    map[string]map[string]types.AttributeValue
	getCalls                 []*dynamodb.GetItemInput
	putCalls                 []*dynamodb.PutItemInput
	putError                 error
	applyPutBeforeError      bool
	omitConditionFailureItem bool
	beforePut                func(*fakeDynamoDB, *dynamodb.PutItemInput)
}

type deadlineRecordingDynamoDB struct {
	delegate  *fakeDynamoDB
	mu        sync.Mutex
	remaining []time.Duration
}

func (d *deadlineRecordingDynamoDB) record(ctx context.Context) {
	deadline, found := ctx.Deadline()
	remaining := time.Duration(0)
	if found {
		remaining = time.Until(deadline)
	}
	d.mu.Lock()
	d.remaining = append(d.remaining, remaining)
	d.mu.Unlock()
}

func (d *deadlineRecordingDynamoDB) GetItem(ctx context.Context, input *dynamodb.GetItemInput, options ...func(*dynamodb.Options)) (*dynamodb.GetItemOutput, error) {
	d.record(ctx)
	return d.delegate.GetItem(ctx, input, options...)
}

func (d *deadlineRecordingDynamoDB) PutItem(ctx context.Context, input *dynamodb.PutItemInput, options ...func(*dynamodb.Options)) (*dynamodb.PutItemOutput, error) {
	d.record(ctx)
	return d.delegate.PutItem(ctx, input, options...)
}

func (d *deadlineRecordingDynamoDB) remainingTimeouts() []time.Duration {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]time.Duration(nil), d.remaining...)
}

type blockingDynamoDB struct {
	started chan struct{}
	once    sync.Once
}

func (d *blockingDynamoDB) GetItem(ctx context.Context, _ *dynamodb.GetItemInput, _ ...func(*dynamodb.Options)) (*dynamodb.GetItemOutput, error) {
	d.once.Do(func() { close(d.started) })
	<-ctx.Done()
	return nil, errors.New("adapter hid context termination")
}

func (d *blockingDynamoDB) PutItem(ctx context.Context, _ *dynamodb.PutItemInput, _ ...func(*dynamodb.Options)) (*dynamodb.PutItemOutput, error) {
	d.once.Do(func() { close(d.started) })
	<-ctx.Done()
	return nil, errors.New("adapter hid context termination")
}

func newFakeDynamoDB() *fakeDynamoDB {
	return &fakeDynamoDB{items: make(map[string]map[string]types.AttributeValue)}
}

func (f *fakeDynamoDB) GetItem(_ context.Context, input *dynamodb.GetItemInput, _ ...func(*dynamodb.Options)) (*dynamodb.GetItemOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.getCalls = append(f.getCalls, input)
	return &dynamodb.GetItemOutput{Item: cloneDynamoItem(f.items[fakeItemKey(input.Key)])}, nil
}

func (f *fakeDynamoDB) PutItem(_ context.Context, input *dynamodb.PutItemInput, _ ...func(*dynamodb.Options)) (*dynamodb.PutItemOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.putCalls = append(f.putCalls, input)
	if f.putError != nil {
		if f.applyPutBeforeError {
			f.items[fakeItemKey(input.Item)] = cloneDynamoItem(input.Item)
		}
		return nil, f.putError
	}
	if f.beforePut != nil {
		f.beforePut(f, input)
	}
	key := fakeItemKey(input.Item)
	current := f.items[key]
	if !fakeConditionMatches(input, current) {
		var item map[string]types.AttributeValue
		if !f.omitConditionFailureItem {
			item = cloneDynamoItem(current)
		}
		return nil, &types.ConditionalCheckFailedException{Item: item}
	}
	f.items[key] = cloneDynamoItem(input.Item)
	return &dynamodb.PutItemOutput{}, nil
}

func (f *fakeDynamoDB) seed(item map[string]types.AttributeValue) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.items[fakeItemKey(item)] = cloneDynamoItem(item)
}

func (f *fakeDynamoDB) calls() ([]*dynamodb.PutItemInput, []*dynamodb.GetItemInput) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]*dynamodb.PutItemInput(nil), f.putCalls...), append([]*dynamodb.GetItemInput(nil), f.getCalls...)
}

func (f *fakeDynamoDB) itemCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.items)
}

func fakeConditionMatches(input *dynamodb.PutItemInput, current map[string]types.AttributeValue) bool {
	expression := stringValue(input.ConditionExpression)
	if expression == "attribute_not_exists(#pk) OR #phase = :complete" {
		return len(current) == 0 || fakeEqualExpression(input, current, "#phase", ":complete")
	}
	if expression == "#payload = :before" {
		return len(current) > 0 && fakeEqualExpression(input, current, "#payload", ":before")
	}
	if expression == "#payload = :lock" {
		return len(current) > 0 && fakeEqualExpression(input, current, "#payload", ":lock")
	}
	if expression == "#payload = :old AND #version = :version" {
		return len(current) > 0 && fakeEqualExpression(input, current, "#payload", ":old") && fakeEqualExpression(input, current, "#version", ":version")
	}
	if expression == "attribute_not_exists(#pk)" {
		return len(current) == 0
	}
	if strings.HasPrefix(expression, "attribute_not_exists(#pk) OR") {
		if len(current) == 0 {
			return true
		}
		return fakeEqualExpression(input, current, "#record_type", ":record_type") &&
			fakeEqualExpression(input, current, "#topology_hash", ":topology_hash") &&
			fakeUintAttribute(current[attributeSequence]) < fakeUintAttribute(input.ExpressionAttributeValues[":sequence"])
	}
	if len(current) == 0 {
		return false
	}
	for _, comparison := range [][2]string{
		{"#record_type", ":record_type"},
		{"#topology_hash", ":topology_hash"},
		{"#item_version", ":item_version"},
		{"#document_revision", ":document_revision"},
		{"#fence_term", ":fence_term"},
		{"#lease_holder", ":lease_holder"},
		{"#lease_fence_term", ":lease_fence_term"},
		{"#lease_record_version", ":lease_record_version"},
		{"#lease_record_version", ":expected_lease_record_version"},
	} {
		clause := comparison[0] + " = " + comparison[1]
		if strings.Contains(expression, clause) && !fakeEqualExpression(input, current, comparison[0], comparison[1]) {
			return false
		}
	}
	for _, placeholder := range []string{"#lease_holder", "#lease_record_version"} {
		if strings.Contains(expression, "attribute_not_exists("+placeholder+")") {
			if _, exists := current[input.ExpressionAttributeNames[placeholder]]; exists {
				return false
			}
		}
	}
	if strings.Contains(expression, "#lease_expires_at > :now") {
		expires := fakeIntAttribute(current[input.ExpressionAttributeNames["#lease_expires_at"]])
		now := fakeIntAttribute(input.ExpressionAttributeValues[":now"])
		if expires <= now {
			return false
		}
	}
	return true
}

func fakeEqualExpression(input *dynamodb.PutItemInput, current map[string]types.AttributeValue, namePlaceholder, valuePlaceholder string) bool {
	name := input.ExpressionAttributeNames[namePlaceholder]
	return reflect.DeepEqual(current[name], input.ExpressionAttributeValues[valuePlaceholder])
}

func fakeItemKey(item map[string]types.AttributeValue) string {
	return fakeStringAttribute(item[attributePartitionKey]) + "\x00" + fakeStringAttribute(item[attributeSortKey])
}

func fakeStringAttribute(attribute types.AttributeValue) string {
	if value, ok := attribute.(*types.AttributeValueMemberS); ok {
		return value.Value
	}
	return ""
}

func fakeUintAttribute(attribute types.AttributeValue) uint64 {
	value, ok := attribute.(*types.AttributeValueMemberN)
	if !ok {
		return 0
	}
	parsed, _ := strconv.ParseUint(value.Value, 10, 64)
	return parsed
}

func fakeIntAttribute(attribute types.AttributeValue) int64 {
	value, ok := attribute.(*types.AttributeValueMemberN)
	if !ok {
		return 0
	}
	parsed, _ := strconv.ParseInt(value.Value, 10, 64)
	return parsed
}

func cloneDynamoItem(item map[string]types.AttributeValue) map[string]types.AttributeValue {
	if item == nil {
		return nil
	}
	clone := make(map[string]types.AttributeValue, len(item))
	for name, attribute := range item {
		clone[name] = cloneDynamoAttribute(attribute)
	}
	return clone
}

func cloneDynamoAttribute(attribute types.AttributeValue) types.AttributeValue {
	switch value := attribute.(type) {
	case *types.AttributeValueMemberS:
		return &types.AttributeValueMemberS{Value: value.Value}
	case *types.AttributeValueMemberN:
		return &types.AttributeValueMemberN{Value: value.Value}
	case *types.AttributeValueMemberB:
		return &types.AttributeValueMemberB{Value: append([]byte(nil), value.Value...)}
	default:
		return attribute
	}
}

func newDynamoDBStoreForTest(t *testing.T, api *fakeDynamoDB, clock Clock, observers ...ObserverIdentity) *DynamoDBStore {
	t.Helper()
	dynamo, err := NewDynamoDBStore(api, "controller-state", clock, time.Second, observers...)
	if err != nil {
		t.Fatalf("NewDynamoDBStore() error = %v", err)
	}
	return dynamo
}

func createDynamoDomain(t *testing.T, dynamo *DynamoDBStore) {
	t.Helper()
	initial := dynamoInitialState()
	if _, err := dynamo.CreateDomain(context.Background(), &initial); err != nil {
		t.Fatalf("CreateDomain() error = %v", err)
	}
}

func dynamoDomainRef() DomainRef {
	return DomainRef{DeploymentID: "deployment-a", DomainID: "domain-a", TopologyHash: dynamoTopologyHash}
}

func dynamoObserverIdentity(controllerID string) ObserverIdentity {
	return ObserverIdentity{DeploymentID: "deployment-a", TopologyHash: dynamoTopologyHash, ControllerID: controllerID}
}

func dynamoInitialState() model.DomainState {
	return model.DomainState{
		Activated: true,
		Authority: model.DomainAuthority{
			TopologyHash:            dynamoTopologyHash,
			DeploymentID:            "deployment-a",
			DomainID:                "domain-a",
			SiteID:                  "site-a",
			VPCID:                   "vpc-a",
			Region:                  "us-west-2",
			SourcePrefix:            "10.0.0.0/24",
			RouteTableID:            "rtb-a",
			GWLBESubnetID:           "subnet-gwlbe-a",
			RouteTableAssociationID: "rtbassoc-gwlbe-a",
			RemotePrefixes:          []string{"10.1.0.0/24", "10.1.1.0/24"},
			PreferredOwner:          "node-a",
			Owners: []model.OwnerAuthority{
				{RouterID: "router-a", StableNodeID: "node-a", InstanceID: "i-a", ENIID: "eni-a", VPCID: "vpc-a", SubnetID: "subnet-a", AvailabilityZone: "us-west-2a", Region: "us-west-2"},
				{RouterID: "router-b", StableNodeID: "node-b", InstanceID: "i-b", ENIID: "eni-b", VPCID: "vpc-a", SubnetID: "subnet-b", AvailabilityZone: "us-west-2b", Region: "us-west-2"},
			},
		},
		Revision:         1,
		Phase:            model.PhaseStable,
		StableOwner:      "node-a",
		LastTransitionAt: dynamoTestTime,
		UpdatedAt:        dynamoTestTime,
	}
}

func dynamoObservation(controllerID, topologyHash string, sequence uint64, capturedAt time.Time) model.Observation {
	return model.Observation{
		ControllerID:   controllerID,
		TopologyHash:   topologyHash,
		Sequence:       sequence,
		CapturedAt:     capturedAt,
		ExpiresAt:      capturedAt.Add(time.Minute),
		BackendHealthy: true,
		Domains: map[string]model.OwnerObservation{
			"domain-a": dynamoOwnerObservation(),
		},
	}
}

func dynamoOwnerObservation() model.OwnerObservation {
	return model.OwnerObservation{
		StableNodeID:       "node-a",
		SolePrimary:        true,
		Online:             true,
		Healthy:            true,
		AdvertisedPrefixes: []string{"10.0.0.0/24"},
		EnabledPrefixes:    []string{"10.0.0.0/24"},
	}
}

func dynamoMakeOwnerObserved(state *model.DomainState, at time.Time) {
	state.Phase = model.PhaseOwnerObserved
	state.ObservedOwner = "node-b"
	state.OwnerObservedAt = &at
	state.LastTransitionAt = at
	state.UpdatedAt = at
}

func requireDynamoTypedError[T error](t *testing.T, err, target error) T {
	t.Helper()
	if !errors.Is(err, target) {
		t.Fatalf("error = %v, want errors.Is(%v)", err, target)
	}
	var typed T
	if !errors.As(err, &typed) {
		t.Fatalf("error type = %T, want typed error", err)
	}
	return typed
}

func requireStoreAPITimeout(t *testing.T, err error, operation string) {
	t.Helper()
	if !errors.Is(err, ErrAPITimeout) {
		t.Fatalf("error = %v, want errors.Is(ErrAPITimeout)", err)
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		t.Fatalf("store-local API timeout retained context cancellation identity: %v", err)
	}
	var timeout *APITimeoutError
	if !errors.As(err, &timeout) || timeout.Operation != operation {
		t.Fatalf("error = %v, want APITimeoutError for %q", err, operation)
	}
}

func requireExpressionContains(t *testing.T, expression *string, fragments ...string) {
	t.Helper()
	for _, fragment := range fragments {
		if !strings.Contains(stringValue(expression), fragment) {
			t.Fatalf("expression %q does not contain %q", stringValue(expression), fragment)
		}
	}
}

func requireNoUnusedExpressionNames(t *testing.T, input *dynamodb.PutItemInput) {
	t.Helper()
	expression := stringValue(input.ConditionExpression)
	for placeholder := range input.ExpressionAttributeNames {
		if !strings.Contains(expression, placeholder) {
			t.Fatalf("condition %q has unused name placeholder %q", expression, placeholder)
		}
	}
}

func stringValue(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}
