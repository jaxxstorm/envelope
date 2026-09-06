package store

import (
	"context"
	"errors"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/jaxxstorm/envelope/internal/controller/model"
)

type lifecycleDynamo struct {
	*fakeDynamoDB
	lostResponse      bool
	beforeTransaction func()
}

func (f *lifecycleDynamo) TransactWriteItems(ctx context.Context, input *dynamodb.TransactWriteItemsInput, _ ...func(*dynamodb.Options)) (*dynamodb.TransactWriteItemsOutput, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if f.beforeTransaction != nil {
		f.beforeTransaction()
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(input.TransactItems) < 2 || input.TransactItems[0].ConditionCheck == nil {
		return nil, errors.New("missing lock check")
	}
	for _, item := range input.TransactItems {
		var key map[string]types.AttributeValue
		var condition *string
		var names map[string]string
		var values map[string]types.AttributeValue
		if item.ConditionCheck != nil {
			c := item.ConditionCheck
			key, condition, names, values = c.Key, c.ConditionExpression, c.ExpressionAttributeNames, c.ExpressionAttributeValues
		} else {
			p := item.Put
			key, condition, names, values = p.Item, p.ConditionExpression, p.ExpressionAttributeNames, p.ExpressionAttributeValues
		}
		if !fakeConditionMatches(&dynamodb.PutItemInput{ConditionExpression: condition, ExpressionAttributeNames: names, ExpressionAttributeValues: values}, f.items[fakeItemKey(key)]) {
			return nil, &types.TransactionCanceledException{}
		}
	}
	for _, item := range input.TransactItems {
		if item.Put != nil {
			f.items[fakeItemKey(item.Put.Item)] = cloneDynamoItem(item.Put.Item)
		}
	}
	if f.lostResponse {
		return nil, context.DeadlineExceeded
	}
	return &dynamodb.TransactWriteItemsOutput{}, nil
}

func TestDeploymentLockAndAtomicActivation(t *testing.T) {
	api := &lifecycleDynamo{fakeDynamoDB: newFakeDynamoDB()}
	clock := NewFakeClock(dynamoTestTime)
	durable, err := NewDynamoDBStore(api, "controller-state", clock, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	initial := dynamoInitialState()
	initial.Activated = false
	if _, err := durable.CreateDomain(context.Background(), &initial); err != nil {
		t.Fatal(err)
	}
	lock := DeploymentLock{DeploymentID: "deployment-a", TopologyHash: dynamoTopologyHash, OperationID: "operation-a", Kind: "activate", Phase: "locked"}
	var wg sync.WaitGroup
	errorsCh := make(chan error, 2)
	for range 2 {
		wg.Add(1)
		go func() { defer wg.Done(); errorsCh <- durable.BeginDeployment(context.Background(), lock) }()
	}
	wg.Wait()
	close(errorsCh)
	success := 0
	for err := range errorsCh {
		if err == nil {
			success++
		}
	}
	if success != 1 {
		t.Fatalf("concurrent lock acquisitions=%d", success)
	}
	clock.Advance(24 * time.Hour)
	other := lock
	other.OperationID = "operation-b"
	if durable.BeginDeployment(context.Background(), other) == nil {
		t.Fatal("lock expired automatically")
	}
	before, _ := durable.LoadDomain(context.Background(), dynamoDomainRef())
	after := before.Clone()
	after.Activated = true
	after.UpdatedAt = clock.Now()
	if err := durable.RewriteDeploymentDomains(context.Background(), other, []*model.DomainState{before}, []*model.DomainState{after}); err == nil {
		t.Fatal("wrong lock activated domain")
	}
	if err := durable.RewriteDeploymentDomains(context.Background(), lock, []*model.DomainState{before}, []*model.DomainState{after}); err != nil {
		t.Fatal(err)
	}
	loaded, _ := durable.LoadDomain(context.Background(), dynamoDomainRef())
	if !loaded.Activated || loaded.Revision != before.Revision+1 || loaded.Authority.TopologyHash != dynamoTopologyHash {
		t.Fatalf("activation=%+v", loaded)
	}
	if err := durable.RewriteDeploymentDomains(context.Background(), lock, []*model.DomainState{before}, []*model.DomainState{after}); err == nil {
		t.Fatal("stale snapshot accepted")
	}
	complete := lock
	complete.Phase = "complete"
	if err := durable.AdvanceDeployment(context.Background(), lock, complete); err != nil {
		t.Fatal(err)
	}
	if err := durable.BeginDeployment(context.Background(), other); err != nil {
		t.Fatal(err)
	}
	if durable.AdvanceDeployment(context.Background(), lock, complete) == nil {
		t.Fatal("stale process completed successor lock")
	}
}

func TestDeactivationFencesPausedLeaseAndJournalWriters(t *testing.T) {
	api := &lifecycleDynamo{fakeDynamoDB: newFakeDynamoDB()}
	clock := NewFakeClock(dynamoTestTime)
	durable, _ := NewDynamoDBStore(api, "controller-state", clock, time.Second)
	createDynamoDomain(t, durable)
	lease, err := durable.AcquireLease(context.Background(), dynamoDomainRef(), "controller-a", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	before, _ := durable.LoadDomain(context.Background(), dynamoDomainRef())
	after := before.Clone()
	after.Activated = false
	lock := DeploymentLock{DeploymentID: "deployment-a", TopologyHash: dynamoTopologyHash, OperationID: "deactivate-a", Kind: "deactivate", Phase: "locked"}
	if err := durable.BeginDeployment(context.Background(), lock); err != nil {
		t.Fatal(err)
	}
	if err := durable.RewriteDeploymentDomains(context.Background(), lock, []*model.DomainState{before}, []*model.DomainState{after}); err != nil {
		t.Fatal(err)
	}
	if _, err := durable.AcquireLease(context.Background(), dynamoDomainRef(), "controller-b", time.Minute); !errors.Is(err, ErrDomainInactive) {
		t.Fatalf("inactive acquire: %v", err)
	}
	if _, err := durable.TakeoverLease(context.Background(), dynamoDomainRef(), "controller-b", lease.RecordVersion, time.Minute); !errors.Is(err, ErrDomainInactive) {
		t.Fatalf("paused contender: %v", err)
	}
	if _, err := durable.RenewLease(context.Background(), dynamoDomainRef(), LeaseTokenFor(lease), time.Minute); !errors.Is(err, ErrDomainInactive) {
		t.Fatalf("paused renewer: %v", err)
	}
	if _, err := durable.CompareAndSwapDomain(context.Background(), dynamoDomainRef(), before.Revision, LeaseTokenFor(lease), before); !errors.Is(err, ErrDomainInactive) {
		t.Fatalf("paused journal writer: %v", err)
	}
	state, _ := durable.LoadDomain(context.Background(), dynamoDomainRef())
	if state.Activated || state.Lease.RecordVersion != lease.RecordVersion || state.FenceTerm != lease.FenceTerm {
		t.Fatal("inactive state was reactivated or renewed")
	}
}

func TestDeploymentTransactionsRetainJournalOnAmbiguityAndContention(t *testing.T) {
	for _, mode := range []string{"lost-response", "item-version-changed", "journal-change", "active-migration", "wrong-phase", "valid-migration"} {
		t.Run(mode, func(t *testing.T) {
			api := &lifecycleDynamo{fakeDynamoDB: newFakeDynamoDB()}
			clock := NewFakeClock(dynamoTestTime)
			durable, _ := NewDynamoDBStore(api, "controller-state", clock, time.Second)
			initial := dynamoInitialState()
			initial.Activated = false
			if _, err := durable.CreateDomain(context.Background(), &initial); err != nil {
				t.Fatal(err)
			}
			lock := DeploymentLock{DeploymentID: "deployment-a", TopologyHash: dynamoTopologyHash, OperationID: "operation-a", Kind: "migrate", Phase: "locked"}
			if err := durable.BeginDeployment(context.Background(), lock); err != nil {
				t.Fatal(err)
			}
			quiescent := lock
			quiescent.Phase = "quiescent"
			if mode != "wrong-phase" {
				if err := durable.AdvanceDeployment(context.Background(), lock, quiescent); err != nil {
					t.Fatal(err)
				}
				lock = quiescent
			}
			before, _ := durable.LoadDomain(context.Background(), dynamoDomainRef())
			after := before.Clone()
			after.Authority.TopologyHash = dynamoOtherHash
			switch mode {
			case "lost-response":
				api.lostResponse = true
			case "item-version-changed":
				api.beforeTransaction = func() {
					api.mu.Lock()
					defer api.mu.Unlock()
					item := api.items[fakeItemKey(domainItemKey("deployment-a", "domain-a"))]
					item["item_version"] = numberAttribute(fakeUintAttribute(item["item_version"]) + 1)
				}
			case "journal-change":
				after.Phase = model.PhaseOwnerObserved
			case "active-migration":
				after.Activated = true
			}
			err := durable.RewriteDeploymentDomains(context.Background(), lock, []*model.DomainState{before}, []*model.DomainState{after})
			if (err == nil) != (mode == "valid-migration") {
				t.Fatalf("transaction=%v", err)
			}
			retained, err := durable.ReadDeployment(context.Background(), lock.DeploymentID)
			if err != nil || retained != lock {
				t.Fatal("uncertain transaction released lock")
			}
			ref := dynamoDomainRef()
			if mode == "lost-response" || mode == "valid-migration" {
				ref.TopologyHash = dynamoOtherHash
			}
			loaded, err := durable.LoadDomain(context.Background(), ref)
			if err != nil {
				t.Fatal(err)
			}
			if mode == "lost-response" || mode == "valid-migration" {
				if loaded.Revision != before.Revision+1 || loaded.Activated || loaded.FenceTerm != before.FenceTerm {
					t.Fatal("migration discarded fence or activated domain")
				}
			} else if !reflect.DeepEqual(loaded, before) {
				t.Fatal("rejected transaction changed journal")
			}
		})
	}
}
