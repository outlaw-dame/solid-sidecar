package authz

import (
	"context"
	"errors"
	"sync"
	"time"
)

const (
	DefaultBackoffEvaluatorBaseDelay = 500 * time.Millisecond
	DefaultBackoffEvaluatorMaxDelay  = 30 * time.Second
)

var ErrEvaluatorBackoffActive = errors.New("authz evaluator backoff active")

type BackoffEvaluatorOptions struct {
	Evaluator Evaluator
	BaseDelay time.Duration
	MaxDelay  time.Duration
	Now       func() time.Time
}

type BackoffEvaluator struct {
	evaluator Evaluator
	baseDelay time.Duration
	maxDelay  time.Duration
	now       func() time.Time

	mu          sync.Mutex
	failures    int
	nextAllowed time.Time
}

func NewBackoffEvaluator(options BackoffEvaluatorOptions) (*BackoffEvaluator, error) {
	if options.Evaluator == nil {
		return nil, errors.New("authz backoff evaluator requires evaluator")
	}
	baseDelay := options.BaseDelay
	if baseDelay == 0 {
		baseDelay = DefaultBackoffEvaluatorBaseDelay
	}
	maxDelay := options.MaxDelay
	if maxDelay == 0 {
		maxDelay = DefaultBackoffEvaluatorMaxDelay
	}
	if baseDelay <= 0 || maxDelay <= 0 || baseDelay > maxDelay {
		return nil, errors.New("authz backoff evaluator delays must be positive and ordered")
	}
	now := options.Now
	if now == nil {
		now = time.Now
	}
	return &BackoffEvaluator{
		evaluator: options.Evaluator,
		baseDelay: baseDelay,
		maxDelay:  maxDelay,
		now:       now,
	}, nil
}

func (e *BackoffEvaluator) Evaluate(ctx context.Context, request Request) (Decision, error) {
	if err := ctx.Err(); err != nil {
		return Decision{}, err
	}
	if !e.allowAttempt() {
		return Decision{}, ErrEvaluatorBackoffActive
	}
	decision, err := e.evaluator.Evaluate(ctx, request)
	if err != nil {
		e.recordFailure()
		return Decision{}, err
	}
	e.recordSuccess()
	return decision, nil
}

func (e *BackoffEvaluator) allowAttempt() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.nextAllowed.IsZero() || !e.now().Before(e.nextAllowed)
}

func (e *BackoffEvaluator) recordSuccess() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.failures = 0
	e.nextAllowed = time.Time{}
}

func (e *BackoffEvaluator) recordFailure() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.failures++
	e.nextAllowed = e.now().Add(e.delayForFailuresLocked())
}

func (e *BackoffEvaluator) delayForFailuresLocked() time.Duration {
	shift := e.failures - 1
	if shift > 30 {
		return e.maxDelay
	}
	delay := e.baseDelay
	for i := 0; i < shift; i++ {
		if delay >= e.maxDelay/2 {
			return e.maxDelay
		}
		delay *= 2
	}
	if delay > e.maxDelay {
		return e.maxDelay
	}
	return delay
}
