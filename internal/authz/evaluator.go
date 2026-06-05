package authz

import (
	"context"
	"errors"
)

var ErrNilRequest = errors.New("authz request is nil")

type Evaluator interface {
	Evaluate(ctx context.Context, request Request) (Decision, error)
}

type ShadowEvaluator struct{}

func NewShadowEvaluator() ShadowEvaluator {
	return ShadowEvaluator{}
}

func (ShadowEvaluator) Evaluate(ctx context.Context, request Request) (Decision, error) {
	if err := ctx.Err(); err != nil {
		return Decision{}, err
	}
	if request.SchemaVersion == "" || request.RequestID == "" {
		return Decision{}, ErrNilRequest
	}
	return Decision{
		SchemaVersion:   SchemaVersion,
		RequestID:       request.RequestID,
		Decision:        DecisionAbstain,
		ReasonCode:      ReasonKernelAbstainShadowMode,
		CacheTTLSeconds: 0,
		PolicyVersion:   request.PolicyVersion,
		ResourceVersion: request.ResourceVersion,
		Audit:           AuditForRequest(request),
	}, nil
}

func ShouldContinueToCSS(decision Decision) bool {
	return decision.Decision == "" || decision.Decision == DecisionAbstain
}
