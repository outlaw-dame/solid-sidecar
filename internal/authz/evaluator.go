package authz

import (
	"context"
)

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

	audit := AuditForRequest(request)
	if request.SchemaVersion != SchemaVersion {
		return shadowDecision(request, audit, DecisionDeny, ReasonUnsupportedSchema, httpBadRequestStatus), nil
	}
	if !validToken(request.RequestID, 128) || !supportedMethod(request.Method) {
		return shadowDecision(request, audit, DecisionDeny, ReasonInvalidRequest, httpBadRequestStatus), nil
	}
	if len(request.RequestedModes) == 0 {
		return shadowDecision(request, audit, DecisionDeny, ReasonMissingRequestedModes, httpBadRequestStatus), nil
	}
	if !validResourceURI(request.ResourceURI) {
		return shadowDecision(request, audit, DecisionDeny, ReasonUnsafeResourceURI, httpBadRequestStatus), nil
	}
	if err := ValidateRequest(request); err != nil {
		return shadowDecision(request, audit, DecisionDeny, ReasonInvalidRequest, httpBadRequestStatus), nil
	}
	return shadowDecision(request, audit, DecisionAbstain, ReasonKernelAbstainShadowMode, 0), nil
}

func shadowDecision(request Request, audit AuditFields, decision DecisionValue, reason ReasonCode, statusHint int) Decision {
	return Decision{
		SchemaVersion:    SchemaVersion,
		RequestID:        request.RequestID,
		Decision:         decision,
		ReasonCode:       reason,
		StatusHint:       statusHint,
		CacheTTLSeconds:  0,
		PolicyVersion:    request.PolicyVersion,
		ResourceVersion:  request.ResourceVersion,
		Audit:            audit,
	}
}

func supportedMethod(method string) bool {
	_, err := modesForMethod(method)
	return err == nil
}

func ShouldContinueToCSS(decision Decision) bool {
	return decision.Decision == "" || decision.Decision == DecisionAbstain
}

const httpBadRequestStatus = 400
