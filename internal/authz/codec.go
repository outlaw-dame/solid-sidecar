package authz

import (
	"bytes"
	"encoding/json"
	"fmt"
)

func EncodeRequest(request Request) ([]byte, error) {
	if err := ValidateRequest(request); err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(request)
	if err != nil {
		return nil, fmt.Errorf("encode authz request: %w", err)
	}
	return encoded, nil
}

func DecodeRequest(input []byte) (Request, error) {
	var request Request
	decoder := json.NewDecoder(bytes.NewReader(input))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		return Request{}, fmt.Errorf("decode authz request: %w", err)
	}
	if decoder.More() {
		return Request{}, fmt.Errorf("decode authz request: trailing data")
	}
	if err := ValidateRequest(request); err != nil {
		return Request{}, err
	}
	return request, nil
}

func EncodeDecision(decision Decision) ([]byte, error) {
	if err := ValidateDecision(decision); err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(decision)
	if err != nil {
		return nil, fmt.Errorf("encode authz decision: %w", err)
	}
	return encoded, nil
}

func DecodeDecision(input []byte) (Decision, error) {
	var decision Decision
	decoder := json.NewDecoder(bytes.NewReader(input))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&decision); err != nil {
		return Decision{}, fmt.Errorf("decode authz decision: %w", err)
	}
	if decoder.More() {
		return Decision{}, fmt.Errorf("decode authz decision: trailing data")
	}
	if err := ValidateDecision(decision); err != nil {
		return Decision{}, err
	}
	return decision, nil
}
