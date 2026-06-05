package authz

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
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
	if err := ensureEOF(decoder, "authz request"); err != nil {
		return Request{}, err
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
	if err := ensureEOF(decoder, "authz decision"); err != nil {
		return Decision{}, err
	}
	if err := ValidateDecision(decision); err != nil {
		return Decision{}, err
	}
	return decision, nil
}

func ensureEOF(decoder *json.Decoder, label string) error {
	var extra struct{}
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return fmt.Errorf("decode %s: trailing data", label)
		}
		return fmt.Errorf("decode %s: trailing data: %w", label, err)
	}
	return nil
}
