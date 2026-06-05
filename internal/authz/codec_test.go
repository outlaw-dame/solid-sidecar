package authz

import (
	"bytes"
	"testing"
)

func TestRequestCodecRoundTripSharedFixture(t *testing.T) {
	request := readFixture[Request](t, "authz_request.valid.json")
	encoded, err := EncodeRequest(request)
	if err != nil {
		t.Fatalf("EncodeRequest returned error: %v", err)
	}
	decoded, err := DecodeRequest(encoded)
	if err != nil {
		t.Fatalf("DecodeRequest returned error: %v", err)
	}
	if decoded.SchemaVersion != request.SchemaVersion || decoded.RequestID != request.RequestID || decoded.ResourceURI != request.ResourceURI {
		t.Fatalf("decoded request mismatch: %+v", decoded)
	}
}

func TestDecisionCodecRoundTripSharedFixture(t *testing.T) {
	decision := readFixture[Decision](t, "authz_decision.shadow.json")
	encoded, err := EncodeDecision(decision)
	if err != nil {
		t.Fatalf("EncodeDecision returned error: %v", err)
	}
	decoded, err := DecodeDecision(encoded)
	if err != nil {
		t.Fatalf("DecodeDecision returned error: %v", err)
	}
	if decoded != decision {
		t.Fatalf("decoded decision mismatch: got %+v, want %+v", decoded, decision)
	}
}

func TestDecodeRequestRejectsUnknownField(t *testing.T) {
	input := []byte(`{"schema_version":"authz.v1","request_id":"req","method":"GET","resource_uri":"https://pod.example/card","requested_modes":["read"],"now_unix":1,"extra":true}`)
	if _, err := DecodeRequest(input); err == nil {
		t.Fatal("expected unknown request field to be rejected")
	}
}

func TestDecodeDecisionRejectsUnknownField(t *testing.T) {
	input := []byte(`{"schema_version":"authz.v1","request_id":"req","decision":"abstain","reason_code":"kernel_abstain_shadow_mode","cache_ttl_seconds":0,"audit":{"request_hash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","policy_hash":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"},"extra":true}`)
	if _, err := DecodeDecision(input); err == nil {
		t.Fatal("expected unknown decision field to be rejected")
	}
}

func TestDecodeRequestRejectsTrailingJSON(t *testing.T) {
	request := readFixture[Request](t, "authz_request.valid.json")
	encoded, err := EncodeRequest(request)
	if err != nil {
		t.Fatalf("EncodeRequest returned error: %v", err)
	}
	encoded = append(encoded, []byte(` {}`)...)
	if _, err := DecodeRequest(encoded); err == nil {
		t.Fatal("expected trailing request JSON to be rejected")
	}
}

func TestEncodeRequestRejectsInvalidRequest(t *testing.T) {
	if _, err := EncodeRequest(Request{}); err == nil {
		t.Fatal("expected invalid request to be rejected")
	}
}

func TestEncodeDecisionIsCompactJSON(t *testing.T) {
	decision := readFixture[Decision](t, "authz_decision.shadow.json")
	encoded, err := EncodeDecision(decision)
	if err != nil {
		t.Fatalf("EncodeDecision returned error: %v", err)
	}
	if bytes.ContainsAny(encoded, "\n\t") {
		t.Fatalf("expected compact JSON, got %q", string(encoded))
	}
}
