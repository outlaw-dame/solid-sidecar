package authz

import "testing"

func TestAuditForRequestMatchesSharedDecisionFixture(t *testing.T) {
	request := readFixture[Request](t, "authz_request.valid.json")
	expected := readFixture[Decision](t, "authz_decision.shadow.json")

	actual := AuditForRequest(request)
	if actual != expected.Audit {
		t.Fatalf("audit mismatch: got %+v, want %+v", actual, expected.Audit)
	}
}

func TestAuditForRequestIsDeterministicForMapAndPolicyOrder(t *testing.T) {
	left := readFixture[Request](t, "authz_request.valid.json")
	right := readFixture[Request](t, "authz_request.valid.json")

	right.PolicyDocuments[0], right.PolicyDocuments[1] = right.PolicyDocuments[1], right.PolicyDocuments[0]
	right.ResourceMetadata = map[string]string{
		"z":         "last",
		"container": "false",
		"a":         "first",
	}
	left.ResourceMetadata = map[string]string{
		"a":         "first",
		"container": "false",
		"z":         "last",
	}

	leftAudit := AuditForRequest(left)
	rightAudit := AuditForRequest(right)

	if leftAudit.RequestHash != rightAudit.RequestHash {
		t.Fatalf("request hash should be deterministic: got %s, want %s", rightAudit.RequestHash, leftAudit.RequestHash)
	}
	if leftAudit.PolicyHash != rightAudit.PolicyHash {
		t.Fatalf("policy hash should be order-independent: got %s, want %s", rightAudit.PolicyHash, leftAudit.PolicyHash)
	}
}

func TestAuditForRequestSeparatesPolicyAndResourceChanges(t *testing.T) {
	base := readFixture[Request](t, "authz_request.valid.json")
	resourceChanged := base
	resourceChanged.ResourceURI = "https://pod.example/alice/other"
	policyChanged := base
	policyChanged.PolicyDocuments = append([]PolicyDocument(nil), base.PolicyDocuments...)
	policyChanged.PolicyDocuments[0].SHA256 = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"

	baseAudit := AuditForRequest(base)
	resourceAudit := AuditForRequest(resourceChanged)
	policyAudit := AuditForRequest(policyChanged)

	if baseAudit.RequestHash == resourceAudit.RequestHash {
		t.Fatal("request hash should change when resource request fields change")
	}
	if baseAudit.PolicyHash != resourceAudit.PolicyHash {
		t.Fatal("policy hash should not change when only resource request fields change")
	}
	if baseAudit.PolicyHash == policyAudit.PolicyHash {
		t.Fatal("policy hash should change when policy document hashes change")
	}
	if baseAudit.RequestHash != policyAudit.RequestHash {
		t.Fatal("request hash should not change when only policy documents change")
	}
}
