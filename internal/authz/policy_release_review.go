package authz

import (
	"fmt"
	"strings"
)

const PolicyFixtureReleaseReviewSchemaVersion = "policy.fixture.release_review.v1"

type PolicyFixtureReleaseStatus string

const (
	PolicyFixtureReleaseOK     PolicyFixtureReleaseStatus = "ok"
	PolicyFixtureReleaseFailed PolicyFixtureReleaseStatus = "failed"
)

type PolicyFixtureReleaseReview struct {
	SchemaVersion string                     `json:"schema_version"`
	Status        PolicyFixtureReleaseStatus `json:"status"`
	LedgerHash    string                     `json:"ledger_hash"`
	RecordCount   int                        `json:"record_count"`
	CheckedAtUnix int64                      `json:"checked_at_unix"`
	FixtureOnly   bool                       `json:"fixture_only"`
	ReviewHash    string                     `json:"review_hash"`
}

func PolicyFixtureReleaseReviewForLedger(ledger PolicyFixtureReleaseLedger, checkedAtUnix int64) (PolicyFixtureReleaseReview, error) {
	if checkedAtUnix < 0 {
		return PolicyFixtureReleaseReview{}, fmt.Errorf("%w: negative release review time", ErrInvalidPolicyFixtureRelease)
	}
	status := PolicyFixtureReleaseOK
	if ValidatePolicyFixtureReleaseLedger(ledger) != nil {
		status = PolicyFixtureReleaseFailed
	}
	review := PolicyFixtureReleaseReview{SchemaVersion: PolicyFixtureReleaseReviewSchemaVersion, Status: status, LedgerHash: ledger.LedgerHash, RecordCount: len(ledger.Records), CheckedAtUnix: checkedAtUnix, FixtureOnly: true}
	review.ReviewHash = PolicyFixtureReleaseReviewHash(review)
	if err := ValidatePolicyFixtureReleaseReview(review); err != nil {
		return PolicyFixtureReleaseReview{}, err
	}
	return review, nil
}

func ValidatePolicyFixtureReleaseReview(review PolicyFixtureReleaseReview) error {
	if review.SchemaVersion != PolicyFixtureReleaseReviewSchemaVersion || !review.FixtureOnly {
		return fmt.Errorf("%w: invalid release review metadata", ErrInvalidPolicyFixtureRelease)
	}
	if review.Status != PolicyFixtureReleaseOK && review.Status != PolicyFixtureReleaseFailed {
		return fmt.Errorf("%w: invalid release review status", ErrInvalidPolicyFixtureRelease)
	}
	if !validSHA256Hex(review.LedgerHash) || !validSHA256Hex(review.ReviewHash) || review.RecordCount < 0 || review.CheckedAtUnix < 0 {
		return fmt.Errorf("%w: invalid release review values", ErrInvalidPolicyFixtureRelease)
	}
	if PolicyFixtureReleaseReviewHash(review) != review.ReviewHash {
		return fmt.Errorf("%w: release review hash mismatch", ErrInvalidPolicyFixtureRelease)
	}
	return nil
}

func PolicyFixtureReleaseReviewHash(review PolicyFixtureReleaseReview) string {
	parts := []string{review.SchemaVersion, string(review.Status), review.LedgerHash, fmt.Sprintf("%020d", review.RecordCount), fmt.Sprintf("%020d", review.CheckedAtUnix)}
	return sha256Hex(strings.Join(parts, "\x1f"))
}
