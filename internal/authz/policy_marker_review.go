package authz

import (
	"fmt"
	"strings"
)

const PolicyFixtureMarkerReviewSchemaVersion = "policy.fixture.marker_review.v1"

type PolicyFixtureMarkerStatus string

const (
	PolicyFixtureMarkerOK     PolicyFixtureMarkerStatus = "ok"
	PolicyFixtureMarkerFailed PolicyFixtureMarkerStatus = "failed"
)

type PolicyFixtureMarkerReview struct {
	SchemaVersion string                    `json:"schema_version"`
	Status        PolicyFixtureMarkerStatus `json:"status"`
	LogHash       string                    `json:"log_hash"`
	RecordCount   int                       `json:"record_count"`
	CheckedAtUnix int64                     `json:"checked_at_unix"`
	FixtureOnly   bool                      `json:"fixture_only"`
	ReviewHash    string                    `json:"review_hash"`
}

func PolicyFixtureMarkerReviewForLog(log PolicyFixtureMarkerLog, checkedAtUnix int64) (PolicyFixtureMarkerReview, error) {
	if checkedAtUnix < 0 {
		return PolicyFixtureMarkerReview{}, fmt.Errorf("%w: negative marker review time", ErrInvalidPolicyFixtureRelease)
	}
	status := PolicyFixtureMarkerOK
	if ValidatePolicyFixtureMarkerLog(log) != nil {
		status = PolicyFixtureMarkerFailed
	}
	review := PolicyFixtureMarkerReview{SchemaVersion: PolicyFixtureMarkerReviewSchemaVersion, Status: status, LogHash: log.LogHash, RecordCount: len(log.Records), CheckedAtUnix: checkedAtUnix, FixtureOnly: true}
	review.ReviewHash = PolicyFixtureMarkerReviewHash(review)
	if err := ValidatePolicyFixtureMarkerReview(review); err != nil {
		return PolicyFixtureMarkerReview{}, err
	}
	return review, nil
}

func ValidatePolicyFixtureMarkerReview(review PolicyFixtureMarkerReview) error {
	if review.SchemaVersion != PolicyFixtureMarkerReviewSchemaVersion || !review.FixtureOnly {
		return fmt.Errorf("%w: invalid marker review metadata", ErrInvalidPolicyFixtureRelease)
	}
	if review.Status != PolicyFixtureMarkerOK && review.Status != PolicyFixtureMarkerFailed {
		return fmt.Errorf("%w: invalid marker review status", ErrInvalidPolicyFixtureRelease)
	}
	if !validSHA256Hex(review.LogHash) || !validSHA256Hex(review.ReviewHash) || review.RecordCount < 0 || review.CheckedAtUnix < 0 {
		return fmt.Errorf("%w: invalid marker review values", ErrInvalidPolicyFixtureRelease)
	}
	if PolicyFixtureMarkerReviewHash(review) != review.ReviewHash {
		return fmt.Errorf("%w: marker review hash mismatch", ErrInvalidPolicyFixtureRelease)
	}
	return nil
}

func PolicyFixtureMarkerReviewHash(review PolicyFixtureMarkerReview) string {
	parts := []string{review.SchemaVersion, string(review.Status), review.LogHash, fmt.Sprintf("%020d", review.RecordCount), fmt.Sprintf("%020d", review.CheckedAtUnix)}
	return sha256Hex(strings.Join(parts, "\x1f"))
}
