// Package storage provides the production storage engine for the Solid runtime.
// This file contains utility functions.
package storage

import (
	"crypto/sha256"
	"encoding/hex"
)

// sha256Sum computes SHA-256 hash of data
func sha256Sum(data []byte) [32]byte {
	if len(data) == 0 {
		return [32]byte{}
	}
	return sha256.Sum256(data)
}

// computeDigest computes a SHA-256 digest for the given data
func computeDigest(data []byte) string {
	hash := sha256Sum(data)
	return hex.EncodeToString(hash[:])
}

// computeContentAddress computes a content address for the given data
func computeContentAddress(data []byte) ContentAddress {
	return ContentAddress(computeDigest(data))
}

// generateETag generates an ETag for the given data
func generateETag(data []byte) string {
	if len(data) == 0 {
		return "\"0-0\""
	}
	hash := sha256Sum(data)
	return string(hash[:8])
}
