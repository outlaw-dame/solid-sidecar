// Package storage provides the production storage engine for the Solid runtime.
// This file implements the transaction functionality.
package storage

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
)

// storageTransaction implements the Transaction interface
type storageTransaction struct {
	engine   *storageEngineImpl
	ctx      context.Context
	pending  map[string]*WriteResource
	deleted  map[string]bool
	committed bool
	rolledBack bool
	logger   *slog.Logger
}

// Get retrieves a resource within the transaction
func (t *storageTransaction) Get(ctx context.Context, uri string) (*Resource, error) {
	// First check if the resource is in the pending writes
	if pending, exists := t.pending[uri]; exists {
		return &Resource{
			URI:      pending.URI,
			Body:     pending.Body,
			Metadata: pending.Metadata,
		}, nil
	}

	// Check if the resource was deleted in this transaction
	if t.deleted[uri] {
		return nil, ErrNotFound
	}

	// Fall back to the engine's Get method
	readResource, err := t.engine.Get(ctx, uri)
	if err != nil {
		return nil, err
	}
	return &Resource{
		URI:      readResource.URI,
		Body:     readResource.Body,
		Metadata: readResource.Metadata,
	}, nil
}

// Put stores a resource within the transaction
func (t *storageTransaction) Put(ctx context.Context, resource *WriteResource) error {
	if t.committed || t.rolledBack {
		return fmt.Errorf("transaction already completed")
	}
	
	// Store in pending
	t.pending[resource.URI] = resource
	return nil
}

// Delete removes a resource within the transaction
func (t *storageTransaction) Delete(ctx context.Context, uri string) error {
	if t.committed || t.rolledBack {
		return fmt.Errorf("transaction already completed")
	}
	
	// Mark as deleted
	t.deleted[uri] = true
	// Also remove from pending in case it was added in this transaction
	delete(t.pending, uri)
	return nil
}

// Commit commits the transaction
func (t *storageTransaction) Commit(ctx context.Context) error {
	if t.committed {
		return fmt.Errorf("transaction already committed")
	}
	if t.rolledBack {
		return fmt.Errorf("transaction was rolled back")
	}

	t.committed = true

	// Apply all pending operations
	for uri, resource := range t.pending {
		if err := t.engine.defaultBackend.Put(ctx, uri, resource); err != nil {
			// Rollback on error
			t.rolledBack = true
			t.committed = false
			return fmt.Errorf("failed to commit transaction: %w", err)
		}
	}

	// Apply all deletions
	for uri := range t.deleted {
		if err := t.engine.defaultBackend.Delete(ctx, uri); err != nil && !errors.Is(err, ErrNotFound) {
			// Rollback on error
			t.rolledBack = true
			t.committed = false
			return fmt.Errorf("failed to commit transaction: %w", err)
		}
	}

	t.engine.metrics.TransactionsCommitted++
	t.logger.Info("Transaction committed")
	return nil
}

// Rollback rolls back the transaction
func (t *storageTransaction) Rollback(ctx context.Context) error {
	if t.rolledBack {
		return fmt.Errorf("transaction already rolled back")
	}
	if t.committed {
		return fmt.Errorf("transaction already committed")
	}

	t.rolledBack = true
	t.pending = make(map[string]*WriteResource)
	t.deleted = make(map[string]bool)

	t.engine.metrics.TransactionsRolledBack++
	t.logger.Info("Transaction rolled back")
	return nil
}