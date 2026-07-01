// Package sai implements Solid Application Interoperability (SAI) support.
package sai

import (
	"context"
	"math"
	"math/rand"
	"time"
)

// RetryConfig configures retry behavior with exponential backoff
type RetryConfig struct {
	// MaxRetries is the maximum number of retry attempts (0 = no retries)
	MaxRetries int
	// InitialDelay is the initial delay before the first retry
	InitialDelay time.Duration
	// MaxDelay is the maximum delay between retries
	MaxDelay time.Duration
	// BackoffMultiplier is the multiplier for exponential backoff
	BackoffMultiplier float64
	// Jitter adds randomness to prevent thundering herd
	Jitter bool
}

// DefaultRetryConfig returns safe default retry configuration
func DefaultRetryConfig() RetryConfig {
	return RetryConfig{
		MaxRetries:        3,
		InitialDelay:      100 * time.Millisecond,
		MaxDelay:          10 * time.Second,
		BackoffMultiplier: 2.0,
		Jitter:            true,
	}
}

// WithRetry executes an operation with exponential backoff retries
// Returns the number of attempts and the error (if any)
func WithRetry(ctx context.Context, config RetryConfig, operation func() error) (attempts int, lastErr error) {
	var delay time.Duration = config.InitialDelay

	for attempt := 0; attempt <= config.MaxRetries; attempt++ {
		// Check context cancellation
		if ctxErr := ctx.Err(); ctxErr != nil {
			return attempt + 1, ctxErr
		}

		// Execute the operation
		opErr := operation()
		if opErr == nil {
			return attempt + 1, nil
		}

		// Store the error
		lastErr = opErr

		// Don't retry on the last attempt
		if attempt == config.MaxRetries {
			return attempt + 1, lastErr
		}

		// Calculate delay with exponential backoff
		delay = calculateDelay(delay, config)

		// Apply jitter if enabled
		if config.Jitter {
			delay = applyJitter(delay)
		}

		// Wait for the delay or context cancellation
		select {
		case <-ctx.Done():
			return attempt + 1, ctx.Err()
		case <-time.After(delay):
			// Continue to next retry
		}
	}

	return 0, nil
}

// calculateDelay calculates the next delay with exponential backoff
func calculateDelay(currentDelay time.Duration, config RetryConfig) time.Duration {
	// Calculate next delay: currentDelay * multiplier
	nextDelay := float64(currentDelay) * config.BackoffMultiplier

	// Cap at max delay
	if nextDelay > float64(config.MaxDelay) {
		nextDelay = float64(config.MaxDelay)
	}

	return time.Duration(nextDelay)
}

// applyJitter adds random jitter to the delay to prevent thundering herd
func applyJitter(delay time.Duration) time.Duration {
	// Add jitter: delay * (0.5 + random(0, 0.5))
	// This gives a range of [0.5 * delay, 1.0 * delay]
	jitterFactor := 0.5 + rand.Float64()*0.5
	return time.Duration(float64(delay) * jitterFactor)
}

// RetryOperation provides a simpler interface for retrying operations
func RetryOperation(maxRetries int, operation func() error) error {
	config := RetryConfig{
		MaxRetries:        maxRetries,
		InitialDelay:      100 * time.Millisecond,
		MaxDelay:          10 * time.Second,
		BackoffMultiplier: 2.0,
		Jitter:            true,
	}

	_, err := WithRetry(context.Background(), config, operation)
	return err
}

// CalculateBackoffDelay calculates the delay for a given attempt with exponential backoff
func CalculateBackoffDelay(attempt int, config RetryConfig) time.Duration {
	// Calculate: initialDelay * (multiplier ^ attempt)
	delay := float64(config.InitialDelay) * math.Pow(config.BackoffMultiplier, float64(attempt))

	// Cap at max delay
	if delay > float64(config.MaxDelay) {
		delay = float64(config.MaxDelay)
	}

	// Apply jitter if enabled
	if config.Jitter {
		delay = float64(applyJitter(time.Duration(delay)))
	}

	return time.Duration(delay)
}
