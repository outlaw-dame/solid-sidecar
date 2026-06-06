package authz

import (
	"errors"
	"os"
	"testing"
	"time"
)

func TestExternalCLIEvaluatorRejectsInvalidConfig(t *testing.T) {
	for _, test := range []struct {
		name    string
		options ExternalCLIEvaluatorOptions
	}{
		{name: "missing command", options: ExternalCLIEvaluatorOptions{}},
		{name: "control character in command", options: ExternalCLIEvaluatorOptions{Command: "solid\npolicy"}},
		{name: "control character in arg", options: ExternalCLIEvaluatorOptions{Command: os.Args[0], Args: []string{"bad\narg"}}},
		{name: "negative timeout", options: ExternalCLIEvaluatorOptions{Command: os.Args[0], Timeout: -time.Second}},
		{name: "negative output limit", options: ExternalCLIEvaluatorOptions{Command: os.Args[0], MaxOutputBytes: -1}},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := NewExternalCLIEvaluator(test.options)
			if !errors.Is(err, ErrExternalEvaluatorConfig) {
				t.Fatalf("error = %v, want ErrExternalEvaluatorConfig", err)
			}
		})
	}
}

func TestExternalCLIEvaluatorAppliesSafeDefaults(t *testing.T) {
	evaluator, err := NewExternalCLIEvaluator(ExternalCLIEvaluatorOptions{Command: os.Args[0]})
	if err != nil {
		t.Fatalf("NewExternalCLIEvaluator returned error: %v", err)
	}
	if evaluator.timeout != DefaultExternalEvaluatorTimeout {
		t.Fatalf("timeout = %s, want %s", evaluator.timeout, DefaultExternalEvaluatorTimeout)
	}
	if evaluator.maxOutputBytes != DefaultExternalEvaluatorMaxOutputBytes {
		t.Fatalf("max output = %d, want %d", evaluator.maxOutputBytes, DefaultExternalEvaluatorMaxOutputBytes)
	}
}
