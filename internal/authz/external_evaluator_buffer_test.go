package authz

import (
	"errors"
	"testing"
)

func TestLimitedBufferRejectsOversizedOutput(t *testing.T) {
	buffer := newLimitedBuffer(4)
	written, err := buffer.Write([]byte("abcdef"))
	if written != 6 {
		t.Fatalf("written = %d, want 6", written)
	}
	if !errors.Is(err, ErrExternalEvaluatorOutputSize) {
		t.Fatalf("error = %v, want ErrExternalEvaluatorOutputSize", err)
	}
	if !errors.Is(buffer.Err(), ErrExternalEvaluatorOutputSize) {
		t.Fatalf("buffer error = %v, want ErrExternalEvaluatorOutputSize", buffer.Err())
	}
	if string(buffer.Bytes()) != "abcd" {
		t.Fatalf("buffer = %q, want %q", string(buffer.Bytes()), "abcd")
	}
}

func TestLimitedBufferAcceptsOutputAtLimit(t *testing.T) {
	buffer := newLimitedBuffer(4)
	written, err := buffer.Write([]byte("abcd"))
	if err != nil {
		t.Fatalf("Write returned error: %v", err)
	}
	if written != 4 {
		t.Fatalf("written = %d, want 4", written)
	}
	if buffer.Err() != nil {
		t.Fatalf("buffer error = %v, want nil", buffer.Err())
	}
}
