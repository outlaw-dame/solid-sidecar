package authz

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"strings"
	"time"
)

const (
	DefaultExternalEvaluatorTimeout        = 2 * time.Second
	DefaultExternalEvaluatorMaxOutputBytes = int64(64 << 10) // 64 KiB
)

var (
	ErrExternalEvaluatorConfig     = errors.New("external authz evaluator config invalid")
	ErrExternalEvaluatorExecution  = errors.New("external authz evaluator execution failed")
	ErrExternalEvaluatorOutput     = errors.New("external authz evaluator output invalid")
	ErrExternalEvaluatorOutputSize = errors.New("external authz evaluator output too large")
)

type ExternalCLIEvaluatorOptions struct {
	Command        string
	Args           []string
	Timeout        time.Duration
	MaxOutputBytes int64
}

type ExternalCLIEvaluator struct {
	command        string
	args           []string
	timeout        time.Duration
	maxOutputBytes int64
}

func NewExternalCLIEvaluator(options ExternalCLIEvaluatorOptions) (ExternalCLIEvaluator, error) {
	command := strings.TrimSpace(options.Command)
	if command == "" || containsControlCharacter(command) {
		return ExternalCLIEvaluator{}, fmt.Errorf("%w: command is required", ErrExternalEvaluatorConfig)
	}
	args := make([]string, 0, len(options.Args))
	for _, arg := range options.Args {
		if containsControlCharacter(arg) {
			return ExternalCLIEvaluator{}, fmt.Errorf("%w: command arguments must not contain control characters", ErrExternalEvaluatorConfig)
		}
		args = append(args, arg)
	}
	timeout := options.Timeout
	if timeout == 0 {
		timeout = DefaultExternalEvaluatorTimeout
	}
	if timeout <= 0 {
		return ExternalCLIEvaluator{}, fmt.Errorf("%w: timeout must be positive", ErrExternalEvaluatorConfig)
	}
	maxOutputBytes := options.MaxOutputBytes
	if maxOutputBytes == 0 {
		maxOutputBytes = DefaultExternalEvaluatorMaxOutputBytes
	}
	if maxOutputBytes <= 0 {
		return ExternalCLIEvaluator{}, fmt.Errorf("%w: max output bytes must be positive", ErrExternalEvaluatorConfig)
	}
	return ExternalCLIEvaluator{command: command, args: args, timeout: timeout, maxOutputBytes: maxOutputBytes}, nil
}

func (e ExternalCLIEvaluator) Evaluate(ctx context.Context, request Request) (Decision, error) {
	if err := ctx.Err(); err != nil {
		return Decision{}, err
	}
	encoded, err := EncodeRequest(request)
	if err != nil {
		return Decision{}, fmt.Errorf("%w: encode request", ErrExternalEvaluatorOutput)
	}

	evalCtx, cancel := context.WithTimeout(ctx, e.timeout)
	defer cancel()

	cmd := exec.CommandContext(evalCtx, e.command, e.args...)
	cmd.Stdin = bytes.NewReader(append(encoded, '\n'))
	stdout := newLimitedBuffer(e.maxOutputBytes)
	stderr := newLimitedBuffer(4 << 10)
	cmd.Stdout = stdout
	cmd.Stderr = stderr

	if err := cmd.Run(); err != nil {
		if errors.Is(stdout.Err(), ErrExternalEvaluatorOutputSize) || errors.Is(stderr.Err(), ErrExternalEvaluatorOutputSize) {
			return Decision{}, ErrExternalEvaluatorOutputSize
		}
		if evalCtx.Err() != nil {
			return Decision{}, fmt.Errorf("%w: timeout", ErrExternalEvaluatorExecution)
		}
		return Decision{}, ErrExternalEvaluatorExecution
	}
	if errors.Is(stdout.Err(), ErrExternalEvaluatorOutputSize) {
		return Decision{}, ErrExternalEvaluatorOutputSize
	}
	decisionBytes := bytes.TrimSpace(stdout.Bytes())
	if len(decisionBytes) == 0 {
		return Decision{}, fmt.Errorf("%w: empty decision", ErrExternalEvaluatorOutput)
	}
	decision, err := DecodeDecision(decisionBytes)
	if err != nil {
		return Decision{}, fmt.Errorf("%w: decode decision", ErrExternalEvaluatorOutput)
	}
	return decision, nil
}

type limitedBuffer struct {
	buf   bytes.Buffer
	limit int64
	err   error
}

func newLimitedBuffer(limit int64) *limitedBuffer {
	return &limitedBuffer{limit: limit}
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	if b.err != nil {
		return 0, b.err
	}
	if int64(b.buf.Len()+len(p)) > b.limit {
		remaining := int(b.limit) - b.buf.Len()
		if remaining > 0 {
			_, _ = b.buf.Write(p[:remaining])
		}
		b.err = ErrExternalEvaluatorOutputSize
		return len(p), b.err
	}
	return b.buf.Write(p)
}

func (b *limitedBuffer) Bytes() []byte {
	return b.buf.Bytes()
}

func (b *limitedBuffer) Err() error {
	if b.err == io.ErrShortBuffer {
		return ErrExternalEvaluatorOutputSize
	}
	return b.err
}

func containsControlCharacter(value string) bool {
	for _, r := range value {
		if r < 0x20 || r == 0x7f {
			return true
		}
	}
	return false
}
