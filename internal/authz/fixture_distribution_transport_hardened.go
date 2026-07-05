package authz

import (
	"context"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	s3sdk "github.com/aws/aws-sdk-go-v2/service/s3"
)

// NewHardenedHTTPTransport creates an HTTP fixture transport using the shared
// outbound network policy for its HTTP client. This keeps the legacy constructor
// stable while giving production callers an explicit hardened path.
func NewHardenedHTTPTransport(options FixtureTransportOptions) (*HTTPTransport, error) {
	transport, err := NewHTTPTransport(options)
	if err != nil {
		return nil, err
	}
	policy := outboundPolicyFromTransportConfig(transport.config)
	transport.client = policy.NewHTTPClient(transport.config.Timeout)
	return transport, nil
}

// SetHardenedBaseURL validates and sets an HTTP base URL through the shared
// outbound network policy. It requires HTTPS by default and rejects userinfo,
// localhost, single-label names, private IPs, loopback, link-local, multicast,
// and unspecified targets unless AllowLocalhost is explicitly set for tests.
func (t *HTTPTransport) SetHardenedBaseURL(rawURL string) error {
	policy := outboundPolicyFromTransportConfig(t.config)
	parsedURL, err := policy.ValidateURL(rawURL)
	if err != nil {
		return err
	}
	t.baseURL = parsedURL
	return nil
}

// NewHardenedS3TransportWithOptions creates an S3 fixture transport that fails
// closed on unsafe custom endpoints and configures AWS SDK HTTP traffic through
// the shared outbound network policy client.
func NewHardenedS3TransportWithOptions(options S3TransportOptions) (*S3Transport, error) {
	transport, err := NewS3TransportWithOptions(options)
	if err != nil {
		return nil, err
	}
	policy := outboundPolicyFromTransportConfig(transport.config)
	if options.Endpoint != "" {
		if _, err := policy.ValidateURL(options.Endpoint); err != nil {
			return nil, fmt.Errorf("%w: unsafe S3 endpoint", err)
		}
	}
	if err := transport.initializeHardenedS3Client(context.TODO(), policy); err != nil {
		return nil, err
	}
	return transport, nil
}

// SetHardenedS3Endpoint validates and stores a custom S3 endpoint through the
// shared outbound network policy. It also rebuilds the SDK client when
// credentials are already configured.
func (t *S3Transport) SetHardenedS3Endpoint(endpoint string) error {
	policy := outboundPolicyFromTransportConfig(t.config)
	if endpoint != "" {
		if _, err := policy.ValidateURL(endpoint); err != nil {
			return fmt.Errorf("%w: unsafe S3 endpoint", err)
		}
	}
	t.endpoint = endpoint
	return t.initializeHardenedS3Client(context.TODO(), policy)
}

func (t *S3Transport) initializeHardenedS3Client(ctx context.Context, policy OutboundTransportNetworkPolicy) error {
	if t.accessKeyID == "" && t.secretAccessKey == "" && !t.useDefaultCreds {
		return nil
	}
	if t.endpoint != "" {
		if _, err := policy.ValidateURL(t.endpoint); err != nil {
			return fmt.Errorf("%w: unsafe S3 endpoint", err)
		}
	}

	var awsConfig aws.Config
	var err error
	if t.useDefaultCreds && t.accessKeyID == "" && t.secretAccessKey == "" {
		awsConfig, err = awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(t.region))
	} else {
		provider := credentials.NewStaticCredentialsProvider(t.accessKeyID, t.secretAccessKey, t.sessionToken)
		awsConfig, err = awsconfig.LoadDefaultConfig(ctx, awsconfig.WithCredentialsProvider(provider), awsconfig.WithRegion(t.region))
	}
	if err != nil {
		return fmt.Errorf("%w: failed to create AWS config", ErrTransportConnectionFailed)
	}
	awsConfig.HTTPClient = policy.NewHTTPClient(timeoutOrDefault(t.config.Timeout))
	t.s3Client = s3sdk.NewFromConfig(awsConfig, func(o *s3sdk.Options) {
		o.UsePathStyle = true
		o.UseAccelerate = false
		if t.endpoint != "" {
			o.EndpointResolver = s3sdk.EndpointResolverFromURL(t.endpoint)
		}
	})
	return nil
}

func outboundPolicyFromTransportConfig(config TransportConfig) OutboundTransportNetworkPolicy {
	policy := DefaultOutboundTransportNetworkPolicy()
	policy.AllowLocalhost = config.AllowLocalhost
	policy.RequireHTTPS = true
	return policy
}

func timeoutOrDefault(timeout time.Duration) time.Duration {
	if timeout > 0 {
		return timeout
	}
	return DefaultTransportTimeout
}
