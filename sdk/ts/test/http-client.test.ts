/**
 * Solid Sidecar TypeScript SDK - HTTP Client Tests
 * Phase: 27 - SDK/Client Compatibility Layer
 * Version: v1.0.0
 * Created: 2026-07-07
 * Author: Mistral Vibe
 * License: MIT
 */

import {
  SolidSidecarHttpClient,
  getDefaultHttpClient,
  resetDefaultHttpClient,
  DEFAULT_HTTP_CLIENT_CONFIG,
} from '../src/http-client';
import {
  NetworkError,
  ValidationError,
  RateLimitError,
  AuthenticationError,
  AuthorizationError,
  ResourceNotFoundError,
  ConflictError,
  PreconditionFailedError,
} from '../src/types';

// Mock fetch implementation
const mockFetch = jest.fn();

beforeEach(() => {
  // Reset all mocks
  jest.clearAllMocks();
  resetDefaultHttpClient();
  
  // Reset global fetch
  global.fetch = mockFetch;
});

afterEach(() => {
  resetDefaultHttpClient();
  jest.clearAllMocks();
});

describe('SolidSidecarHttpClient', () => {
  describe('Initialization', () => {
    it('should initialize with default configuration', () => {
      const client = new SolidSidecarHttpClient();
      expect(client.getConfig()).toBeDefined();
      expect(client.getConfig().baseUrl).toBe('');
      expect(client.getConfig().timeout).toBe(30000);
      expect(client.getConfig().maxRetries).toBe(3);
    });

    it('should initialize with custom configuration', () => {
      const customConfig = {
        baseUrl: 'https://example.com',
        timeout: 60000,
        maxRetries: 5,
      };
      
      const client = new SolidSidecarHttpClient(customConfig);
      const config = client.getConfig();
      
      expect(config.baseUrl).toBe('https://example.com');
      expect(config.timeout).toBe(60000);
      expect(config.maxRetries).toBe(5);
    });
  });

  describe('URL Validation (SSRF Prevention)', () => {
    it('should reject URLs with invalid protocols', async () => {
      const client = new SolidSidecarHttpClient({
        validateUrls: true,
      });

      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        headers: new Headers(),
        json: () => Promise.resolve({}),
        text: () => Promise.resolve(''),
        arrayBuffer: () => Promise.resolve(new ArrayBuffer(0)),
      });

      await expect(
        client.get('file:///etc/passwd')
      ).rejects.toThrow(ValidationError);
    });

    it('should reject URLs with credentials', async () => {
      const client = new SolidSidecarHttpClient({
        validateUrls: true,
      });

      await expect(
        client.get('https://user:password@example.com/data')
      ).rejects.toThrow(ValidationError);
    });

    it('should accept valid HTTPS URLs', async () => {
      const client = new SolidSidecarHttpClient({
        baseUrl: 'https://example.com',
        validateUrls: true,
      });

      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        headers: new Headers({
          'content-type': 'application/json',
        }),
        json: () => Promise.resolve({ test: 'data' }),
        text: () => Promise.resolve(''),
        arrayBuffer: () => Promise.resolve(new ArrayBuffer(0)),
      });

      const response = await client.get('/data');
      expect(response.status).toBe(200);
    });

    it('should accept valid HTTP URLs in development mode', async () => {
      const client = new SolidSidecarHttpClient({
        baseUrl: 'http://localhost:8080',
        validateUrls: true,
        validateSsl: false,
      });

      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        headers: new Headers(),
        json: () => Promise.resolve({}),
        text: () => Promise.resolve(''),
        arrayBuffer: () => Promise.resolve(new ArrayBuffer(0)),
      });

      // Should not throw for HTTP in development
      const response = await client.get('/data');
      expect(response.status).toBe(200);
    });
  });

  describe('Request Methods', () => {
    const baseUrl = 'https://example.com';
    
    beforeEach(() => {
      mockFetch.mockImplementation((url, init) => {
        const requestUrl = url instanceof Request ? url.url : String(url);
        const method = init?.method || 'GET';
        
        return Promise.resolve({
          ok: true,
          status: 200,
          headers: new Headers({
            'content-type': 'application/json',
          }),
          json: () => Promise.resolve({ method, url: requestUrl }),
          text: () => Promise.resolve(''),
          arrayBuffer: () => Promise.resolve(new ArrayBuffer(0)),
        });
      });
    });

    it('should make GET requests', async () => {
      const client = new SolidSidecarHttpClient({ baseUrl });
      
      const response = await client.get('/resource');
      
      expect(mockFetch).toHaveBeenCalledWith(
        'https://example.com/resource',
        expect.objectContaining({
          method: 'GET',
        })
      );
      expect(response.status).toBe(200);
    });

    it('should make HEAD requests', async () => {
      const client = new SolidSidecarHttpClient({ baseUrl });
      
      const response = await client.head('/resource');
      
      expect(mockFetch).toHaveBeenCalledWith(
        'https://example.com/resource',
        expect.objectContaining({
          method: 'HEAD',
        })
      );
    });

    it('should make POST requests with body', async () => {
      const client = new SolidSidecarHttpClient({ baseUrl });
      const body = JSON.stringify({ test: 'data' });
      
      const response = await client.post('/resource', body, {
        'content-type': 'application/json',
      });
      
      expect(mockFetch).toHaveBeenCalledWith(
        'https://example.com/resource',
        expect.objectContaining({
          method: 'POST',
          body,
          headers: expect.objectContaining({
            'content-type': 'application/json',
          }),
        })
      );
    });

    it('should make PUT requests with body', async () => {
      const client = new SolidSidecarHttpClient({ baseUrl });
      const body = 'test data';
      
      const response = await client.put('/resource', body);
      
      expect(mockFetch).toHaveBeenCalledWith(
        'https://example.com/resource',
        expect.objectContaining({
          method: 'PUT',
          body,
        })
      );
    });

    it('should make PATCH requests', async () => {
      const client = new SolidSidecarHttpClient({ baseUrl });
      const body = 'patch data';
      
      const response = await client.patch('/resource', body);
      
      expect(mockFetch).toHaveBeenCalledWith(
        'https://example.com/resource',
        expect.objectContaining({
          method: 'PATCH',
          body,
        })
      );
    });

    it('should make DELETE requests', async () => {
      const client = new SolidSidecarHttpClient({ baseUrl });
      
      const response = await client.delete('/resource');
      
      expect(mockFetch).toHaveBeenCalledWith(
        'https://example.com/resource',
        expect.objectContaining({
          method: 'DELETE',
        })
      );
    });
  });

  describe('Error Handling', () => {
    it('should throw AuthenticationError for 401 responses', async () => {
      const client = new SolidSidecarHttpClient();
      
      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 401,
        headers: new Headers(),
        json: () => Promise.resolve({ code: 'UNAUTHORIZED', message: 'Authentication required' }),
        text: () => Promise.resolve('Authentication required'),
        arrayBuffer: () => Promise.resolve(new ArrayBuffer(0)),
      });

      await expect(client.get('/protected')).rejects.toThrow(AuthenticationError);
    });

    it('should throw AuthorizationError for 403 responses', async () => {
      const client = new SolidSidecarHttpClient();
      
      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 403,
        headers: new Headers(),
        json: () => Promise.resolve({ code: 'FORBIDDEN', message: 'Access denied' }),
        text: () => Promise.resolve('Access denied'),
        arrayBuffer: () => Promise.resolve(new ArrayBuffer(0)),
      });

      await expect(client.get('/forbidden')).rejects.toThrow(AuthorizationError);
    });

    it('should throw ResourceNotFoundError for 404 responses', async () => {
      const client = new SolidSidecarHttpClient();
      
      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 404,
        headers: new Headers(),
        json: () => Promise.resolve({ code: 'NOT_FOUND', message: 'Resource not found' }),
        text: () => Promise.resolve('Resource not found'),
        arrayBuffer: () => Promise.resolve(new ArrayBuffer(0)),
      });

      await expect(client.get('/missing')).rejects.toThrow(ResourceNotFoundError);
    });

    it('should throw ConflictError for 409 responses', async () => {
      const client = new SolidSidecarHttpClient();
      
      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 409,
        headers: new Headers({
          'etag': '"abc123"',
        }),
        json: () => Promise.resolve({ code: 'CONFLICT', message: 'Conflict' }),
        text: () => Promise.resolve('Conflict'),
        arrayBuffer: () => Promise.resolve(new ArrayBuffer(0)),
      });

      await expect(client.get('/conflict')).rejects.toThrow(ConflictError);
    });

    it('should throw PreconditionFailedError for 412 responses', async () => {
      const client = new SolidSidecarHttpClient();
      
      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 412,
        headers: new Headers({
          'etag': '"xyz789"',
        }),
        json: () => Promise.resolve({ code: 'PRECONDITION_FAILED', message: 'Precondition failed' }),
        text: () => Promise.resolve('Precondition failed'),
        arrayBuffer: () => Promise.resolve(new ArrayBuffer(0)),
      });

      await expect(client.get('/precondition')).rejects.toThrow(PreconditionFailedError);
    });

    it('should throw RateLimitError for 429 responses', async () => {
      const client = new SolidSidecarHttpClient();
      
      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 429,
        headers: new Headers({
          'retry-after': '60',
        }),
        json: () => Promise.resolve({ code: 'RATE_LIMIT', message: 'Rate limited' }),
        text: () => Promise.resolve('Rate limited'),
        arrayBuffer: () => Promise.resolve(new ArrayBuffer(0)),
      });

      await expect(client.get('/rate-limited')).rejects.toThrow(RateLimitError);
      
      // Verify retry-after is parsed
      try {
        await client.get('/rate-limited');
      } catch (error) {
        expect((error as RateLimitError).retryAfter).toBe(60);
      }
    });

    it('should throw NetworkError for 500 responses', async () => {
      const client = new SolidSidecarHttpClient();
      
      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 500,
        headers: new Headers(),
        json: () => Promise.resolve({ code: 'INTERNAL_ERROR', message: 'Internal server error' }),
        text: () => Promise.resolve('Internal server error'),
        arrayBuffer: () => Promise.resolve(new ArrayBuffer(0)),
      });

      await expect(client.get('/server-error')).rejects.toThrow(NetworkError);
    });

    it('should throw ValidationError for 400 responses', async () => {
      const client = new SolidSidecarHttpClient();
      
      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 400,
        headers: new Headers(),
        json: () => Promise.resolve({ code: 'BAD_REQUEST', message: 'Bad request' }),
        text: () => Promise.resolve('Bad request'),
        arrayBuffer: () => Promise.resolve(new ArrayBuffer(0)),
      });

      await expect(client.get('/bad-request')).rejects.toThrow(ValidationError);
    });
  });

  describe('Retry Logic', () => {
    it('should retry on network errors', async () => {
      const client = new SolidSidecarHttpClient({
        maxRetries: 3,
        retryDelay: 10,
      });

      // Fail twice, succeed on third try
      mockFetch
        .mockRejectedValueOnce(new TypeError('Network error'))
        .mockRejectedValueOnce(new TypeError('Network error'))
        .mockResolvedValueOnce({
          ok: true,
          status: 200,
          headers: new Headers(),
          json: () => Promise.resolve({}),
          text: () => Promise.resolve(''),
          arrayBuffer: () => Promise.resolve(new ArrayBuffer(0)),
        });

      const response = await client.get('/retry');
      
      expect(mockFetch).toHaveBeenCalledTimes(3);
      expect(response.status).toBe(200);
    });

    it('should respect max retries', async () => {
      const client = new SolidSidecarHttpClient({
        maxRetries: 2,
        retryDelay: 10,
      });

      // Always fail
      mockFetch.mockRejectedValue(new TypeError('Network error'));

      await expect(client.get('/max-retries')).rejects.toThrow(TypeError);
      expect(mockFetch).toHaveBeenCalledTimes(3); // Initial + 2 retries
    });

    it('should retry on 503 responses', async () => {
      const client = new SolidSidecarHttpClient({
        maxRetries: 2,
        retryDelay: 10,
      });

      // Fail with 503 twice, then succeed
      mockFetch
        .mockResolvedValueOnce({
          ok: false,
          status: 503,
          headers: new Headers(),
          json: () => Promise.resolve({}),
          text: () => Promise.resolve(''),
          arrayBuffer: () => Promise.resolve(new ArrayBuffer(0)),
        })
        .mockResolvedValueOnce({
          ok: false,
          status: 503,
          headers: new Headers(),
          json: () => Promise.resolve({}),
          text: () => Promise.resolve(''),
          arrayBuffer: () => Promise.resolve(new ArrayBuffer(0)),
        })
        .mockResolvedValueOnce({
          ok: true,
          status: 200,
          headers: new Headers(),
          json: () => Promise.resolve({}),
          text: () => Promise.resolve(''),
          arrayBuffer: () => Promise.resolve(new ArrayBuffer(0)),
        });

      const response = await client.get('/service-unavailable');
      
      expect(mockFetch).toHaveBeenCalledTimes(3);
      expect(response.status).toBe(200);
    });

    it('should not retry on 404 responses', async () => {
      const client = new SolidSidecarHttpClient({
        maxRetries: 3,
      });

      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 404,
        headers: new Headers(),
        json: () => Promise.resolve({}),
        text: () => Promise.resolve(''),
        arrayBuffer: () => Promise.resolve(new ArrayBuffer(0)),
      });

      try {
        await client.get('/not-found');
      } catch {
        // Expected
      }
      
      expect(mockFetch).toHaveBeenCalledTimes(1); // No retries for 404
    });
  });

  describe('Timeout', () => {
    it('should respect timeout setting', async () => {
      jest.useFakeTimers();
      
      const client = new SolidSidecarHttpClient({
        timeout: 100,
      });

      // Simulate a slow response
      let resolveFetch: (value: any) => void;
      const fetchPromise = new Promise(resolve => {
        resolveFetch = resolve;
      });
      
      mockFetch.mockReturnValue(fetchPromise);

      const requestPromise = client.get('/slow');
      
      // Advance timers past timeout
      jest.advanceTimersByTime(101);

      // Should reject due to timeout
      await expect(requestPromise).rejects.toThrow();
      
      jest.useRealTimers();
    });
  });

  describe('Header Redaction', () => {
    it('should redact sensitive headers in logs', () => {
      const client = new SolidSidecarHttpClient();
      
      // Access the private method through reflection for testing
      const redactSensitiveHeaders = (client as any).redactSensitiveHeaders;
      
      const headers = {
        'content-type': 'application/json',
        'authorization': 'Bearer secret-token',
        'dpop': 'DPoP jwk-token',
        'cookie': 'session=abc123',
        'x-api-key': 'my-api-key',
      };

      const redacted = redactSensitiveHeaders(headers);
      
      expect(redacted['content-type']).toBe('application/json');
      expect(redacted['authorization']).toBe('[REDACTED]');
      expect(redacted['dpop']).toBe('[REDACTED]');
      expect(redacted['cookie']).toBe('[REDACTED]');
      expect(redacted['x-api-key']).toBe('[REDACTED]');
    });

    it('should handle case-insensitive header names', () => {
      const client = new SolidSidecarHttpClient();
      const redactSensitiveHeaders = (client as any).redactSensitiveHeaders;
      
      const headers = {
        'Authorization': 'Bearer token',
        'AUTHORIZATION': 'Bearer token2',
        'DPoP': 'proof',
      };

      const redacted = redactSensitiveHeaders(headers);
      
      expect(redacted['Authorization']).toBe('[REDACTED]');
      expect(redacted['AUTHORIZATION']).toBe('[REDACTED]');
      expect(redacted['DPoP']).toBe('[REDACTED]');
    });
  });

  describe('IDOR Prevention', () => {
    it('should validate resource URIs are within allowed scope', () => {
      const client = new SolidSidecarHttpClient({
        baseUrl: 'https://pod.example.com',
      });

      const validateResourceUri = (client as any).validateResourceUri;
      
      // Valid URI within scope
      expect(validateResourceUri('/data/resource', ['/data/'])).toBe(true);
      
      // URI outside scope
      expect(validateResourceUri('/admin/config', ['/data/'])).toBe(false);
      
      // Path traversal
      expect(() => validateResourceUri('../etc/passwd', ['/data/'])).toThrow(ValidationError);
    });

    it('should check if resource is within Pod', () => {
      const client = new SolidSidecarHttpClient({
        baseUrl: 'https://pod.example.com',
      });

      const isWithinPod = (client as any).isWithinPod;
      
      expect(isWithinPod('/data/resource', '/')).toBe(true);
      expect(isWithinPod('/data/resource', '/data/')).toBe(true);
      expect(isWithinPod('/admin/config', '/data/')).toBe(false);
    });
  });

  describe('Default HTTP Client', () => {
    it('should create default client on first use', () => {
      const client = getDefaultHttpClient();
      expect(client).toBeInstanceOf(SolidSidecarHttpClient);
    });

    it('should return same instance on subsequent calls', () => {
      const client1 = getDefaultHttpClient();
      const client2 = getDefaultHttpClient();
      expect(client1).toBe(client2);
    });

    it('should create new instance when config is provided', () => {
      const client1 = getDefaultHttpClient();
      const client2 = getDefaultHttpClient({ baseUrl: 'https://custom.com' });
      
      expect(client1).not.toBe(client2);
      expect(client2.getConfig().baseUrl).toBe('https://custom.com');
    });

    it('should reset default client', () => {
      const client1 = getDefaultHttpClient();
      resetDefaultHttpClient();
      const client2 = getDefaultHttpClient();
      
      expect(client1).not.toBe(client2);
    });

    it('should configure default client', () => {
      const client = configureDefaultHttpClient({ baseUrl: 'https://configured.com' });
      expect(client.getConfig().baseUrl).toBe('https://configured.com');
      
      const defaultClient = getDefaultHttpClient();
      expect(defaultClient.getConfig().baseUrl).toBe('https://configured.com');
    });
  });
});
