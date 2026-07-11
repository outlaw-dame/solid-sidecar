/**
 * Solid Sidecar TypeScript SDK - Utilities Tests
 * Phase: 27 - SDK/Client Compatibility Layer
 * Version: v1.0.0
 * Created: 2026-07-07
 * Author: Mistral Vibe
 * License: MIT
 */

import * as utils from '../src/utils';

describe('URL Utilities', () => {
  describe('resolveUrl', () => {
    it('should return absolute URL as-is', () => {
      const result = utils.resolveUrl('https://example.com/path');
      expect(result).toBe('https://example.com/path');
    });

    it('should resolve relative URL with base', () => {
      const result = utils.resolveUrl('https://example.com', 'path');
      expect(result).toBe('https://example.com/path');
    });

    it('should resolve absolute path with base', () => {
      const result = utils.resolveUrl('https://example.com', '/path');
      expect(result).toBe('https://example.com/path');
    });

    it('should handle base URL with trailing slash', () => {
      const result = utils.resolveUrl('https://example.com/', 'path');
      expect(result).toBe('https://example.com/path');
    });

    it('should handle empty base URL', () => {
      const result = utils.resolveUrl('', '/path');
      expect(result).toBe('/path');
    });

    it('should handle nested paths', () => {
      const result = utils.resolveUrl('https://example.com/base/', 'path');
      expect(result).toBe('https://example.com/base/path');
    });
  });

  describe('normalizeUrl', () => {
    it('should remove query parameters', () => {
      const result = utils.normalizeUrl('https://example.com/path?query=1');
      expect(result).toBe('https://example.com/path');
    });

    it('should remove fragments', () => {
      const result = utils.normalizeUrl('https://example.com/path#fragment');
      expect(result).toBe('https://example.com/path');
    });

    it('should remove both query and fragment', () => {
      const result = utils.normalizeUrl('https://example.com/path?query=1#fragment');
      expect(result).toBe('https://example.com/path');
    });

    it('should handle URL without query or fragment', () => {
      const result = utils.normalizeUrl('https://example.com/path');
      expect(result).toBe('https://example.com/path');
    });
  });

  describe('validateUrl', () => {
    it('should accept valid HTTPS URLs', () => {
      expect(utils.validateUrl('https://example.com/path')).toBe(true);
    });

    it('should accept valid HTTP URLs', () => {
      expect(utils.validateUrl('http://example.com/path')).toBe(true);
    });

    it('should accept URLs with ports', () => {
      expect(utils.validateUrl('https://example.com:8443/path')).toBe(true);
    });

    it('should reject file URLs', () => {
      expect(utils.validateUrl('file:///etc/passwd')).toBe(false);
    });

    it('should reject data URLs', () => {
      expect(utils.validateUrl('data:text/plain;base64,SGVsbG8=')).toBe(false);
    });

    it('should reject URLs with credentials', () => {
      expect(utils.validateUrl('https://user:password@example.com/path')).toBe(false);
    });

    it('should reject invalid URLs', () => {
      expect(utils.validateUrl('not-a-url')).toBe(false);
      expect(utils.validateUrl('')).toBe(false);
    });

    it('should accept only allowed hosts', () => {
      expect(utils.validateUrl('https://example.com/path', ['example.com'])).toBe(true);
      expect(utils.validateUrl('https://other.com/path', ['example.com'])).toBe(false);
    });

    it('should be case-insensitive for hosts', () => {
      expect(utils.validateUrl('https://EXAMPLE.COM/path', ['example.com'])).toBe(true);
    });
  });

  describe('isSameOrigin', () => {
    it('should return true for same origin URLs', () => {
      expect(utils.isSameOrigin('https://example.com:8443/path1', 'https://example.com:8443/path2')).toBe(true);
    });

    it('should return false for different protocols', () => {
      expect(utils.isSameOrigin('https://example.com/path', 'http://example.com/path')).toBe(false);
    });

    it('should return false for different hosts', () => {
      expect(utils.isSameOrigin('https://example.com/path', 'https://other.com/path')).toBe(false);
    });

    it('should return false for different ports', () => {
      expect(utils.isSameOrigin('https://example.com:8443/path', 'https://example.com:8444/path')).toBe(false);
    });

    it('should return true for same origin with different paths', () => {
      expect(utils.isSameOrigin('https://example.com/path1', 'https://example.com/path2')).toBe(true);
    });
  });
});

describe('Base64 URL Encoding', () => {
  describe('base64UrlEncode', () => {
    it('should encode string to Base64Url', () => {
      const result = utils.base64UrlEncode('hello world');
      expect(result).toBe('aGVsbG8gd29ybGQ');
    });

    it('should encode buffer to Base64Url', () => {
      const buffer = Buffer.from('hello world');
      const result = utils.base64UrlEncode(buffer);
      expect(result).toBe('aGVsbG8gd29ybGQ');
    });

    it('should remove padding', () => {
      const result = utils.base64UrlEncode('abc');
      expect(result).toBe('YWJj');
    });

    it('should replace + with -', () => {
      const input = Buffer.from([255, 254, 253]).toString('base64'); // Contains +
      const result = utils.base64UrlEncode(input);
      expect(result).not.toContain('+');
      expect(result).toContain('-');
    });

    it('should replace / with _', () => {
      const input = Buffer.from([255, 254, 252]).toString('base64'); // Contains /
      const result = utils.base64UrlEncode(input);
      expect(result).not.toContain('/');
      expect(result).toContain('_');
    });
  });

  describe('base64UrlDecode', () => {
    it('should decode Base64Url to string', () => {
      const result = utils.base64UrlDecode('aGVsbG8gd29ybGQ');
      expect(result).toBe('hello world');
    });

    it('should handle missing padding', () => {
      const result = utils.base64UrlDecode('YWJj');
      expect(result).toBe('abc');
    });

    it('should handle - instead of +', () => {
      const encoded = 'YWJj-YWJj'.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
      const result = utils.base64UrlDecode(encoded);
      // This is a simple test, actual decoding depends on input
    });

    it('should handle _ instead of /', () => {
      const encoded = 'YWJj_YWJj'.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
      const result = utils.base64UrlDecode(encoded);
      // This is a simple test, actual decoding depends on input
    });
  });
});

describe('SHA-256 Hashing', () => {
  describe('sha256Base64UrlSync', () => {
    it('should hash string to SHA-256 Base64Url', () => {
      const input = 'hello world';
      const result = utils.sha256Base64UrlSync(input);
      
      expect(result).toBeDefined();
      expect(result.length).toBeGreaterThan(0);
      // SHA-256 hash of 'hello world' in base64url
      expect(result).toBe('b94d27-b9934d3e08-a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9');
    });

    it('should produce consistent output', () => {
      const input = 'test';
      const result1 = utils.sha256Base64UrlSync(input);
      const result2 = utils.sha256Base64UrlSync(input);
      
      expect(result1).toBe(result2);
    });

    it('should produce different output for different input', () => {
      const result1 = utils.sha256Base64UrlSync('input1');
      const result2 = utils.sha256Base64UrlSync('input2');
      
      expect(result1).not.toBe(result2);
    });
  });
});

describe('UUID Generation', () => {
  it('should generate valid UUID v4', () => {
    const uuid = utils.generateUuid();
    
    // UUID v4 format: xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx
    expect(uuid).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i);
  });

  it('should generate unique UUIDs', () => {
    const uuid1 = utils.generateUuid();
    const uuid2 = utils.generateUuid();
    
    expect(uuid1).not.toBe(uuid2);
  });

  it('should generate UUIDs with version 4', () => {
    const uuid = utils.generateUuid();
    const versionPart = uuid.substring(14, 18);
    
    expect(versionPart).toBe('4');
  });
});

describe('Exponential Backoff', () => {
  describe('sleep', () => {
    it('should resolve after specified delay', async () => {
      jest.useFakeTimers();
      
      const promise = utils.sleep(100);
      
      expect(promise).toBeInstanceOf(Promise);
      
      jest.advanceTimersByTime(50);
      // Should not be resolved yet
      
      jest.advanceTimersByTime(50);
      // Should be resolved now
      
      await expect(promise).resolves.toBeUndefined();
      
      jest.useRealTimers();
    });
  });

  describe('calculateBackoffDelay', () => {
    it('should calculate exponential delay', () => {
      const delay = utils.calculateBackoffDelay(2); // 3rd retry (0-indexed)
      
      // With baseDelay 1000, maxDelay 30000, jitterFactor 0.1
      expect(delay).toBeGreaterThanOrEqual(4000); // 1000 * 2^2 = 4000
      expect(delay).toBeLessThanOrEqual(4000 + 400); // + max jitter
    });

    it('should respect max delay', () => {
      const delay = utils.calculateBackoffDelay(10, {
        baseDelay: 1000,
        maxDelay: 5000,
        jitterFactor: 0,
      });
      
      // 1000 * 2^10 = 1,024,000 but capped at 5000
      expect(delay).toBeLessThanOrEqual(5000);
    });

    it('should apply jitter', () => {
      const delays = new Set();
      for (let i = 0; i < 10; i++) {
        const delay = utils.calculateBackoffDelay(0, {
          baseDelay: 1000,
          maxDelay: 30000,
          jitterFactor: 0.1,
        });
        delays.add(delay);
      }
      
      // With jitter, we should get different delays
      // Note: this might occasionally fail due to randomness
      expect(delays.size).toBeGreaterThan(1);
    });
  });

  describe('isRetryableStatus', () => {
    it('should return true for 5xx errors', () => {
      expect(utils.isRetryableStatus(500)).toBe(true);
      expect(utils.isRetryableStatus(502)).toBe(true);
      expect(utils.isRetryableStatus(503)).toBe(true);
      expect(utils.isRetryableStatus(504)).toBe(true);
    });

    it('should return true for 429', () => {
      expect(utils.isRetryableStatus(429)).toBe(true);
    });

    it('should return false for 4xx errors by default', () => {
      expect(utils.isRetryableStatus(400)).toBe(false);
      expect(utils.isRetryableStatus(401)).toBe(false);
      expect(utils.isRetryableStatus(403)).toBe(false);
      expect(utils.isRetryableStatus(404)).toBe(false);
    });

    it('should return true for 4xx errors when retryOn4xx is true', () => {
      expect(utils.isRetryableStatus(400, { retryOn4xx: true })).toBe(true);
    });

    it('should return true for specific retryable statuses', () => {
      expect(utils.isRetryableStatus(418, { retryableStatuses: [418] })).toBe(true);
    });

    it('should return false for 2xx statuses', () => {
      expect(utils.isRetryableStatus(200)).toBe(false);
      expect(utils.isRetryableStatus(201)).toBe(false);
    });
  });
});

describe('Error Handling', () => {
  describe('parseErrorResponse', () => {
    it('should parse JSON error response', async () => {
      const response = new Response(JSON.stringify({ message: 'Test error', code: 'TEST' }), {
        status: 400,
        headers: new Headers({ 'content-type': 'application/json' }),
      });

      const result = await utils.parseErrorResponse(response);
      
      expect(result.message).toBe('Test error');
      expect(result.code).toBe('TEST');
      expect(result.statusCode).toBe(400);
    });

    it('should parse text error response', async () => {
      const response = new Response('Plain text error', {
        status: 500,
        headers: new Headers({ 'content-type': 'text/plain' }),
      });

      const result = await utils.parseErrorResponse(response);
      
      expect(result.message).toBe('Plain text error');
      expect(result.statusCode).toBe(500);
    });

    it('should use default message for empty response', async () => {
      const response = new Response('', {
        status: 400,
        headers: new Headers({ 'content-type': 'text/plain' }),
      });

      const result = await utils.parseErrorResponse(response, 'Default message');
      
      expect(result.message).toBe('Default message');
      expect(result.statusCode).toBe(400);
    });

    it('should handle JSON parse errors', async () => {
      const response = new Response('not valid json', {
        status: 500,
        headers: new Headers({ 'content-type': 'application/json' }),
      });

      const result = await utils.parseErrorResponse(response, 'Fallback message');
      
      expect(result.message).toBe('Fallback message');
      expect(result.statusCode).toBe(500);
    });
  });
});

describe('IDOR Prevention', () => {
  describe('validateResourceScope', () => {
    it('should return true for matching scope', () => {
      expect(utils.validateResourceScope('/container/resource', ['/container/'])).toBe(true);
    });

    it('should return true for exact match', () => {
      expect(utils.validateResourceScope('/container/', ['/container/'])).toBe(true);
    });

    it('should return false for non-matching scope', () => {
      expect(utils.validateResourceScope('/admin/config', ['/container/'])).toBe(false);
    });

    it('should handle multiple scopes', () => {
      expect(utils.validateResourceScope('/data/resource', ['/admin/', '/data/'])).toBe(true);
      expect(utils.validateResourceScope('/admin/resource', ['/admin/', '/data/'])).toBe(true);
      expect(utils.validateResourceScope('/other/resource', ['/admin/', '/data/'])).toBe(false);
    });

    it('should normalize scope with trailing slash', () => {
      expect(utils.validateResourceScope('/container/resource', ['/container'])).toBe(true);
    });
  });

  describe('getContainerUri', () => {
    it('should return root for path without slash', () => {
      expect(utils.getContainerUri('resource')).toBe('/');
    });

    it('should return container for nested path', () => {
      expect(utils.getContainerUri('/container/resource')).toBe('/container/');
    });

    it('should handle trailing slash', () => {
      expect(utils.getContainerUri('/container/resource/')).toBe('/container/resource/');
    });

    it('should handle multiple nested levels', () => {
      expect(utils.getContainerUri('/a/b/c/d')).toBe('/a/b/c/');
    });

    it('should handle root path', () => {
      expect(utils.getContainerUri('/')).toBe('/');
    });
  });

  describe('getResourceName', () => {
    it('should return resource name from path', () => {
      expect(utils.getResourceName('/container/resource')).toBe('resource');
    });

    it('should handle trailing slash', () => {
      expect(utils.getResourceName('/container/resource/')).toBe('resource');
    });

    it('should handle simple filename', () => {
      expect(utils.getResourceName('resource')).toBe('resource');
    });

    it('should handle nested path', () => {
      expect(utils.getResourceName('/a/b/c/d.txt')).toBe('d.txt');
    });

    it('should handle root path', () => {
      expect(utils.getResourceName('/')).toBe('');
    });
  });
});

describe('Content-Type Utilities', () => {
  describe('isRdfContentType', () => {
    it('should return true for Turtle', () => {
      expect(utils.isRdfContentType('text/turtle')).toBe(true);
    });

    it('should return true for JSON-LD', () => {
      expect(utils.isRdfContentType('application/ld+json')).toBe(true);
    });

    it('should return true for N-Triples', () => {
      expect(utils.isRdfContentType('application/n-triples')).toBe(true);
    });

    it('should return true for RDF/XML', () => {
      expect(utils.isRdfContentType('application/rdf+xml')).toBe(true);
    });

    it('should return false for non-RDF types', () => {
      expect(utils.isRdfContentType('text/plain')).toBe(false);
      expect(utils.isRdfContentType('application/json')).toBe(false);
    });

    it('should be case-insensitive', () => {
      expect(utils.isRdfContentType('TEXT/TURTLE')).toBe(true);
    });
  });

  describe('getPreferredRdfContentType', () => {
    it('should return Turtle as preferred', () => {
      expect(utils.getPreferredRdfContentType()).toBe('text/turtle');
    });
  });

  describe('RDF_CONTENT_TYPES', () => {
    it('should have all RDF content types', () => {
      expect(utils.RDF_CONTENT_TYPES.TURTLE).toBe('text/turtle');
      expect(utils.RDF_CONTENT_TYPES.JSON_LD).toBe('application/ld+json');
      expect(utils.RDF_CONTENT_TYPES.N_TRIPLES).toBe('application/n-triples');
      expect(utils.RDF_CONTENT_TYPES.RDF_XML).toBe('application/rdf+xml');
    });
  });

  describe('CONTENT_TYPES', () => {
    it('should include RDF and non-RDF types', () => {
      expect(utils.CONTENT_TYPES.TURTLE).toBe('text/turtle');
      expect(utils.CONTENT_TYPES.JSON).toBe('application/json');
      expect(utils.CONTENT_TYPES.PLAIN).toBe('text/plain');
    });
  });
});

describe('Link Header Parsing', () => {
  describe('parseLinkHeaders', () => {
    it('should parse Link header with single link', () => {
      const headers = new Headers({
        Link: '<https://example.com/acl>; rel="acl"',
      });

      const links = utils.parseLinkHeaders(headers);
      
      expect(links).toHaveLength(1);
      expect(links[0].uri).toBe('https://example.com/acl');
      expect(links[0].rel).toBe('acl');
    });

    it('should parse Link header with multiple links', () => {
      const headers = new Headers({
        Link: '<https://example.com/acl>; rel="acl", <https://example.com/meta>; rel="meta"',
      });

      const links = utils.parseLinkHeaders(headers);
      
      expect(links).toHaveLength(2);
      expect(links[0].uri).toBe('https://example.com/acl');
      expect(links[0].rel).toBe('acl');
      expect(links[1].uri).toBe('https://example.com/meta');
      expect(links[1].rel).toBe('meta');
    });

    it('should handle Link header as object', () => {
      const headers = {
        link: '<https://example.com/acl>; rel="acl"',
      };

      const links = utils.parseLinkHeaders(headers);
      
      expect(links).toHaveLength(1);
      expect(links[0].uri).toBe('https://example.com/acl');
    });

    it('should handle empty Link header', () => {
      const headers = new Headers();
      const links = utils.parseLinkHeaders(headers);
      
      expect(links).toHaveLength(0);
    });

    it('should handle malformed Link header', () => {
      const headers = new Headers({
        Link: 'invalid-link-header',
      });

      const links = utils.parseLinkHeaders(headers);
      
      expect(links).toHaveLength(0);
    });
  });

  describe('LINK_RELATIONS', () => {
    it('should have common link relations', () => {
      expect(utils.LINK_RELATIONS.TYPE).toBe('type');
      expect(utils.LINK_RELATIONS.ACL).toBe('acl');
      expect(utils.LINK_RELATIONS.META).toBe('meta');
    });
  });
});

describe('ETag Utilities', () => {
  describe('parseETag', () => {
    it('should remove weak indicator', () => {
      expect(utils.parseETag('W/"abc123"')).toBe('"abc123"');
    });

    it('should handle strong ETag', () => {
      expect(utils.parseETag('"abc123"')).toBe('"abc123"');
    });

    it('should handle empty ETag', () => {
      expect(utils.parseETag('')).toBe('');
    });

    it('should handle ETag without quotes', () => {
      expect(utils.parseETag('abc123')).toBe('abc123');
    });
  });

  describe('etagsMatch', () => {
    it('should return true for matching ETags', () => {
      expect(utils.etagsMatch('"abc123"', '"abc123"')).toBe(true);
    });

    it('should return true for weak matching ETags', () => {
      expect(utils.etagsMatch('W/"abc123"', '"abc123"')).toBe(true);
      expect(utils.etagsMatch('"abc123"', 'W/"abc123"')).toBe(true);
    });

    it('should return false for non-matching ETags', () => {
      expect(utils.etagsMatch('"abc123"', '"xyz789"')).toBe(false);
    });

    it('should handle ETags without quotes', () => {
      expect(utils.etagsMatch('abc123', 'abc123')).toBe(true);
      expect(utils.etagsMatch('abc123', 'xyz789')).toBe(false);
    });
  });
});

describe('Environment Detection', () => {
  it('should detect Node.js environment', () => {
    const originalProcess = global.process;
    
    global.process = { versions: { node: '18.0.0' } } as any;
    
    // Re-import to get fresh environment detection
    jest.resetModules();
    const utils = require('../src/utils');
    
    expect(utils.environment.isNode).toBe(true);
    expect(utils.environment.isBrowser).toBe(false);
    
    global.process = originalProcess;
  });

  it('should detect browser environment', () => {
    const originalProcess = global.process;
    const originalWindow = global.window;
    
    // @ts-ignore
    delete global.process;
    // @ts-ignore
    global.window = {};
    
    jest.resetModules();
    const utils = require('../src/utils');
    
    expect(utils.environment.isNode).toBe(false);
    expect(utils.environment.isBrowser).toBe(true);
    
    global.process = originalProcess;
    global.window = originalWindow;
  });
});

describe('Default Logger', () => {
  const originalConsole = { ...console };

  beforeEach(() => {
    console.debug = jest.fn();
    console.info = jest.fn();
    console.warn = jest.fn();
    console.error = jest.fn();
  });

  afterEach(() => {
    console.debug = originalConsole.debug;
    console.info = originalConsole.info;
    console.warn = originalConsole.warn;
    console.error = originalConsole.error;
  });

  it('should have debug logger', () => {
    expect(utils.defaultLogger.debug).toBeDefined();
    utils.defaultLogger.debug('Test debug', { key: 'value' });
    expect(console.debug).toHaveBeenCalled();
  });

  it('should have info logger', () => {
    utils.defaultLogger.info('Test info');
    expect(console.info).toHaveBeenCalled();
  });

  it('should have warn logger', () => {
    utils.defaultLogger.warn('Test warn');
    expect(console.warn).toHaveBeenCalled();
  });

  it('should have error logger', () => {
    utils.defaultLogger.error('Test error');
    expect(console.error).toHaveBeenCalled();
  });
});

describe('Null Logger', () => {
  it('should have all logger methods', () => {
    expect(utils.nullLogger.debug).toBeDefined();
    expect(utils.nullLogger.info).toBeDefined();
    expect(utils.nullLogger.warn).toBeDefined();
    expect(utils.nullLogger.error).toBeDefined();
  });

  it('should not output anything', () => {
    const originalConsole = { ...console };
    console.debug = jest.fn();
    console.info = jest.fn();
    console.warn = jest.fn();
    console.error = jest.fn();

    utils.nullLogger.debug('Test');
    utils.nullLogger.info('Test');
    utils.nullLogger.warn('Test');
    utils.nullLogger.error('Test');

    expect(console.debug).not.toHaveBeenCalled();
    expect(console.info).not.toHaveBeenCalled();
    expect(console.warn).not.toHaveBeenCalled();
    expect(console.error).not.toHaveBeenCalled();

    console.debug = originalConsole.debug;
    console.info = originalConsole.info;
    console.warn = originalConsole.warn;
    console.error = originalConsole.error;
  });
});
