import { SolidSidecarHttpClient } from '../src/http-client';
import {
  base64UrlEncode,
  calculateBackoffDelay,
  resolveUrl,
  validateResourceScope,
  validateUrl,
} from '../src/utils';

describe('HTTP transport and utility hardening', () => {
  test('resolves relative resources canonically', () => {
    expect(resolveUrl('https://pod.example/base/', '../profile/card')).toBe(
      'https://pod.example/profile/card'
    );
  });

  test('rejects private targets unless explicitly allowlisted', () => {
    expect(validateUrl('http://127.0.0.1/admin')).toBe(false);
    expect(validateUrl('http://127.0.0.1/admin', ['127.0.0.1'])).toBe(true);
  });

  test('uses URL boundaries instead of string-prefix scope matching', () => {
    expect(
      validateResourceScope(
        'https://pod.example/private/file',
        ['https://pod.example/private/']
      )
    ).toBe(true);
    expect(
      validateResourceScope(
        'https://pod.example/private-escape/file',
        ['https://pod.example/private/']
      )
    ).toBe(false);
    expect(
      validateResourceScope(
        'https://pod.example.evil/private/file',
        ['https://pod.example/private/']
      )
    ).toBe(false);
  });

  test('Base64URL encoding preserves arbitrary binary bytes', () => {
    expect(base64UrlEncode(new Uint8Array([0, 255, 128, 1]))).toBe('AP-AAQ');
  });

  test('validates retry configuration bounds', () => {
    expect(() => calculateBackoffDelay(-1)).toThrow(RangeError);
    expect(() => calculateBackoffDelay(0, { baseDelay: 10, maxDelay: 5 })).toThrow(
      RangeError
    );
  });

  test('fails closed when HTTPS is required', async () => {
    const fetchMock = jest.fn<typeof fetch>();
    const client = new SolidSidecarHttpClient({
      baseUrl: 'http://pod.example/',
      allowedHosts: ['pod.example'],
      fetch: fetchMock,
      validateSsl: true,
    });

    await expect(client.get('/profile')).rejects.toThrow('HTTPS is required');
    expect(fetchMock).not.toHaveBeenCalled();
  });

  test('does not automatically replay POST requests', async () => {
    const fetchMock = jest.fn<typeof fetch>().mockResolvedValue(
      new Response('temporary failure', { status: 503 })
    );
    const client = new SolidSidecarHttpClient({
      baseUrl: 'https://pod.example/',
      allowedHosts: ['pod.example'],
      fetch: fetchMock,
      maxRetries: 3,
      retryDelay: 0,
      maxRetryDelay: 0,
    });

    await expect(client.post('/inbox', 'payload')).rejects.toThrow();
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  test('retries an idempotent GET within configured bounds', async () => {
    const fetchMock = jest
      .fn<typeof fetch>()
      .mockResolvedValueOnce(new Response('temporary failure', { status: 503 }))
      .mockResolvedValueOnce(
        new Response('ok', {
          status: 200,
          headers: { 'content-type': 'text/plain' },
        })
      );
    const client = new SolidSidecarHttpClient({
      baseUrl: 'https://pod.example/',
      allowedHosts: ['pod.example'],
      fetch: fetchMock,
      maxRetries: 1,
      retryDelay: 0,
      maxRetryDelay: 0,
    });

    await expect(client.get<string>('/profile')).resolves.toMatchObject({ body: 'ok' });
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });
});
