import { ResourceClient } from '../src/clients/resource-client';
import type { AuthManager } from '../src/auth/auth-manager';

function okResponse(headers: Record<string, string> = {}): Response {
  return new Response('', { status: 200, headers });
}

describe('ResourceClient baseline', () => {
  it('honors top-level HTTP configuration and nested precedence', () => {
    const topFetch = jest.fn<typeof fetch>();
    const nestedFetch = jest.fn<typeof fetch>();
    const client = new ResourceClient({
      baseUrl: 'https://top.example/pod/',
      fetch: topFetch,
      useDpop: false,
      httpClientConfig: {
        baseUrl: 'https://nested.example/storage/',
        fetch: nestedFetch,
      },
    });

    expect(client.getHttpClient().getConfig().baseUrl).toBe(
      'https://nested.example/storage/'
    );
    expect(client.getHttpClient().getConfig().fetch).toBe(nestedFetch);
  });

  it('preserves create wildcard and prevents caller auth spoofing', async () => {
    const fetchMock = jest.fn<typeof fetch>().mockResolvedValue(okResponse({ etag: '"v1"' }));
    const authManager = {
      signRequest: jest.fn().mockResolvedValue({
        accessToken: 'trusted-token',
        dpopProof: 'trusted-proof',
      }),
    } as unknown as AuthManager;
    const client = new ResourceClient({
      baseUrl: 'https://pod.example/storage/',
      fetch: fetchMock,
      authManager,
      maxRetries: 0,
    });

    await client.create('/storage/item', 'body', {
      headers: {
        Authorization: 'Bearer attacker',
        DPoP: 'attacker-proof',
        'If-None-Match': 'attacker',
      },
    });

    const [, init] = fetchMock.mock.calls[0]!;
    const headers = init?.headers as Record<string, string>;
    expect(headers.Authorization).toBe('DPoP trusted-token');
    expect(headers.DPoP).toBe('trusted-proof');
    expect(headers['If-None-Match']).toBe('*');
  });

  it('fails closed when DPoP signing fails', async () => {
    const fetchMock = jest.fn<typeof fetch>();
    const authManager = {
      signRequest: jest.fn().mockRejectedValue(new Error('signing failed')),
    } as unknown as AuthManager;
    const client = new ResourceClient({
      baseUrl: 'https://pod.example/storage/',
      fetch: fetchMock,
      authManager,
    });

    await expect(client.get('/storage/item')).rejects.toThrow('signing failed');
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('rejects cross-origin and sibling-prefix resources', async () => {
    const client = new ResourceClient({
      baseUrl: 'https://pod.example/storage/',
      fetch: jest.fn<typeof fetch>(),
      useDpop: false,
    });

    await expect(client.get('https://attacker.example/storage/item')).rejects.toThrow(
      'outside the configured origin'
    );
    await expect(client.get('https://pod.example/storage-evil/item')).rejects.toThrow(
      'outside the configured path scope'
    );
  });

  it('does not weaken an explicitly supplied ETag', async () => {
    const fetchMock = jest.fn<typeof fetch>().mockResolvedValue(okResponse());
    const client = new ResourceClient({
      baseUrl: 'https://pod.example/storage/',
      fetch: fetchMock,
      useDpop: false,
      maxRetries: 0,
    });

    await client.put('/storage/item', 'body', { ifMatch: 'W/"version-1"' });
    const [, init] = fetchMock.mock.calls[0]!;
    expect((init?.headers as Record<string, string>)['If-Match']).toBe(
      'W/"version-1"'
    );
  });
});
