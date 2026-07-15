import { WebIdClient } from '../src/clients/webid-client';

const WEB_ID = 'https://pod.example/profile/card#me';

function createClient(fetchMock: typeof fetch, overrides: Record<string, unknown> = {}): WebIdClient {
  return new WebIdClient({
    baseUrl: 'https://pod.example/profile/',
    fetch: fetchMock,
    useDpop: false,
    maxRetries: 0,
    allowedHosts: ['pod.example'],
    ...overrides,
  });
}

function response(body: string, contentType?: string): Response {
  return new Response(body, {
    status: 200,
    headers: contentType ? { 'content-type': contentType } : {},
  });
}

describe('WebIdClient late review hardening', () => {
  it('does not share cached profiles when implicit authentication is enabled', async () => {
    const turtle = `<${WEB_ID}> <http://xmlns.com/foaf/0.1/name> "Alice" .`;
    const fetchMock = jest.fn<typeof fetch>().mockResolvedValue(response(turtle, 'text/turtle'));
    const client = createClient(fetchMock, { useDpop: true });

    await client.discoverWebId(WEB_ID);
    await client.discoverWebId(WEB_ID);

    expect(fetchMock).toHaveBeenCalledTimes(2);
    expect(client.getCacheSize()).toBe(0);
  });

  it('parses application/ld+json when the HTTP client returns a parsed JSON body', async () => {
    const jsonLd = JSON.stringify({
      '@id': WEB_ID,
      'http://xmlns.com/foaf/0.1/name': 'Parsed JSON Alice',
    });
    const fetchMock = jest
      .fn<typeof fetch>()
      .mockResolvedValue(response(jsonLd, 'application/ld+json'));

    const profile = await createClient(fetchMock).discoverWebId(WEB_ID);
    expect(profile.name).toBe('Parsed JSON Alice');
    expect(profile.raw).toContain('Parsed JSON Alice');
  });

  it('recognizes JSON-LD arrays without content type and falls back for Turtle blank nodes', async () => {
    const jsonArray = JSON.stringify([
      { '@id': WEB_ID, 'http://xmlns.com/foaf/0.1/name': 'Array Alice' },
    ]);
    const turtle = `[] <http://example.com/ignored> "value" .\n<${WEB_ID}> <http://xmlns.com/foaf/0.1/name> "Turtle Alice" .`;
    const fetchMock = jest
      .fn<typeof fetch>()
      .mockResolvedValueOnce(response(jsonArray))
      .mockResolvedValueOnce(response(turtle));

    const first = await createClient(fetchMock, { profileCacheTtl: 0 }).discoverWebId(WEB_ID);
    const second = await createClient(fetchMock, { profileCacheTtl: 0 }).discoverWebId(WEB_ID);

    expect(first.name).toBe('Array Alice');
    expect(second.name).toBe('Turtle Alice');
  });

  it('expands out-of-order and recursively defined JSON-LD context aliases', async () => {
    const jsonLd = JSON.stringify({
      '@context': {
        storage: 'pim:storage',
        pim: 'http://www.w3.org/ns/pim/space#',
      },
      '@id': WEB_ID,
      storage: { '@id': 'https://pod.example/storage/' },
    });
    const fetchMock = jest
      .fn<typeof fetch>()
      .mockResolvedValue(response(jsonLd, 'application/ld+json'));

    const profile = await createClient(fetchMock).discoverWebId(WEB_ID);
    expect(profile.storage).toEqual(['https://pod.example/storage/']);
  });

  it('preserves root context aliases when a node context overrides their prefix', async () => {
    const jsonLd = JSON.stringify({
      '@context': {
        pim: 'http://www.w3.org/ns/pim/space#',
        storage: 'pim:storage',
      },
      '@graph': [
        {
          '@id': WEB_ID,
          '@context': {
            pim: 'https://example.invalid/overridden#',
          },
          storage: { '@id': 'https://pod.example/storage/' },
        },
      ],
    });
    const fetchMock = jest
      .fn<typeof fetch>()
      .mockResolvedValue(response(jsonLd, 'application/ld+json'));

    const profile = await createClient(fetchMock).discoverWebId(WEB_ID);
    expect(profile.storage).toEqual(['https://pod.example/storage/']);
  });

  it('preserves compact FOAF and PIM keys without a local JSON-LD context', async () => {
    const jsonLd = JSON.stringify({
      '@id': WEB_ID,
      'foaf:name': 'Compact Alice',
      'pim:storage': { '@id': 'https://pod.example/storage/' },
    });
    const fetchMock = jest
      .fn<typeof fetch>()
      .mockResolvedValue(response(jsonLd, 'application/ld+json'));

    const profile = await createClient(fetchMock).discoverWebId(WEB_ID);
    expect(profile.name).toBe('Compact Alice');
    expect(profile.storage).toEqual(['https://pod.example/storage/']);
  });

  it('keeps semicolons and hash characters inside Turtle literals and supports empty local names', async () => {
    const turtle = `
@prefix profile: <${WEB_ID}> .
profile: <http://xmlns.com/foaf/0.1/name> "Alice #1; Bob" ;
  <http://www.w3.org/ns/pim/space#storage> <https://pod.example/storage/#primary> . # trailing comment
`;
    const fetchMock = jest.fn<typeof fetch>().mockResolvedValue(response(turtle, 'text/turtle'));

    const profile = await createClient(fetchMock).discoverWebId(WEB_ID);
    expect(profile.name).toBe('Alice #1; Bob');
    expect(profile.storage).toEqual(['https://pod.example/storage/#primary']);
  });

  it('does not terminate Turtle statements at dots inside prefixed-name locals', async () => {
    const dottedWebId = 'https://pod.example/profile/card#me.v1';
    const turtle = `
@prefix profile: <#> .
profile:me.v1 <http://xmlns.com/foaf/0.1/name> "Dotted Alice" .
`;
    const fetchMock = jest.fn<typeof fetch>().mockResolvedValue(response(turtle, 'text/turtle'));

    const profile = await createClient(fetchMock).discoverWebId(dottedWebId);
    expect(profile.id).toBe(dottedWebId);
    expect(profile.name).toBe('Dotted Alice');
  });
});
