import { WebIdClient } from '../src/clients/webid-client';
import type { WebIdClientConfig } from '../src/clients/webid-client';

const WEB_ID = 'https://pod.example/profile/card#me';
const PROFILE = `
# A document-level comment must not become a statement.
<https://pod.example/profile/card#me>
  a <http://xmlns.com/foaf/0.1/Person> ;
  <http://xmlns.com/foaf/0.1/name> "Alice" ;
  <http://www.w3.org/ns/pim/space#storage> <https://pod.example/storage/> .
`;

function profileResponse(body = PROFILE, contentType = 'text/turtle'): Response {
  return new Response(body, {
    status: 200,
    headers: {
      'content-type': contentType,
      etag: '"profile-v1"',
    },
  });
}

function createClient(
  fetchMock: typeof fetch,
  overrides: Partial<WebIdClientConfig> = {}
): WebIdClient {
  return new WebIdClient({
    baseUrl: 'https://pod.example/profile/',
    fetch: fetchMock,
    useDpop: false,
    maxRetries: 0,
    allowedHosts: ['pod.example'],
    ...overrides,
  });
}

describe('WebIdClient baseline', () => {
  it('fetches the profile document and parses the first Turtle predicate', async () => {
    const fetchMock = jest.fn<typeof fetch>().mockResolvedValue(profileResponse());
    const profile = await createClient(fetchMock).discoverWebId(WEB_ID);

    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(fetchMock.mock.calls[0]?.[0]).toBe('https://pod.example/profile/card');
    expect(profile.id).toBe(WEB_ID);
    expect(profile.profileUri).toBe('https://pod.example/profile/card');
    expect(profile.type).toBe('http://xmlns.com/foaf/0.1/Person');
    expect(profile.name).toBe('Alice');
    expect(profile.storage).toEqual(['https://pod.example/storage/']);
  });

  it('uses a canonical cache key for equivalent host casing', async () => {
    const fetchMock = jest.fn<typeof fetch>().mockResolvedValue(profileResponse());
    const client = createClient(fetchMock);

    await client.discoverWebId('https://POD.EXAMPLE/profile/card#me');
    await client.discoverWebId(WEB_ID);

    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(client.getCacheSize()).toBe(1);
  });

  it('rejects credential-bearing WebIDs before network access', async () => {
    const fetchMock = jest.fn<typeof fetch>();
    const client = createClient(fetchMock);

    await expect(
      client.discoverWebId('https://user:secret@pod.example/profile/card#me')
    ).rejects.toThrow('must not contain credentials');
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('rejects IPv4-mapped IPv6 private targets before network access', async () => {
    const fetchMock = jest.fn<typeof fetch>();
    const client = createClient(fetchMock, { allowedHosts: [] });

    await expect(
      client.discoverWebId('http://[::ffff:127.0.0.1]/profile/card#me')
    ).rejects.toThrow();
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('bounds the profile cache and re-fetches an evicted entry', async () => {
    const profileOne = `<https://pod.example/profile/card#one>
  a <http://xmlns.com/foaf/0.1/Person> ;
  <http://xmlns.com/foaf/0.1/name> "One" .`;
    const profileTwo = `<https://pod.example/profile/card#two>
  a <http://xmlns.com/foaf/0.1/Person> ;
  <http://xmlns.com/foaf/0.1/name> "Two" .`;
    const fetchMock = jest
      .fn<typeof fetch>()
      .mockResolvedValueOnce(profileResponse(profileOne))
      .mockResolvedValueOnce(profileResponse(profileTwo))
      .mockResolvedValueOnce(profileResponse(profileOne));
    const client = createClient(fetchMock, { profileCacheSize: 1 });

    await client.discoverWebId('https://pod.example/profile/card#one');
    await client.discoverWebId('https://pod.example/profile/card#two');

    expect(client.getCacheSize()).toBe(1);
    expect(client.isCached('https://pod.example/profile/card#one')).toBe(false);
    expect(client.isCached('https://pod.example/profile/card#two')).toBe(true);
    expect(fetchMock).toHaveBeenCalledTimes(2);

    await client.discoverWebId('https://pod.example/profile/card#one');
    expect(fetchMock).toHaveBeenCalledTimes(3);
  });

  it('rejects a profile that does not describe the requested WebID subject', async () => {
    const wrongProfile = `<https://pod.example/profile/card#other>
  <http://xmlns.com/foaf/0.1/name> "Mallory" .`;
    const fetchMock = jest.fn<typeof fetch>().mockResolvedValue(profileResponse(wrongProfile));

    await expect(createClient(fetchMock).discoverWebId(WEB_ID)).rejects.toThrow(
      'does not contain the requested WebID subject'
    );
  });

  it('rejects unsafe profile-derived IRIs instead of returning them', async () => {
    const maliciousProfile = `<https://pod.example/profile/card#me>
  <http://www.w3.org/ns/pim/space#storage> <http://127.0.0.1/private/> .`;
    const fetchMock = jest.fn<typeof fetch>().mockResolvedValue(profileResponse(maliciousProfile));

    await expect(createClient(fetchMock).discoverWebId(WEB_ID)).rejects.toThrow(
      'URL safety validation'
    );
  });

  it('deduplicates option-equivalent concurrent discovery requests', async () => {
    const fetchMock = jest.fn<typeof fetch>().mockResolvedValue(profileResponse());
    const client = createClient(fetchMock);

    const [firstProfile, secondProfile] = await Promise.all([
      client.discoverWebId(WEB_ID),
      client.discoverWebId(WEB_ID),
    ]);

    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(firstProfile).toEqual(secondProfile);
    expect(firstProfile).not.toBe(secondProfile);
  });

  it('does not coalesce or cache requests with different effective headers', async () => {
    const fetchMock = jest.fn<typeof fetch>().mockResolvedValue(profileResponse());
    const client = createClient(fetchMock);

    await Promise.all([
      client.discoverWebId(WEB_ID, { headers: { 'x-tenant': 'alpha' } }),
      client.discoverWebId(WEB_ID, { headers: { 'x-tenant': 'beta' } }),
    ]);

    expect(fetchMock).toHaveBeenCalledTimes(2);
    const sentHeaders = fetchMock.mock.calls.map(call => call[1]?.headers as Record<string, string>);
    expect(sentHeaders.some(headers => headers['x-tenant'] === 'alpha')).toBe(true);
    expect(sentHeaders.some(headers => headers['x-tenant'] === 'beta')).toBe(true);
    expect(client.getCacheSize()).toBe(0);
  });

  it('does not cache profiles when the TTL is zero', async () => {
    const fetchMock = jest.fn<typeof fetch>().mockResolvedValue(profileResponse());
    const client = createClient(fetchMock, { profileCacheTtl: 0 });

    await client.discoverWebId(WEB_ID);
    await client.discoverWebId(WEB_ID);

    expect(fetchMock).toHaveBeenCalledTimes(2);
    expect(client.getCacheSize()).toBe(0);
  });

  it('resolves empty and document-relative Turtle prefixes', async () => {
    const turtle = `
@prefix : <#> .
@prefix foaf: <http://xmlns.com/foaf/0.1/> .
:me a foaf:Person ;
  foaf:name "Relative Alice" .
`;
    const fetchMock = jest.fn<typeof fetch>().mockResolvedValue(profileResponse(turtle));

    const profile = await createClient(fetchMock).discoverWebId(WEB_ID);
    expect(profile.id).toBe(WEB_ID);
    expect(profile.type).toBe('http://xmlns.com/foaf/0.1/Person');
    expect(profile.name).toBe('Relative Alice');
  });

  it('uses response content type when Turtle starts with a blank-node statement', async () => {
    const turtle = `
[] <http://example.com/ignored> "value" .
<https://pod.example/profile/card#me>
  <http://xmlns.com/foaf/0.1/name> "Blank Node Safe" .
`;
    const fetchMock = jest.fn<typeof fetch>().mockResolvedValue(
      profileResponse(turtle, 'text/turtle; charset=utf-8')
    );

    const profile = await createClient(fetchMock).discoverWebId(WEB_ID);
    expect(profile.name).toBe('Blank Node Safe');
  });

  it('parses expanded JSON-LD profiles and validates derived IRIs', async () => {
    const jsonLd = JSON.stringify({
      '@graph': [
        {
          '@id': WEB_ID,
          '@type': 'http://xmlns.com/foaf/0.1/Person',
          'http://xmlns.com/foaf/0.1/name': [{ '@value': 'Alice JSON-LD' }],
          'http://www.w3.org/ns/pim/space#storage': [
            { '@id': 'https://pod.example/storage/' },
          ],
        },
      ],
    });
    const fetchMock = jest
      .fn<typeof fetch>()
      .mockResolvedValue(profileResponse(jsonLd, 'application/ld+json'));

    const profile = await createClient(fetchMock).discoverWebId(WEB_ID);
    expect(profile.name).toBe('Alice JSON-LD');
    expect(profile.storage).toEqual(['https://pod.example/storage/']);
  });

  it('expands JSON-LD context aliases for storage discovery', async () => {
    const jsonLd = JSON.stringify({
      '@context': {
        storage: 'http://www.w3.org/ns/pim/space#storage',
        name: 'http://xmlns.com/foaf/0.1/name',
      },
      '@id': WEB_ID,
      name: 'Context Alice',
      storage: { '@id': 'https://pod.example/storage/' },
    });
    const fetchMock = jest
      .fn<typeof fetch>()
      .mockResolvedValue(profileResponse(jsonLd, 'application/ld+json; charset=utf-8'));

    const profile = await createClient(fetchMock).discoverWebId(WEB_ID);
    expect(profile.name).toBe('Context Alice');
    expect(profile.storage).toEqual(['https://pod.example/storage/']);
  });

  it('contains malformed JSON-LD identifiers without raw URL exceptions', async () => {
    const jsonLd = JSON.stringify({
      '@graph': [{ '@id': 'http://[', name: 'Malformed' }],
    });
    const fetchMock = jest
      .fn<typeof fetch>()
      .mockResolvedValue(profileResponse(jsonLd, 'application/ld+json'));

    await expect(createClient(fetchMock).discoverWebId(WEB_ID)).rejects.toThrow(
      'does not contain the requested WebID subject'
    );
  });

  it('ignores a malformed non-authoritative JSON-LD type IRI', async () => {
    const jsonLd = JSON.stringify({
      '@id': WEB_ID,
      '@type': 'http://[',
      'http://xmlns.com/foaf/0.1/name': 'Alice',
    });
    const fetchMock = jest
      .fn<typeof fetch>()
      .mockResolvedValue(profileResponse(jsonLd, 'application/ld+json'));

    const profile = await createClient(fetchMock).discoverWebId(WEB_ID);
    expect(profile.id).toBe(WEB_ID);
    expect(profile.type).toBeUndefined();
    expect(profile.name).toBe('Alice');
  });

  it('rejects unsupported per-request redirect overrides', async () => {
    const fetchMock = jest.fn<typeof fetch>();
    const client = createClient(fetchMock);

    await expect(client.discoverWebId(WEB_ID, { followRedirects: false })).rejects.toThrow(
      'redirect overrides are unsupported'
    );
    expect(fetchMock).not.toHaveBeenCalled();
  });
});
