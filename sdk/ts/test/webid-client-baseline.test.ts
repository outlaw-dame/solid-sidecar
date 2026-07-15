import { WebIdClient } from '../src/clients/webid-client';

const WEB_ID = 'https://pod.example/profile/card#me';
const PROFILE = `
<https://pod.example/profile/card#me>
  a <http://xmlns.com/foaf/0.1/Person> ;
  <http://xmlns.com/foaf/0.1/name> "Alice" ;
  <http://www.w3.org/ns/pim/space#storage> <https://pod.example/storage/> .
`;

function profileResponse(body = PROFILE): Response {
  return new Response(body, {
    status: 200,
    headers: {
      'content-type': 'text/turtle',
      etag: '"profile-v1"',
    },
  });
}

describe('WebIdClient baseline', () => {
  it('fetches the profile document without the WebID fragment', async () => {
    const fetchMock = jest.fn<typeof fetch>().mockResolvedValue(profileResponse());
    const client = new WebIdClient({
      baseUrl: 'https://pod.example/profile/',
      fetch: fetchMock,
      useDpop: false,
      maxRetries: 0,
      allowedHosts: ['pod.example'],
    });

    const profile = await client.discoverWebId(WEB_ID);

    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(fetchMock.mock.calls[0]?.[0]).toBe('https://pod.example/profile/card');
    expect(profile.id).toBe(WEB_ID);
    expect(profile.profileUri).toBe('https://pod.example/profile/card');
  });

  it('uses a canonical cache key for equivalent host casing', async () => {
    const fetchMock = jest.fn<typeof fetch>().mockResolvedValue(profileResponse());
    const client = new WebIdClient({
      baseUrl: 'https://pod.example/profile/',
      fetch: fetchMock,
      useDpop: false,
      maxRetries: 0,
      allowedHosts: ['pod.example'],
    });

    await client.discoverWebId('https://POD.EXAMPLE/profile/card#me');
    await client.discoverWebId(WEB_ID);

    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(client.getCacheSize()).toBe(1);
  });

  it('rejects credential-bearing WebIDs before network access', async () => {
    const fetchMock = jest.fn<typeof fetch>();
    const client = new WebIdClient({
      baseUrl: 'https://pod.example/profile/',
      fetch: fetchMock,
      useDpop: false,
      allowedHosts: ['pod.example'],
    });

    await expect(
      client.discoverWebId('https://user:secret@pod.example/profile/card#me')
    ).rejects.toThrow('must not contain credentials');
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
    const client = new WebIdClient({
      baseUrl: 'https://pod.example/profile/',
      fetch: fetchMock,
      useDpop: false,
      maxRetries: 0,
      allowedHosts: ['pod.example'],
      profileCacheSize: 1,
    });

    await client.discoverWebId('https://pod.example/profile/card#one');
    await client.discoverWebId('https://pod.example/profile/card#two');

    expect(client.getCacheSize()).toBe(1);
    expect(client.isCached('https://pod.example/profile/card#one')).toBe(false);
    expect(client.isCached('https://pod.example/profile/card#two')).toBe(true);
    expect(fetchMock).toHaveBeenCalledTimes(2);

    await client.discoverWebId('https://pod.example/profile/card#one');
    expect(fetchMock).toHaveBeenCalledTimes(3);
  });
});
