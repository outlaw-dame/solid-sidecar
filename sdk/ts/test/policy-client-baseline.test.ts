import { PolicyClient } from '../src/clients/policy-client';
import type { AcpPolicy, WacPolicy } from '../src/types';

function response(body = '', headers: Record<string, string> = {}): Response {
  return new Response(body, { status: 200, headers });
}

describe('PolicyClient baseline', () => {
  it('serializes WAC safely and preserves write preconditions', async () => {
    const fetchMock = jest.fn<typeof fetch>().mockResolvedValue(
      response('', { etag: '"policy-2"' })
    );
    const client = new PolicyClient({
      baseUrl: 'https://pod.example/storage/',
      fetch: fetchMock,
      useDpop: false,
    });
    const policy: WacPolicy = {
      authorization: [
        {
          type: 'Authorization',
          accessTo: 'https://pod.example/storage/doc',
          agent: 'https://alice.example/profile#me',
          mode: ['Read', 'Write'],
        },
      ],
    };

    await client.setWacPolicy('/storage/doc?ignored=1#fragment', policy, {
      ifMatch: 'policy-1',
      headers: { 'if-match': 'attacker' },
    });

    const [url, init] = fetchMock.mock.calls[0]!;
    expect(url).toBe('https://pod.example/storage/doc.acl');
    const headers = new Headers(init?.headers);
    expect(headers.get('if-match')).toBe('"policy-1"');
    const turtle = String(init?.body);
    expect(turtle).toContain('acl:agent <https://alice.example/profile#me>');
    expect(turtle).toContain('acl:mode <http://www.w3.org/ns/auth/acl#Read>');
  });

  it('rejects policy IRIs that can break Turtle syntax', async () => {
    const client = new PolicyClient({
      baseUrl: 'https://pod.example/storage/',
      fetch: jest.fn<typeof fetch>(),
      useDpop: false,
    });
    const policy: WacPolicy = {
      authorization: [
        {
          type: 'Authorization',
          accessTo: 'https://pod.example/storage/doc',
          agent: 'https://alice.example/profile> <https://attacker.example/',
          mode: 'Read',
        },
      ],
    };
    await expect(client.setWacPolicy('/storage/doc', policy)).rejects.toThrow(
      'Invalid agent IRI'
    );
  });

  it('does not treat arbitrary WAC agent classes as matching every agent', async () => {
    const turtle = `@prefix acl: <http://www.w3.org/ns/auth/acl#> .\n\n<https://pod.example/storage/doc.acl#auth> a acl:Authorization ;\n  acl:accessTo <https://pod.example/storage/doc> ;\n  acl:agentClass <https://groups.example/private-class> ;\n  acl:mode <http://www.w3.org/ns/auth/acl#Read> .\n`;
    const fetchMock = jest.fn<typeof fetch>().mockResolvedValue(
      response(turtle, { 'content-type': 'text/turtle' })
    );
    const client = new PolicyClient({
      baseUrl: 'https://pod.example/storage/',
      fetch: fetchMock,
      useDpop: false,
    });
    await expect(
      client.checkWacAccess(
        '/storage/doc',
        'https://alice.example/profile#me',
        'Read'
      )
    ).resolves.toBe(false);
  });

  it('evaluates ACP deny rules before allow rules', async () => {
    const turtle = `@prefix acp: <http://www.w3.org/ns/solid/acp#> .\n\n<> a acp:AccessPolicy ;\n  acp:appliesTo <https://pod.example/storage/doc> ;\n  acp:allow [ acp:actorClass <http://xmlns.com/foaf/0.1/Agent> ; acp:operation <http://www.w3.org/ns/solid/acp#Read> ] ;\n  acp:deny [ acp:actor <https://alice.example/profile#me> ; acp:operation <http://www.w3.org/ns/solid/acp#Read> ] .\n`;
    const fetchMock = jest.fn<typeof fetch>().mockResolvedValue(
      response(turtle, { 'content-type': 'text/turtle' })
    );
    const client = new PolicyClient({
      baseUrl: 'https://pod.example/storage/',
      fetch: fetchMock,
      useDpop: false,
    });
    await expect(
      client.checkAcpAccess(
        '/storage/doc',
        'https://alice.example/profile#me',
        'Read'
      )
    ).resolves.toBe(false);
  });

  it('rejects ACP appliesTo values that broaden policy scope', async () => {
    const client = new PolicyClient({
      baseUrl: 'https://pod.example/storage/',
      fetch: jest.fn<typeof fetch>(),
      useDpop: false,
    });
    const policy: AcpPolicy = {
      appliesTo: 'https://pod.example/storage/',
      allow: [
        {
          type: 'allow',
          actorClass: 'http://xmlns.com/foaf/0.1/Agent',
          operation: 'Read',
        },
      ],
    };
    await expect(client.setAcpPolicy('/storage/doc', policy)).rejects.toThrow(
      'ACP appliesTo must equal the target resource'
    );
  });

  it('rejects resources outside the configured origin and path scope', async () => {
    const client = new PolicyClient({
      baseUrl: 'https://pod.example/storage/',
      fetch: jest.fn<typeof fetch>(),
      useDpop: false,
    });
    await expect(
      client.getWacPolicy('https://attacker.example/storage/doc')
    ).rejects.toThrow('outside the configured scope');
    await expect(client.getWacPolicy('https://pod.example/admin/doc')).rejects.toThrow(
      'outside the configured scope'
    );
  });

  it('inherits a nested container policy from its parent container', async () => {
    const parentPolicy = `<https://pod.example/storage/.acl#auth> a <http://www.w3.org/ns/auth/acl#Authorization> ;\n  <http://www.w3.org/ns/auth/acl#accessTo> <https://pod.example/storage/> ;\n  <http://www.w3.org/ns/auth/acl#agentClass> <http://xmlns.com/foaf/0.1/Agent> ;\n  <http://www.w3.org/ns/auth/acl#mode> <http://www.w3.org/ns/auth/acl#Read> .\n`;
    const fetchMock = jest
      .fn<typeof fetch>()
      .mockResolvedValueOnce(
        new Response(JSON.stringify({ message: 'missing' }), {
          status: 404,
          headers: { 'content-type': 'application/json' },
        })
      )
      .mockResolvedValueOnce(response(parentPolicy, { 'content-type': 'text/turtle' }));
    const client = new PolicyClient({
      baseUrl: 'https://pod.example/storage/',
      fetch: fetchMock,
      useDpop: false,
    });

    await expect(client.getWacPolicy('/storage/projects/')).resolves.not.toBeNull();
    expect(fetchMock.mock.calls.map(call => call[0])).toEqual([
      'https://pod.example/storage/projects/.acl',
      'https://pod.example/storage/.acl',
    ]);
  });

  it('parses expanded WAC predicate IRIs', async () => {
    const turtle = `<https://pod.example/storage/doc.acl#auth> a <http://www.w3.org/ns/auth/acl#Authorization> ;\n  <http://www.w3.org/ns/auth/acl#accessTo> <https://pod.example/storage/doc> ;\n  <http://www.w3.org/ns/auth/acl#agent> <https://alice.example/profile#me> ;\n  <http://www.w3.org/ns/auth/acl#mode> <http://www.w3.org/ns/auth/acl#Read> .\n`;
    const client = new PolicyClient({
      baseUrl: 'https://pod.example/storage/',
      fetch: jest.fn<typeof fetch>().mockResolvedValue(
        response(turtle, { 'content-type': 'text/turtle' })
      ),
      useDpop: false,
    });
    await expect(
      client.checkWacAccess(
        '/storage/doc',
        'https://alice.example/profile#me',
        'Read'
      )
    ).resolves.toBe(true);
  });

  it('parses expanded ACP predicate IRIs', async () => {
    const turtle = `<> a <http://www.w3.org/ns/solid/acp#AccessPolicy> ;\n  <http://www.w3.org/ns/solid/acp#appliesTo> <https://pod.example/storage/doc> ;\n  <http://www.w3.org/ns/solid/acp#allow> [\n    <http://www.w3.org/ns/solid/acp#actor> <https://alice.example/profile#me> ;\n    <http://www.w3.org/ns/solid/acp#operation> <http://www.w3.org/ns/solid/acp#Read>\n  ] .\n`;
    const client = new PolicyClient({
      baseUrl: 'https://pod.example/storage/',
      fetch: jest.fn<typeof fetch>().mockResolvedValue(
        response(turtle, { 'content-type': 'text/turtle' })
      ),
      useDpop: false,
    });
    await expect(
      client.checkAcpAccess(
        '/storage/doc',
        'https://alice.example/profile#me',
        'Read'
      )
    ).resolves.toBe(true);
  });
});
