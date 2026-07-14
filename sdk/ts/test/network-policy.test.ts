import {
  isPrivateOrLocalHostname,
  isResourceWithinScope,
  validateOutboundUrl,
} from '../src/security/network-policy';

describe('validateOutboundUrl', () => {
  it.each([
    ['http://pod.example/resource', 'unsupported_scheme'],
    ['ftp://pod.example/resource', 'unsupported_scheme'],
    ['https://user:secret@pod.example/resource', 'credentials_forbidden'],
    ['https://localhost/resource', 'private_host_forbidden'],
    ['https://api.local/resource', 'private_host_forbidden'],
    ['https://service/resource', 'private_host_forbidden'],
    ['https://127.0.0.1/resource', 'private_host_forbidden'],
    ['https://10.0.0.4/resource', 'private_host_forbidden'],
    ['https://169.254.169.254/latest/meta-data', 'private_host_forbidden'],
    ['https://[::1]/resource', 'private_host_forbidden'],
    ['https://[fd00::1]/resource', 'private_host_forbidden'],
    ['https://[::ffff:127.0.0.1]/resource', 'private_host_forbidden'],
    ['https://[::ffff:10.0.0.4]/resource', 'private_host_forbidden'],
    ['https://[::127.0.0.1]/resource', 'private_host_forbidden'],
  ])('rejects unsafe target %s', (input, reason) => {
    expect(validateOutboundUrl(input)).toEqual({ ok: false, reason });
  });

  it('accepts a public HTTPS URL', () => {
    const result = validateOutboundUrl('https://pod.example/resource');
    expect(result.ok).toBe(true);
    expect(result.url?.origin).toBe('https://pod.example');
  });

  it('requires exact allowlisted host matches', () => {
    expect(
      validateOutboundUrl('https://pod.example/resource', {
        allowedHosts: ['pod.example'],
      }).ok
    ).toBe(true);

    expect(
      validateOutboundUrl('https://evilpod.example/resource', {
        allowedHosts: ['pod.example'],
      })
    ).toEqual({ ok: false, reason: 'host_not_allowed' });
  });

  it('requires exact origin matches including port', () => {
    expect(
      validateOutboundUrl('https://pod.example:8443/resource', {
        allowedOrigins: ['https://pod.example:8443'],
      }).ok
    ).toBe(true);

    expect(
      validateOutboundUrl('https://pod.example/resource', {
        allowedOrigins: ['https://pod.example:8443'],
      })
    ).toEqual({ ok: false, reason: 'origin_not_allowed' });
  });

  it('allows explicit local HTTP only when both overrides are enabled', () => {
    expect(
      validateOutboundUrl('http://localhost:3000/resource', {
        allowHttp: true,
        allowPrivateHosts: true,
      }).ok
    ).toBe(true);
  });
});

describe('isPrivateOrLocalHostname', () => {
  it.each([
    'localhost',
    'x.localhost',
    'printer.local',
    'singlelabel',
    '0.0.0.0',
    '100.64.0.1',
    '172.16.0.1',
    '192.168.1.1',
    '224.0.0.1',
    '::',
    '::1',
    'fe80::1',
    'ff02::1',
    '::ffff:127.0.0.1',
    '::ffff:10.0.0.4',
    '::ffff:7f00:1',
    '::ffff:a00:4',
    '::127.0.0.1',
    '::7f00:1',
  ])('classifies %s as private or local', hostname => {
    expect(isPrivateOrLocalHostname(hostname)).toBe(true);
  });

  it.each(['pod.example', '93.184.216.34', '2001:4860:4860::8888'])('
    does not classify %s as private or local',
    hostname => {
      expect(isPrivateOrLocalHostname(hostname)).toBe(false);
    }
  );
});

describe('isResourceWithinScope', () => {
  it('accepts the exact scope and descendants', () => {
    expect(
      isResourceWithinScope(
        'https://pod.example/private',
        'https://pod.example/private'
      )
    ).toBe(true);
    expect(
      isResourceWithinScope(
        'https://pod.example/private/document.ttl',
        'https://pod.example/private/'
      )
    ).toBe(true);
  });

  it('rejects prefix-confusion and cross-origin targets', () => {
    expect(
      isResourceWithinScope(
        'https://pod.example/private-evil/document.ttl',
        'https://pod.example/private/'
      )
    ).toBe(false);
    expect(
      isResourceWithinScope(
        'https://evil.example/private/document.ttl',
        'https://pod.example/private/'
      )
    ).toBe(false);
  });

  it('canonicalizes dot segments without widening access', () => {
    expect(
      isResourceWithinScope(
        'https://pod.example/private/../public/document.ttl',
        'https://pod.example/private/'
      )
    ).toBe(false);
  });

  it('supports relative resource paths with segment boundaries', () => {
    expect(isResourceWithinScope('/private/a', '/private/')).toBe(true);
    expect(isResourceWithinScope('/private-other/a', '/private/')).toBe(false);
    expect(
      isResourceWithinScope('/private/a', 'https://pod.example/private/')
    ).toBe(true);
    expect(isResourceWithinScope('a', 'https://pod.example/private/')).toBe(true);
    expect(
      isResourceWithinScope('../private-other/a', 'https://pod.example/private/')
    ).toBe(false);
  });
});
