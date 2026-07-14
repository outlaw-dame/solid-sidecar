import sdk, {
  AuthManager,
  DpopKeyStore,
  InMemoryKeyStore,
  NotificationClient,
  PolicyClient,
  RdfCodec,
  ResourceClient,
  SolidSidecarClient,
  SolidSidecarHttpClient,
  SyncClient,
  WebIdClient,
} from '../src/index';

describe('public SDK entry point', () => {
  it('exports all supported public constructors', () => {
    expect(AuthManager).toBeDefined();
    expect(DpopKeyStore).toBeDefined();
    expect(InMemoryKeyStore).toBeDefined();
    expect(NotificationClient).toBeDefined();
    expect(PolicyClient).toBeDefined();
    expect(RdfCodec).toBeDefined();
    expect(ResourceClient).toBeDefined();
    expect(SolidSidecarClient).toBeDefined();
    expect(SolidSidecarHttpClient).toBeDefined();
    expect(SyncClient).toBeDefined();
    expect(WebIdClient).toBeDefined();
  });

  it('keeps the default export aligned with named exports', () => {
    expect(sdk.AuthManager).toBe(AuthManager);
    expect(sdk.ResourceClient).toBe(ResourceClient);
    expect(sdk.SolidSidecarClient).toBe(SolidSidecarClient);
    expect(sdk.SolidSidecarHttpClient).toBe(SolidSidecarHttpClient);
  });

  it('propagates the facade timeout to the HTTP request default', () => {
    const client = new SolidSidecarClient({
      baseUrl: 'https://pod.example',
      timeout: 12_345,
    });

    expect(client.http.getConfig().timeout).toBe(12_345);
    expect(client.http.getConfig().defaultTimeout).toBe(12_345);
  });
});
