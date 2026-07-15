import { NotificationClient } from '../src/clients/notification-client';

class MockEventSource {
  public static readonly CONNECTING = 0;
  public static readonly OPEN = 1;
  public static readonly CLOSED = 2;
  public static readonly instances: MockEventSource[] = [];

  public readonly CONNECTING = 0;
  public readonly OPEN = 1;
  public readonly CLOSED = 2;
  public readyState = MockEventSource.CONNECTING;
  public readonly url: string;
  public readonly withCredentials: boolean;
  public onopen: ((event: Event) => void) | null = null;
  public onerror: ((event: Event) => void) | null = null;
  public onmessage: ((event: MessageEvent) => void) | null = null;

  constructor(url: string, options?: EventSourceInit) {
    this.url = url;
    this.withCredentials = options?.withCredentials ?? false;
    MockEventSource.instances.push(this);
  }

  public open(): void {
    this.readyState = MockEventSource.OPEN;
    this.onopen?.(new Event('open'));
  }

  public emit(data: object, id = 'event-1'): void {
    this.onmessage?.(
      new MessageEvent('message', {
        data: JSON.stringify(data),
        lastEventId: id,
      })
    );
  }

  public failClosed(): void {
    this.readyState = MockEventSource.CLOSED;
    this.onerror?.(new Event('error'));
  }

  public close(): void {
    this.readyState = MockEventSource.CLOSED;
  }

  public addEventListener(): void {}
  public removeEventListener(): void {}
  public dispatchEvent(): boolean {
    return true;
  }
}

describe('NotificationClient baseline', () => {
  const originalEventSource = globalThis.EventSource;

  beforeEach(() => {
    MockEventSource.instances.length = 0;
    globalThis.EventSource = MockEventSource as unknown as typeof EventSource;
  });

  afterAll(() => {
    globalThis.EventSource = originalEventSource;
  });

  it('enforces maxEvents and dispatches close exactly once', async () => {
    const onEvent = jest.fn();
    const onClose = jest.fn();
    const client = new NotificationClient({
      baseUrl: 'https://sidecar.example/api/',
      enableHeartbeat: false,
    });
    const subscription = await client.subscribe({
      resourceUri: '/api/pod/resource',
      maxEvents: 1,
      onEvent,
      onClose,
    });

    const source = MockEventSource.instances[0]!;
    source.emit({
      type: 'ResourceUpdated',
      resource: 'https://sidecar.example/api/pod/resource',
      timestamp: '2026-07-14T00:00:00.000Z',
    });

    expect(onEvent).toHaveBeenCalledTimes(1);
    expect(onClose).toHaveBeenCalledTimes(1);
    expect(subscription.isActive).toBe(false);
    await subscription.close();
    expect(onClose).toHaveBeenCalledTimes(1);
  });

  it('resumes with the cursor encoded into the replacement EventSource URL', async () => {
    const client = new NotificationClient({
      baseUrl: 'https://sidecar.example/api/',
      enableHeartbeat: false,
      reconnectBaseDelay: 0,
      reconnectMaxDelay: 0,
    });
    const subscription = await client.subscribe({
      resourceUri: '/api/pod/resource',
    });

    await subscription.resume('cursor-42');

    expect(MockEventSource.instances).toHaveLength(2);
    const replacement = new URL(MockEventSource.instances[1]!.url);
    expect(replacement.searchParams.get('cursor')).toBe('cursor-42');
    expect(replacement.searchParams.get('resource')).toBe(
      'https://sidecar.example/api/pod/resource'
    );
  });

  it('dispatches one error and closes when reconnect attempts are exhausted', async () => {
    const onError = jest.fn();
    const onClose = jest.fn();
    const client = new NotificationClient({
      baseUrl: 'https://sidecar.example/api/',
      enableHeartbeat: false,
      maxReconnectAttempts: 0,
    });
    const subscription = await client.subscribe({
      resourceUri: '/api/pod/resource',
      onError,
      onClose,
    });

    MockEventSource.instances[0]!.failClosed();
    await Promise.resolve();

    expect(onError).toHaveBeenCalledTimes(1);
    expect(onClose).toHaveBeenCalledTimes(1);
    expect(subscription.isActive).toBe(false);
  });

  it('rejects resources outside the configured origin and path scope', async () => {
    const client = new NotificationClient({
      baseUrl: 'https://sidecar.example/api/',
      enableHeartbeat: false,
    });

    await expect(
      client.subscribe({ resourceUri: 'https://attacker.example/api/resource' })
    ).rejects.toThrow('outside the configured origin');
    await expect(
      client.subscribe({ resourceUri: 'https://sidecar.example/admin/resource' })
    ).rejects.toThrow('outside the configured path scope');
  });
});
