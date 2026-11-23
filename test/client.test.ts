import { describe, expect, it, vi } from 'vitest';
import { createAuthFetch } from '../src/client.js';

// A fake API: requests with the current access token get 200, anything else 401.
function fakeApi() {
  const state = { validToken: 'access-1', calls: [] as { url: string; auth: string | null; body: string | null }[] };
  const fetch = vi.fn(async (input: Parameters<typeof globalThis.fetch>[0], init?: RequestInit) => {
    const request = new Request(input, init);
    const auth = request.headers.get('authorization');
    state.calls.push({ url: request.url, auth, body: request.body ? await request.text() : null });
    return new Response(null, { status: auth === `Bearer ${state.validToken}` ? 200 : 401 });
  });
  return { state, fetch };
}

describe('createAuthFetch', () => {
  it('sends the access token and passes successful responses through', async () => {
    const { fetch, state } = fakeApi();
    const refresh = vi.fn(async () => true);
    const authFetch = createAuthFetch({ fetch, getAccessToken: () => 'access-1', refresh });

    const response = await authFetch('https://api.test/me');
    expect(response.status).toBe(200);
    expect(state.calls[0]?.auth).toBe('Bearer access-1');
    expect(refresh).not.toHaveBeenCalled();
  });

  it('runs one refresh for many parallel 401s, then retries each request once', async () => {
    const { fetch, state } = fakeApi();
    let accessToken = 'expired';
    const refresh = vi.fn(async () => {
      await new Promise((resolve) => setTimeout(resolve, 10));
      accessToken = 'access-1';
      return true;
    });
    const authFetch = createAuthFetch({ fetch, getAccessToken: () => accessToken, refresh });

    const responses = await Promise.all(
      ['a', 'b', 'c', 'd', 'e'].map((path) => authFetch(`https://api.test/${path}`)),
    );
    expect(responses.map((r) => r.status)).toEqual([200, 200, 200, 200, 200]);
    expect(refresh).toHaveBeenCalledTimes(1);
    expect(state.calls).toHaveLength(10);
  });

  it('gives up and reports the expired session when the refresh fails', async () => {
    const { fetch } = fakeApi();
    const onSessionExpired = vi.fn();
    const refresh = vi.fn(async () => false);
    const authFetch = createAuthFetch({ fetch, getAccessToken: () => 'expired', refresh, onSessionExpired });

    const responses = await Promise.all([authFetch('https://api.test/a'), authFetch('https://api.test/b')]);
    expect(responses.map((r) => r.status)).toEqual([401, 401]);
    expect(refresh).toHaveBeenCalledTimes(1);
    expect(onSessionExpired).toHaveBeenCalledTimes(1);
  });

  it('does not log the user out when the refresh fails with an error (offline, 5xx)', async () => {
    const { fetch } = fakeApi();
    const onSessionExpired = vi.fn();
    const authFetch = createAuthFetch({
      fetch,
      getAccessToken: () => 'expired',
      refresh: async () => {
        throw new Error('network down');
      },
      onSessionExpired,
    });
    await expect(
      Promise.all([authFetch('https://api.test/a'), authFetch('https://api.test/b')]),
    ).rejects.toThrow('network down');
    expect(onSessionExpired).not.toHaveBeenCalled();
  });

  it('retries without a second refresh when the token changed while the request was out', async () => {
    const { fetch, state } = fakeApi();
    let accessToken = 'expired';
    const refresh = vi.fn(async () => true);
    // The request is sent with the old token; before its 401 arrives, another request refreshed.
    const slowFetch = vi.fn(async (input: Parameters<typeof globalThis.fetch>[0], init?: RequestInit) => {
      const response = await fetch(input, init);
      accessToken = 'access-1';
      return response;
    });
    const authFetch = createAuthFetch({ fetch: slowFetch, getAccessToken: () => accessToken, refresh });

    expect((await authFetch('https://api.test/a')).status).toBe(200);
    expect(refresh).not.toHaveBeenCalled();
    expect(state.calls.map((c) => c.auth)).toEqual(['Bearer expired', 'Bearer access-1']);
  });

  it('never loops: a retry that is still 401 is returned as is', async () => {
    const { fetch, state } = fakeApi();
    state.validToken = 'never-matches';
    const refresh = vi.fn(async () => true);
    const authFetch = createAuthFetch({ fetch, getAccessToken: () => 'access-1', refresh });

    expect((await authFetch('https://api.test/a')).status).toBe(401);
    expect(refresh).toHaveBeenCalledTimes(1);
    expect(state.calls).toHaveLength(2);
  });

  it('can resend a request body on the retry, also for a Request object', async () => {
    const { fetch, state } = fakeApi();
    let accessToken = 'expired';
    const authFetch = createAuthFetch({
      fetch,
      getAccessToken: () => accessToken,
      refresh: async () => {
        accessToken = 'access-1';
        return true;
      },
    });

    const request = new Request('https://api.test/posts', { method: 'POST', body: '{"title":"hi"}' });
    expect((await authFetch(request)).status).toBe(200);
    expect(state.calls.map((c) => c.body)).toEqual(['{"title":"hi"}', '{"title":"hi"}']);
  });

  it('starts a new refresh for a later wave of 401s', async () => {
    const { fetch, state } = fakeApi();
    let accessToken = 'expired';
    const refresh = vi.fn(async () => {
      accessToken = state.validToken;
      return true;
    });
    const authFetch = createAuthFetch({ fetch, getAccessToken: () => accessToken, refresh });

    await authFetch('https://api.test/a');
    state.validToken = 'access-2'; // the access token expired again later
    expect((await authFetch('https://api.test/b')).status).toBe(200);
    expect(refresh).toHaveBeenCalledTimes(2);
  });

  it('sends no Authorization header when there is no access token yet', async () => {
    const { fetch, state } = fakeApi();
    const authFetch = createAuthFetch({ fetch, getAccessToken: () => null, refresh: async () => false });
    await authFetch('https://api.test/public');
    expect(state.calls[0]?.auth).toBeNull();
  });
});
