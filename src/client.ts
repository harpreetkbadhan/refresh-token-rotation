type FetchInput = Parameters<typeof globalThis.fetch>[0];
type FetchFn = (input: FetchInput, init?: RequestInit) => Promise<Response>;

export interface AuthFetchOptions {
  /** The fetch to wrap. Default: the global fetch. */
  fetch?: FetchFn;
  /** The current access token, or null when there is none. */
  getAccessToken: () => string | null | undefined | Promise<string | null | undefined>;
  /**
   * Exchange the refresh token for new tokens and store them. Resolve true on success and
   * false when the server rejects the refresh token (the session is over). Throw on a
   * temporary problem (offline, timeout, 5xx): the error reaches the callers and the user
   * stays logged in. Call your refresh endpoint with the plain `fetch`, never the wrapped one.
   */
  refresh: () => Promise<boolean>;
  /** Called once when a refresh resolves false, e.g. to send the user to the login screen. */
  onSessionExpired?: () => void;
}

/**
 * Wraps fetch so it sends the access token and, on a 401, refreshes once and retries.
 * However many requests get a 401 at the same time, only one refresh runs; the others
 * wait for it. A retry that still gets a 401 is returned as is, so this never loops.
 *
 * Within one JavaScript context only: browser tabs don't share memory. A second tab
 * refreshing with the same token inside the server's grace window gets the same new
 * token, so that is harmless as long as both tabs store tokens in the same place.
 */
export function createAuthFetch(options: AuthFetchOptions): FetchFn {
  const send = options.fetch ?? ((input: FetchInput, init?: RequestInit) => globalThis.fetch(input, init));
  let inFlight: Promise<boolean> | null = null;

  const currentToken = async (): Promise<string | null> => (await options.getAccessToken()) || null;

  function withToken(request: Request, token: string | null): Promise<Response> {
    const headers = new Headers(request.headers);
    if (token) {
      headers.set('Authorization', `Bearer ${token}`);
    }
    return send(new Request(request, { headers }));
  }

  // Errors from `refresh` reach every waiting caller; only `false` ends the session.
  function refreshOnce(): Promise<boolean> {
    if (!inFlight) {
      inFlight = (async () => {
        const refreshed = await options.refresh();
        if (!refreshed) {
          options.onSessionExpired?.();
        }
        return refreshed;
      })().finally(() => {
        inFlight = null;
      });
    }
    return inFlight;
  }

  async function retry(original: Request, unread: Response): Promise<Response> {
    await unread.body?.cancel().catch(() => undefined);
    return withToken(original, await currentToken());
  }

  return async (input, init) => {
    const original = new Request(input, init);
    const sentToken = await currentToken();
    // Send a copy first, so the body can be sent again on the retry.
    const response = await withToken(original.clone(), sentToken);
    if (response.status !== 401) {
      return response;
    }
    const latest = await currentToken();
    if (latest && latest !== sentToken) {
      // Someone refreshed while this request was out: just retry with the new token.
      return retry(original, response);
    }
    if (!(await refreshOnce())) {
      return response;
    }
    return retry(original, response);
  };
}
