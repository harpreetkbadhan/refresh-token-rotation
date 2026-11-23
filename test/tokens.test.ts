import { describe, expect, it } from 'vitest';
import {
  createMemoryStore,
  createRefreshTokens,
  type RefreshTokenStore,
  type RefreshTokensOptions,
} from '../src/index.js';

const SECRET = 'a-test-server-secret-of-at-least-32-chars';
const DAY = 24 * 60 * 60 * 1000;

function setup(options: Partial<RefreshTokensOptions> = {}) {
  let clock = 1_700_000_000_000;
  const store = createMemoryStore();
  const tokens = createRefreshTokens({
    store,
    secret: SECRET,
    idleTtlMs: 30 * DAY,
    maxSessionMs: 90 * DAY,
    reuseGraceMs: 10_000,
    now: () => clock,
    ...options,
  });
  return { tokens, store, advance: (ms: number) => (clock += ms) };
}

describe('createRefreshTokens', () => {
  it('refuses a missing or short secret and nonsensical options', () => {
    const store = createMemoryStore();
    expect(() => createRefreshTokens({ store, secret: 'short' })).toThrow(/secret/);
    expect(() => createRefreshTokens({ store, secret: SECRET, idleTtlMs: 0 })).toThrow(/idleTtlMs/);
    expect(() => createRefreshTokens({ store, secret: SECRET, reuseGraceMs: -1 })).toThrow(/reuseGraceMs/);
    expect(() => createRefreshTokens({ store, secret: SECRET, idleTtlMs: 10, maxSessionMs: 5 })).toThrow(
      /maxSessionMs/,
    );
  });
});

describe('issue and rotate', () => {
  it('issues an opaque token and rotates it into a new one in the same session', async () => {
    const { tokens } = setup();
    const issued = await tokens.issue('user-1');
    expect(issued.token).toMatch(/^[\w-]+\.[\w-]+$/);

    const rotated = await tokens.rotate(issued.token);
    expect(rotated).toMatchObject({ ok: true, userId: 'user-1', sessionId: issued.sessionId });
    if (!rotated.ok) throw new Error('unreachable');
    expect(rotated.token).not.toBe(issued.token);
    expect((await tokens.rotate(rotated.token)).ok).toBe(true);
  });

  it('never stores a token in plain text', async () => {
    const { tokens, store } = setup();
    const { token } = await tokens.issue('user-1');
    const secretPart = token.split('.')[1] ?? '';
    expect(JSON.stringify(store.dump())).not.toContain(secretPart);
  });

  it('answers invalid for garbage, an unknown id or a wrong secret, without touching the session', async () => {
    const { tokens } = setup();
    const { token, sessionId } = await tokens.issue('user-1');
    const [id] = token.split('.');
    for (const bad of ['', 'nonsense', 'a.b.c', `${id}.wrong-secret`, 'AAAAAAAAAAAAAAAAAAAAAA.AAAA']) {
      expect(await tokens.rotate(bad)).toEqual({ ok: false, reason: 'invalid' });
    }
    expect(await tokens.isSessionActive(sessionId)).toBe(true);
    expect((await tokens.rotate(token)).ok).toBe(true);
  });
});

describe('reuse detection', () => {
  it('revokes the whole session when a used token comes back after the grace window', async () => {
    const { tokens, advance } = setup();
    const issued = await tokens.issue('user-1');
    const rotated = await tokens.rotate(issued.token);
    if (!rotated.ok) throw new Error('unreachable');

    advance(10_001);
    expect(await tokens.rotate(issued.token)).toEqual({ ok: false, reason: 'reused' });
    // The thief and the real user are both out: the newest token is dead too.
    expect(await tokens.rotate(rotated.token)).toEqual({ ok: false, reason: 'revoked' });
    expect(await tokens.isSessionActive(issued.sessionId)).toBe(false);
  });

  it('gives a duplicate inside the grace window the same new token (idempotent rotation)', async () => {
    const { tokens, advance } = setup();
    const issued = await tokens.issue('user-1');
    const first = await tokens.rotate(issued.token);
    advance(5_000);
    const second = await tokens.rotate(issued.token);

    expect(second).toEqual(first);
    if (!second.ok) throw new Error('unreachable');
    expect((await tokens.rotate(second.token)).ok).toBe(true);
    expect(await tokens.isSessionActive(issued.sessionId)).toBe(true);
  });

  it('lets two parallel refreshes with the same token both succeed with the same token', async () => {
    const { tokens } = setup();
    const issued = await tokens.issue('user-1');
    const [a, b] = await Promise.all([tokens.rotate(issued.token), tokens.rotate(issued.token)]);
    expect(a.ok && b.ok).toBe(true);
    expect(a).toEqual(b);
  });

  it('gives a late duplicate the newest token of a chain, not a retired one', async () => {
    const { tokens, advance } = setup();
    const a = await tokens.issue('user-1');
    const b = await tokens.rotate(a.token); // tab 1: A -> B
    if (!b.ok) throw new Error('unreachable');
    advance(1_000);
    const c = await tokens.rotate(b.token); // tab 1: B -> C
    advance(1_000);
    const late = await tokens.rotate(a.token); // tab 2 still holds A, inside A's grace

    expect(late).toEqual(c);
    advance(60_000); // long after every grace window
    if (!late.ok) throw new Error('unreachable');
    expect((await tokens.rotate(late.token)).ok).toBe(true);
  });

  it('measures the grace window from the presented token, so walking a chain cannot stretch it', async () => {
    const { tokens, advance } = setup();
    const a = await tokens.issue('user-1');
    const b = await tokens.rotate(a.token);
    if (!b.ok) throw new Error('unreachable');
    advance(9_000);
    await tokens.rotate(b.token); // B is used 9 s after A
    advance(2_000); // 11 s after A was used: outside A's window, inside B's
    expect(await tokens.rotate(a.token)).toEqual({ ok: false, reason: 'reused' });
  });

  it('treats every duplicate as theft when the grace window is 0', async () => {
    const { tokens } = setup({ reuseGraceMs: 0 });
    const issued = await tokens.issue('user-1');
    await tokens.rotate(issued.token);
    expect(await tokens.rotate(issued.token)).toEqual({ ok: false, reason: 'reused' });
  });

  it('keeps detecting reuse after cleanup, as long as the session lives', async () => {
    const { tokens, advance } = setup();
    const issued = await tokens.issue('user-1');
    await tokens.rotate(issued.token);
    advance(40 * DAY); // the used token is past its own idle expiry, the session is not
    await tokens.deleteExpired();
    expect(await tokens.rotate(issued.token)).toEqual({ ok: false, reason: 'reused' });
  });
});

describe('expiry', () => {
  it('expires a token that was not used within the idle TTL', async () => {
    const { tokens, advance } = setup();
    const issued = await tokens.issue('user-1');
    advance(30 * DAY);
    expect(await tokens.rotate(issued.token)).toEqual({ ok: false, reason: 'expired' });
  });

  it('ends the session at its hard maximum, however often it was rotated', async () => {
    const { tokens, advance } = setup();
    let current = (await tokens.issue('user-1')).token;
    for (let day = 10; day <= 80; day += 10) {
      advance(10 * DAY);
      const rotated = await tokens.rotate(current);
      if (!rotated.ok) throw new Error(`rotation failed on day ${day}`);
      current = rotated.token;
      expect(rotated.expiresAtMs).toBeLessThanOrEqual(1_700_000_000_000 + 90 * DAY);
    }
    advance(10 * DAY);
    expect(await tokens.rotate(current)).toEqual({ ok: false, reason: 'expired' });
  });
});

describe('revocation', () => {
  it('logs out a session at once by its token or its id', async () => {
    const { tokens } = setup();
    const a = await tokens.issue('user-1');
    const b = await tokens.issue('user-1');

    expect(await tokens.revoke(a.token)).toBe(true);
    expect(await tokens.rotate(a.token)).toEqual({ ok: false, reason: 'revoked' });
    expect(await tokens.isSessionActive(a.sessionId)).toBe(false);

    await tokens.revokeSession(b.sessionId);
    expect(await tokens.rotate(b.token)).toEqual({ ok: false, reason: 'revoked' });
  });

  it('does not revoke anything for a token with a wrong secret', async () => {
    const { tokens } = setup();
    const { token, sessionId } = await tokens.issue('user-1');
    expect(await tokens.revoke(`${token.split('.')[0]}.forged`)).toBe(false);
    expect(await tokens.isSessionActive(sessionId)).toBe(true);
  });

  it('logs a user out everywhere without touching other users', async () => {
    const { tokens } = setup();
    const phone = await tokens.issue('user-1');
    const laptop = await tokens.issue('user-1');
    const other = await tokens.issue('user-2');

    await tokens.revokeAllForUser('user-1');
    expect(await tokens.isSessionActive(phone.sessionId)).toBe(false);
    expect(await tokens.isSessionActive(laptop.sessionId)).toBe(false);
    expect(await tokens.isSessionActive(other.sessionId)).toBe(true);
  });

  it('knows a session that never existed or has expired is not active', async () => {
    const { tokens, advance } = setup();
    expect(await tokens.isSessionActive('no-such-session')).toBe(false);
    const { sessionId } = await tokens.issue('user-1');
    advance(90 * DAY);
    expect(await tokens.isSessionActive(sessionId)).toBe(false);
  });
});

describe('cleanup', () => {
  it('also deletes revoked sessions, so user ids are not kept for months', async () => {
    const { tokens, store } = setup();
    const gone = await tokens.issue('user-1');
    const live = await tokens.issue('user-2');
    await tokens.revoke(gone.token);

    expect(await tokens.deleteExpired()).toBe(1);
    expect(store.dump().sessions.map((s) => s.id)).toEqual([live.sessionId]);
    expect(await tokens.rotate(gone.token)).toEqual({ ok: false, reason: 'invalid' });
  });

  it('deletes ended sessions and their tokens, and keeps live ones', async () => {
    const { tokens, store, advance } = setup();
    await tokens.issue('user-1');
    advance(91 * DAY);
    const live = await tokens.issue('user-2');

    expect(await tokens.deleteExpired()).toBe(1);
    expect(store.dump().sessions.map((s) => s.id)).toEqual([live.sessionId]);
    expect(store.dump().tokens).toHaveLength(1);
  });
});

describe('failure safety', () => {
  it('leaves the old token valid when the store fails mid-rotation', async () => {
    const { tokens, store } = setup();
    const issued = await tokens.issue('user-1');
    const markUsed = store.markTokenUsed.bind(store);
    let fail = true;
    (store as RefreshTokenStore).markTokenUsed = async (...args) => {
      if (fail) {
        fail = false;
        throw new Error('database went away');
      }
      return markUsed(...args);
    };

    await expect(tokens.rotate(issued.token)).rejects.toThrow('database went away');
    const retried = await tokens.rotate(issued.token);
    expect(retried.ok).toBe(true);
  });
});
