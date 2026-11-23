import { createHash, createHmac, randomBytes, timingSafeEqual } from 'node:crypto';
import type { RefreshTokenStore, SessionRecord, TokenRecord } from './store.js';

const DAY_MS = 24 * 60 * 60 * 1000;
const ID_BYTES = 16; // 22 base64url characters
const SECRET_BYTES = 32; // 43 base64url characters, the size of an HMAC-SHA256 too
const MIN_SERVER_SECRET_LENGTH = 32;
const TOKEN_PATTERN = /^([A-Za-z0-9_-]{22})\.([A-Za-z0-9_-]{43})$/;
// How many rotations a duplicate inside the grace window may follow. A real client
// rotates a handful of times in 10 s at most; a longer chain is treated as reuse.
const MAX_CHAIN_HOPS = 8;

export interface RefreshTokensOptions {
  store: RefreshTokenStore;
  /**
   * A server-side secret of at least 32 characters (e.g. `openssl rand -base64 48`).
   * A rotated token's secret is derived from the one presented with it, so a duplicate
   * inside the grace window can get the same new token without storing any plaintext.
   * Changing it logs out only users whose duplicate refresh arrives inside the grace
   * window at that moment (their duplicate can no longer be matched).
   */
  secret: string;
  /** A token unused this long expires. Default 30 days. */
  idleTtlMs?: number;
  /** A session ends this long after login, however often it rotates. Default 90 days. */
  maxSessionMs?: number;
  /**
   * How long after a token was used a duplicate counts as a race (it gets the same new
   * token) rather than theft (the session is revoked). Default 10 seconds; 0 disables it.
   */
  reuseGraceMs?: number;
  /** The current time in ms; for tests. */
  now?: () => number;
}

export interface IssuedToken {
  /** Give this to the client. Never log it. */
  token: string;
  /** Put this in your access tokens (e.g. as `sid`) and check it with `isSessionActive`. */
  sessionId: string;
  userId: string;
  expiresAtMs: number;
}

/**
 * Why a rotation failed. For your logs only: answer every failure with the same 401,
 * since telling `reused` from `revoked` helps an attacker.
 */
export type RotationFailure = 'invalid' | 'expired' | 'revoked' | 'reused';

export type RotationResult = ({ ok: true } & IssuedToken) | { ok: false; reason: RotationFailure };

export interface RefreshTokens {
  /** Start a session at login and return its first refresh token. */
  issue(userId: string): Promise<IssuedToken>;
  /** Exchange a refresh token for a new one. */
  rotate(token: string): Promise<RotationResult>;
  /**
   * Log out the session a token belongs to. Any token of the session works, also a
   * retired or expired one. False when the token is not one of ours.
   */
  revoke(token: string): Promise<boolean>;
  revokeSession(sessionId: string): Promise<void>;
  /** Log a user out everywhere, e.g. after a password change. */
  revokeAllForUser(userId: string): Promise<void>;
  /**
   * Whether a session exists, is not revoked and has not reached its hard end. Meant for
   * the `sid` of short-lived access tokens; it doesn't look at a refresh token's idle TTL.
   */
  isSessionActive(sessionId: string): Promise<boolean>;
  /** Delete ended and revoked sessions and their tokens. Returns how many sessions were deleted. */
  deleteExpired(): Promise<number>;
}

const base64url = (bytes: Buffer): string => bytes.toString('base64url');
const randomId = (): string => base64url(randomBytes(ID_BYTES));
const sha256 = (value: string): string => createHash('sha256').update(value).digest('hex');

function sameHash(a: string, b: string): boolean {
  const left = Buffer.from(a, 'hex');
  const right = Buffer.from(b, 'hex');
  return left.length === right.length && timingSafeEqual(left, right);
}

function assertValidOptions(options: RefreshTokensOptions, idleTtlMs: number, maxSessionMs: number, graceMs: number) {
  if (typeof options.secret !== 'string' || options.secret.length < MIN_SERVER_SECRET_LENGTH) {
    throw new Error(`refresh-token-rotation: \`secret\` must be at least ${MIN_SERVER_SECRET_LENGTH} characters`);
  }
  if (!(Number.isFinite(idleTtlMs) && idleTtlMs > 0)) {
    throw new Error('refresh-token-rotation: `idleTtlMs` must be a positive number');
  }
  if (!(Number.isFinite(maxSessionMs) && maxSessionMs >= idleTtlMs)) {
    throw new Error('refresh-token-rotation: `maxSessionMs` must be at least `idleTtlMs`');
  }
  if (!(Number.isFinite(graceMs) && graceMs >= 0)) {
    throw new Error('refresh-token-rotation: `reuseGraceMs` must be 0 or more');
  }
}

/**
 * Refresh-token rotation with reuse detection (OAuth 2.0 Security BCP, RFC 9700):
 * every refresh returns a new token and retires the old one; a retired token that comes
 * back after the grace window means it was copied, so the whole session is revoked.
 */
export function createRefreshTokens(options: RefreshTokensOptions): RefreshTokens {
  const { store } = options;
  const idleTtlMs = options.idleTtlMs ?? 30 * DAY_MS;
  const maxSessionMs = options.maxSessionMs ?? 90 * DAY_MS;
  const reuseGraceMs = options.reuseGraceMs ?? 10_000;
  const now = options.now ?? Date.now;
  assertValidOptions(options, idleTtlMs, maxSessionMs, reuseGraceMs);

  const successorSecret = (secret: string): string =>
    base64url(createHmac('sha256', options.secret).update(secret).digest());

  const newToken = (session: SessionRecord, secret: string, atMs: number): TokenRecord => ({
    id: randomId(),
    sessionId: session.id,
    secretHash: sha256(secret),
    issuedAtMs: atMs,
    expiresAtMs: Math.min(atMs + idleTtlMs, session.expiresAtMs),
    usedAtMs: null,
    replacedBy: null,
  });

  const success = (token: TokenRecord, secret: string, session: SessionRecord): RotationResult => ({
    ok: true,
    token: `${token.id}.${secret}`,
    sessionId: session.id,
    userId: session.userId,
    expiresAtMs: token.expiresAtMs,
  });

  /** The token and its session, or null when the token is not one of ours. */
  async function load(token: string) {
    const match = TOKEN_PATTERN.exec(token);
    if (!match) {
      return null;
    }
    const [, id, secret] = match as unknown as [string, string, string];
    const record = await store.findToken(id);
    if (!record || !sameHash(sha256(secret), record.secretHash)) {
      return null;
    }
    const session = await store.findSession(record.sessionId);
    return session ? { secret, record, session } : null;
  }

  /**
   * A used token came back: a race inside the grace window, or theft after it.
   * Inside the window, follow the chain of successors to the newest unused one, so a
   * slow tab doesn't get a token that was retired meanwhile. The window is measured from
   * the presented token's use only, so walking the chain can't stretch it.
   */
  async function afterUse(secret: string, record: TokenRecord, session: SessionRecord, atMs: number) {
    const usedAtMs = record.usedAtMs ?? atMs;
    if (atMs - usedAtMs < reuseGraceMs) {
      let current = record;
      let currentSecret = secret;
      for (let hop = 0; hop < MAX_CHAIN_HOPS && current.replacedBy; hop += 1) {
        const next = await store.findToken(current.replacedBy);
        const nextSecret = successorSecret(currentSecret);
        if (!next || !sameHash(sha256(nextSecret), next.secretHash)) {
          break;
        }
        if (next.usedAtMs === null) {
          return success(next, nextSecret, session);
        }
        current = next;
        currentSecret = nextSecret;
      }
    }
    await store.revokeSession(session.id, atMs);
    return { ok: false, reason: 'reused' } as const;
  }

  return {
    async issue(userId) {
      if (typeof userId !== 'string' || userId === '') {
        throw new Error('refresh-token-rotation: `userId` must be a non-empty string');
      }
      const atMs = now();
      const session: SessionRecord = {
        id: randomId(),
        userId,
        createdAtMs: atMs,
        expiresAtMs: atMs + maxSessionMs,
        revokedAtMs: null,
      };
      const secret = base64url(randomBytes(SECRET_BYTES));
      const token = newToken(session, secret, atMs);
      await store.insertSession(session);
      await store.insertToken(token);
      const { ok: _ok, ...issued } = success(token, secret, session) as { ok: true } & IssuedToken;
      return issued;
    },

    async rotate(token) {
      const found = await load(token);
      if (!found) {
        return { ok: false, reason: 'invalid' };
      }
      const { secret, record, session } = found;
      const atMs = now();
      if (session.revokedAtMs !== null) {
        return { ok: false, reason: 'revoked' };
      }
      if (atMs >= session.expiresAtMs) {
        return { ok: false, reason: 'expired' };
      }
      if (record.usedAtMs !== null) {
        return afterUse(secret, record, session, atMs);
      }
      if (atMs >= record.expiresAtMs) {
        return { ok: false, reason: 'expired' };
      }

      // Insert the successor first, then retire the old token. A crash in between leaves
      // the old token as the only usable one; the successor's id never left the server.
      const nextSecret = successorSecret(secret);
      const next = newToken(session, nextSecret, atMs);
      await store.insertToken(next);
      if (await store.markTokenUsed(record.id, atMs, next.id)) {
        return success(next, nextSecret, session);
      }
      // A parallel refresh won the race: answer like a duplicate inside the grace window.
      const latest = await store.findToken(record.id);
      return latest ? afterUse(secret, latest, session, atMs) : { ok: false, reason: 'invalid' };
    },

    async revoke(token) {
      const found = await load(token);
      if (!found) {
        return false;
      }
      await store.revokeSession(found.session.id, now());
      return true;
    },

    async revokeSession(sessionId) {
      await store.revokeSession(sessionId, now());
    },

    async revokeAllForUser(userId) {
      await store.revokeUserSessions(userId, now());
    },

    async isSessionActive(sessionId) {
      const session = await store.findSession(sessionId);
      return !!session && session.revokedAtMs === null && now() < session.expiresAtMs;
    },

    async deleteExpired() {
      return store.deleteExpiredSessions(now());
    },
  };
}
