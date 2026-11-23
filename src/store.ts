/** A login session: every token rotated from one login belongs to it. */
export interface SessionRecord {
  id: string;
  userId: string;
  createdAtMs: number;
  /** Hard end of the session, however often its tokens are rotated. */
  expiresAtMs: number;
  revokedAtMs: number | null;
}

/** One refresh token. Only a SHA-256 hash of its secret is stored. */
export interface TokenRecord {
  id: string;
  sessionId: string;
  /** Hex SHA-256 of the token's secret part. */
  secretHash: string;
  issuedAtMs: number;
  /** Idle expiry: the token must be used before this. Never after the session's end. */
  expiresAtMs: number;
  usedAtMs: number | null;
  /** The token this one was rotated into. */
  replacedBy: string | null;
}

/**
 * Where sessions and tokens live: your database. Run `checkStoreContract` from
 * `refresh-token-rotation/testing` against your implementation. The contract:
 *
 * - Read your own writes: `findToken`/`findSession` must see every earlier write, so
 *   read from the primary, never from a lagging replica. A stale read makes a used token
 *   look unused and defeats reuse detection.
 * - `markTokenUsed` is one conditional write (`UPDATE … WHERE id = ? AND used_at IS NULL`,
 *   `updateOne({ _id, usedAtMs: null })`), never a read followed by a write.
 * - Writes are durable when their promise resolves: the successor inserted by
 *   `insertToken` must exist before `markTokenUsed` runs.
 * - Ids are unique: inserting an existing session or token id rejects.
 * - Keep used tokens until their session is deleted, or a stolen token that comes back
 *   later can't be recognised as reused.
 */
export interface RefreshTokenStore {
  insertSession(session: SessionRecord): Promise<void>;
  findSession(id: string): Promise<SessionRecord | null>;
  /** Set `revokedAtMs` if the session is not revoked yet. */
  revokeSession(id: string, atMs: number): Promise<void>;
  /** Revoke every session of the user that is not revoked yet. */
  revokeUserSessions(userId: string, atMs: number): Promise<void>;

  insertToken(token: TokenRecord): Promise<void>;
  findToken(id: string): Promise<TokenRecord | null>;
  /**
   * Atomically set `usedAtMs` and `replacedBy`, but only while `usedAtMs` is null
   * (a conditional update). Return true when this call made the change, false when the
   * token was already used. This is what lets only one of two parallel refreshes win.
   */
  markTokenUsed(id: string, usedAtMs: number, replacedBy: string): Promise<boolean>;

  /**
   * Delete sessions that ended (`expiresAtMs <= nowMs`) or were revoked, and all their
   * tokens. Returns how many sessions were deleted.
   */
  deleteExpiredSessions(nowMs: number): Promise<number>;
}
