import type { RefreshTokenStore, SessionRecord, TokenRecord } from './store.js';

export interface MemoryStore extends RefreshTokenStore {
  /** Copies of everything stored; for tests. */
  dump(): { sessions: SessionRecord[]; tokens: TokenRecord[] };
}

/**
 * An in-memory store for tests and demos. Not for production: it lives in one process
 * and forgets everything on restart. Records are copied in and out, so callers can't
 * change stored state by accident.
 */
export function createMemoryStore(): MemoryStore {
  const sessions = new Map<string, SessionRecord>();
  const tokens = new Map<string, TokenRecord>();

  const copy = <T extends object>(record: T | undefined): T | null => (record ? { ...record } : null);

  return {
    async insertSession(session) {
      if (sessions.has(session.id)) {
        throw new Error(`duplicate session id ${session.id}`);
      }
      sessions.set(session.id, { ...session });
    },
    async findSession(id) {
      return copy(sessions.get(id));
    },
    async revokeSession(id, atMs) {
      const session = sessions.get(id);
      if (session && session.revokedAtMs === null) {
        sessions.set(id, { ...session, revokedAtMs: atMs });
      }
    },
    async revokeUserSessions(userId, atMs) {
      for (const session of sessions.values()) {
        if (session.userId === userId && session.revokedAtMs === null) {
          sessions.set(session.id, { ...session, revokedAtMs: atMs });
        }
      }
    },
    async insertToken(token) {
      if (tokens.has(token.id)) {
        throw new Error(`duplicate token id ${token.id}`);
      }
      tokens.set(token.id, { ...token });
    },
    async findToken(id) {
      return copy(tokens.get(id));
    },
    async markTokenUsed(id, usedAtMs, replacedBy) {
      // Check and set run without an await in between, so this is atomic in one process.
      const token = tokens.get(id);
      if (!token || token.usedAtMs !== null) {
        return false;
      }
      tokens.set(id, { ...token, usedAtMs, replacedBy });
      return true;
    },
    async deleteExpiredSessions(nowMs) {
      const ended = [...sessions.values()].filter(
        (session) => session.expiresAtMs <= nowMs || session.revokedAtMs !== null,
      );
      const endedIds = new Set(ended.map((session) => session.id));
      for (const id of endedIds) {
        sessions.delete(id);
      }
      for (const token of [...tokens.values()]) {
        if (endedIds.has(token.sessionId)) {
          tokens.delete(token.id);
        }
      }
      return ended.length;
    },
    dump() {
      return {
        sessions: [...sessions.values()].map((session) => ({ ...session })),
        tokens: [...tokens.values()].map((token) => ({ ...token })),
      };
    },
  };
}
