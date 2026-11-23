import { describe, expect, it } from 'vitest';
import { createMemoryStore, type RefreshTokenStore } from '../src/index.js';
import { checkStoreContract } from '../src/testing.js';

describe('checkStoreContract', () => {
  it('passes for the memory store', async () => {
    await expect(checkStoreContract(createMemoryStore)).resolves.toBeUndefined();
  });

  it('catches a store whose markTokenUsed reads and then writes', async () => {
    const broken = (): RefreshTokenStore => {
      const store = createMemoryStore();
      return {
        ...store,
        async markTokenUsed(id, usedAtMs, replacedBy) {
          const token = await store.findToken(id);
          await new Promise((resolve) => setTimeout(resolve, 1)); // the gap a real database has
          if (!token || token.usedAtMs !== null) return false;
          return store.markTokenUsed(id, usedAtMs, replacedBy).then(() => true);
        },
      };
    };
    await expect(checkStoreContract(broken)).rejects.toThrow(/markTokenUsed/);
  });

  it('catches a store that accepts duplicate ids', async () => {
    const lax = (): RefreshTokenStore => {
      const store = createMemoryStore();
      return {
        ...store,
        async insertToken(token) {
          await store.deleteExpiredSessions(Number.NEGATIVE_INFINITY);
          try {
            await store.insertToken(token);
          } catch {
            // swallow the duplicate error: the bug under test
          }
        },
      };
    };
    await expect(checkStoreContract(lax)).rejects.toThrow(/duplicate/);
  });
});
