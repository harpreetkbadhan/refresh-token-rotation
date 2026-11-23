import assert from 'node:assert/strict';
import type { RefreshTokenStore, SessionRecord, TokenRecord } from './store.js';

const PARALLEL_MARKS = 10;

async function rejectsDuplicate(write: Promise<void>, method: string): Promise<void> {
  let rejected = false;
  try {
    await write;
  } catch {
    rejected = true;
  }
  assert.ok(rejected, `${method} must reject a duplicate id`);
}

const session = (id: string, userId: string, expiresAtMs: number): SessionRecord => ({
  id,
  userId,
  createdAtMs: 1_000,
  expiresAtMs,
  revokedAtMs: null,
});

const token = (id: string, sessionId: string): TokenRecord => ({
  id,
  sessionId,
  secretHash: 'ab'.repeat(32),
  issuedAtMs: 1_000,
  expiresAtMs: 3_000,
  usedAtMs: null,
  replacedBy: null,
});

/**
 * Checks a `RefreshTokenStore` implementation against the contract the rotation logic
 * relies on. Call it from your own test with a factory that returns an empty store
 * (e.g. on a fresh test database). Resolves when everything holds, throws an
 * `AssertionError` naming the broken rule otherwise.
 */
export async function checkStoreContract(
  createStore: () => RefreshTokenStore | Promise<RefreshTokenStore>,
): Promise<void> {
  const store = await createStore();

  const s1 = session('s1', 'u1', 5_000);
  await store.insertSession(s1);
  assert.deepEqual(await store.findSession('s1'), s1, 'findSession must return what insertSession stored');
  assert.equal(await store.findSession('missing'), null, 'findSession must return null for an unknown id');
  await rejectsDuplicate(store.insertSession(s1), 'insertSession');

  const t1 = token('t1', 's1');
  await store.insertToken(t1);
  assert.deepEqual(await store.findToken('t1'), t1, 'findToken must return what insertToken stored');
  assert.equal(await store.findToken('missing'), null, 'findToken must return null for an unknown id');
  await rejectsDuplicate(store.insertToken(t1), 'insertToken');

  const marks = await Promise.all(
    Array.from({ length: PARALLEL_MARKS }, (_, i) => store.markTokenUsed('t1', 2_000 + i, `next-${i}`)),
  );
  const winners = marks.filter(Boolean).length;
  assert.equal(
    winners,
    1,
    `markTokenUsed must let exactly one of ${PARALLEL_MARKS} parallel calls win, got ${winners}: use one conditional write, not a read followed by a write`,
  );
  const winner = marks.indexOf(true);
  const used = await store.findToken('t1');
  assert.equal(used?.usedAtMs, 2_000 + winner, 'markTokenUsed must store usedAtMs of the winning call');
  assert.equal(used?.replacedBy, `next-${winner}`, 'markTokenUsed must store replacedBy of the winning call');
  assert.equal(await store.markTokenUsed('t1', 9_000, 'late'), false, 'markTokenUsed must refuse a used token');
  assert.equal(await store.markTokenUsed('missing', 9_000, 'x'), false, 'markTokenUsed must refuse an unknown id');

  await store.revokeSession('s1', 2_500);
  await store.revokeSession('s1', 2_600);
  assert.equal((await store.findSession('s1'))?.revokedAtMs, 2_500, 'revokeSession must not overwrite an earlier revocation');

  await store.insertSession(session('s2', 'u1', 5_000));
  await store.insertSession(session('s3', 'u2', 5_000));
  await store.insertSession(session('s4', 'u2', 10_000));
  await store.insertToken(token('t4', 's4'));
  await store.revokeUserSessions('u1', 2_700);
  assert.equal((await store.findSession('s2'))?.revokedAtMs, 2_700, 'revokeUserSessions must revoke every session of the user');
  assert.equal((await store.findSession('s1'))?.revokedAtMs, 2_500, 'revokeUserSessions must not overwrite an earlier revocation');
  assert.equal((await store.findSession('s3'))?.revokedAtMs, null, 'revokeUserSessions must not touch other users');

  // At 6_000: s1, s2 (revoked) and s3 (ended) go; s4 is live.
  assert.equal(await store.deleteExpiredSessions(6_000), 3, 'deleteExpiredSessions must return how many sessions it deleted');
  assert.equal(await store.findSession('s3'), null, 'deleteExpiredSessions must delete ended sessions');
  assert.equal(await store.findSession('s2'), null, 'deleteExpiredSessions must delete revoked sessions');
  assert.equal(await store.findToken('t1'), null, 'deleteExpiredSessions must delete the tokens of deleted sessions');
  assert.ok(await store.findSession('s4'), 'deleteExpiredSessions must keep live sessions');
  assert.ok(await store.findToken('t4'), 'deleteExpiredSessions must keep the tokens of live sessions');
}
