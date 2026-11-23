# refresh-token-rotation

Refresh-token rotation with reuse detection for Node.js, and a fetch client that refreshes once for many parallel 401s.

Refresh tokens are the keys to your users' accounts. Most apps get at least one of these wrong:

- **A stolen token keeps working**, because nothing notices that it's used twice.
- **Parallel refreshes** (two tabs, app start plus a background fetch) race each other and log the user out.
- **Sessions never end:** sliding expiry renews forever, and logout doesn't stop other copies.
- **Tokens are stored in plain text** in the database.

This package rotates the refresh token on every use, following the [OAuth 2.0 Security Best Current Practice (RFC 9700)](https://www.rfc-editor.org/rfc/rfc9700):

- Every refresh returns a **new token** and retires the old one.
- A retired token that comes back means it was copied, so **the whole session is revoked**: the thief and the real user are both logged out, and the user logs in again.
- A duplicate within a short **grace window** (default 10 s) is a race, not theft. It gets **the same new token**, so parallel refreshes never log anyone out.
- Sessions have an **idle timeout** and a **hard maximum lifetime**. Logout takes effect **at once**.
- The database stores only **SHA-256 hashes**, compared in constant time.

Zero runtime dependencies. ESM, usable from CommonJS on Node ≥ 20.19. It handles refresh tokens only: keep issuing short-lived access tokens (for example JWTs) with your existing library.

```sh
npm install refresh-token-rotation
```

## Server

```ts
import { createRefreshTokens } from 'refresh-token-rotation';

const refreshTokens = createRefreshTokens({
  store: myStore,                              // your database, see "Store" below
  secret: process.env.REFRESH_TOKEN_SECRET!,   // ≥ 32 characters, e.g. `openssl rand -base64 48`
  // idleTtlMs: 30 days, maxSessionMs: 90 days, reuseGraceMs: 10 s (defaults)
});

// Login
const { token, sessionId } = await refreshTokens.issue(user.id);
// → send `token` to the client; put `sessionId` into the access token as `sid`

// POST /auth/refresh
const result = await refreshTokens.rotate(req.body.refreshToken);
if (!result.ok) {
  log.warn({ reason: result.reason }, 'refresh refused'); // 'invalid' | 'expired' | 'revoked' | 'reused'
  return res.status(401).json({ error: 'unauthorized' });  // the same answer for every reason
}
const accessToken = signAccessToken({ sub: result.userId, sid: result.sessionId });
res.json({ accessToken, refreshToken: result.token });

// Logout, and "log out everywhere"
await refreshTokens.revoke(refreshToken);
await refreshTokens.revokeAllForUser(user.id); // e.g. after a password change
```

**Answer every failed refresh with the same 401.** The reason is for your logs. Telling a client that its token was `reused` rather than `revoked` helps an attacker.

**Make logout instant for access tokens too.** A revoked session's access tokens stay valid until they expire. To end them at once, put the `sessionId` in the access token (`sid`) and check it on requests that matter:

```ts
if (!(await refreshTokens.isSessionActive(claims.sid))) throw new UnauthorizedException();
```

Run `refreshTokens.deleteExpired()` from a daily job to remove ended sessions.

## Client (React Native, browser, Node)

```ts
import { createAuthFetch } from 'refresh-token-rotation/client';

export const authFetch = createAuthFetch({
  getAccessToken: () => tokenStore.accessToken,
  refresh: async () => {
    // Use the plain fetch here, never authFetch.
    const res = await fetch(`${API}/auth/refresh`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ refreshToken: await tokenStore.getRefreshToken() }),
    });
    if (!res.ok) return false;
    await tokenStore.save(await res.json());
    return true;
  },
  onSessionExpired: () => navigation.navigate('Login'),
});

const res = await authFetch(`${API}/me`);
```

- When many requests get a 401 at the same time, **one** refresh runs and the others wait for it. Each request is then retried once.
- A request whose 401 arrives after another request already refreshed is retried with the new token, without refreshing again.
- A retry that still gets a 401 is returned as is, so there's no refresh loop.
- `refresh` resolving `false` means the server rejected the session: `onSessionExpired` is called once and the 401 is returned.
- `refresh` **throwing** (offline, timeout, 5xx) means a temporary problem: the error reaches the callers, as `fetch`'s own network errors do, and the user stays logged in.

**Browser tabs** don't share memory, so each tab has its own single-flight. That's harmless: a second tab refreshing with the same token within the grace window gets the same new token, as long as all tabs keep their tokens in the same storage.

## Store

You provide the storage with a small interface. `createMemoryStore()` is included for tests and demos only.

**Check your store against the contract.** It catches the mistakes that silently break reuse detection:

```ts
import { checkStoreContract } from 'refresh-token-rotation/testing';

test('my store keeps the contract', async () => {
  await checkStoreContract(() => createMongoStore(freshTestDb())); // throws, naming the broken rule
});
```

The rules:
- **Read your own writes.** Read from the primary, never from a lagging replica. A stale read makes a used token look unused.
- **`markTokenUsed` is a single conditional write**, never a read followed by a write.
- **Writes are durable when the promise resolves.**
- **Ids are unique.** Inserting an existing id rejects.

| Method | What it must do |
|---|---|
| `insertSession`, `findSession` | Store and load a session `{ id, userId, createdAtMs, expiresAtMs, revokedAtMs }`. |
| `revokeSession(id, at)`, `revokeUserSessions(userId, at)` | Set `revokedAtMs` where it is still null. |
| `insertToken`, `findToken` | Store and load a token `{ id, sessionId, secretHash, issuedAtMs, expiresAtMs, usedAtMs, replacedBy }`. |
| `markTokenUsed(id, usedAt, replacedBy)` | **Atomically** set `usedAtMs` and `replacedBy` only while `usedAtMs` is null. Return `true` if this call changed the row. **This is what makes only one parallel refresh win.** Never read, then write. |
| `deleteExpiredSessions(now)` | Delete sessions that ended (`expiresAtMs <= now`) or were revoked, and their tokens. |

**Keep used tokens until their session is deleted.** If you delete a token when it's used, a stolen copy that comes back later looks merely invalid instead of reused, and the theft goes unnoticed.

MongoDB:

```ts
async markTokenUsed(id, usedAtMs, replacedBy) {
  const result = await tokens.updateOne({ _id: id, usedAtMs: null }, { $set: { usedAtMs, replacedBy } });
  return result.modifiedCount === 1;
}
```

SQL:

```sql
UPDATE refresh_tokens SET used_at_ms = $2, replaced_by = $3
WHERE id = $1 AND used_at_ms IS NULL;   -- succeeded when exactly 1 row was updated
```

Index `tokens.sessionId`, `sessions.userId` and `sessions.expiresAtMs`.

## Options

| Option | Default | |
|---|---|---|
| `store` | required | Your `RefreshTokenStore`. |
| `secret` | required | At least 32 characters. Used to derive a rotated token's secret from the presented one, so a duplicate within the grace window can get the same new token without storing plaintext. Changing it logs out only users whose duplicate refresh arrives within the grace window at that moment. |
| `idleTtlMs` | 30 days | A token unused this long expires. |
| `maxSessionMs` | 90 days | A session ends this long after login, however often it rotates. |
| `reuseGraceMs` | 10 s | How long a duplicate counts as a race and gets the same new token. After that it counts as theft. `0` treats every duplicate as theft. |
| `now` | `Date.now` | The clock, for tests. |

## How it works

- A token is `<id>.<secret>`: 128 random bits of id and 256 bits of secret. Only `sha256(secret)` is stored.
- To rotate, the server checks the token's hash and its session (revoked? ended?), then inserts the successor and marks the old token used with the atomic `markTokenUsed`. If the process crashes between those two steps, the old token stays the only usable one, because the successor's id never left the server.
- The successor's secret is `HMAC-SHA256(secret, presentedSecret)`. A duplicate within the grace window can therefore be given the same successor, recomputed from what it presented.
- Revocation is a flag on the session, so tokens issued during a concurrent logout are dead too.
- A duplicate within the grace window gets the **newest** unused token of the chain, not a token that was retired meanwhile. The window is measured from when the presented token was used, so following the chain can't stretch it.

## The grace-window trade-off

RFC 9700 asks for reuse detection. It doesn't prescribe a grace window. The window is a trade-off you should know about:

- **With it (default 10 s):** parallel refreshes never log a user out. But a thief who uses a stolen token within 10 seconds of the real user, before or after, gets the same new token, and detection only fires on a duplicate after the window.
- **With `reuseGraceMs: 0`:** every duplicate is treated as theft. Pair it with a client that never refreshes twice, such as `createAuthFetch` in a single-tab app.

Okta, for example, makes its grace period configurable for the same reason.

`isSessionActive` checks revocation and the hard session end. It doesn't look at a refresh token's idle TTL, because it's meant for short-lived access tokens.

## License

MIT
