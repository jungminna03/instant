// EPL fork: password-only dashboard login.
//
// Each password maps to a "workspace" — an ordinary dashboard account whose
// long-lived master token is kept only on the dashboard server. On a match we
// mint a *fresh* token for that account through the CLI ticket flow
// (register -> claim -> check), so signing out in the dashboard revokes only
// that browser's token, never the master.
//
// Workspaces file (PASSWORD_WORKSPACES_FILE), JSON array:
//   [{ "name": "EmotivePlayLab",
//      "passwordHash": "scrypt$16384$8$1$<salt b64>$<hash b64>",
//      "masterToken": "<refresh token uuid>" }]
// Managed by self-hosting/epl/add-workspace.sh on the server.

import { readFile } from 'node:fs/promises';
import { scrypt, timingSafeEqual, type ScryptOptions } from 'node:crypto';

type Workspace = { name: string; passwordHash: string; masterToken: string };

export type PasswordLoginResult = {
  token: string;
  user: { id: string; email: string; created_at: string };
  workspace: string;
};

export class PasswordLoginError extends Error {
  constructor(
    public status: number,
    public type: 'disabled' | 'invalid-password' | 'rate-limited' | 'upstream',
    message: string,
  ) {
    super(message);
  }
}

function scryptAsync(
  password: string,
  salt: Uint8Array,
  keylen: number,
  opts: ScryptOptions,
): Promise<Buffer> {
  return new Promise((resolve, reject) =>
    scrypt(password, salt, keylen, opts, (err, key) =>
      err ? reject(err) : resolve(key),
    ),
  );
}

async function verifyPassword(password: string, encoded: string) {
  const [alg, n, r, p, saltB64, hashB64] = encoded.split('$');
  if (alg !== 'scrypt' || !saltB64 || !hashB64) return false;
  const expected = Buffer.from(hashB64, 'base64');
  const actual = await scryptAsync(
    password,
    new Uint8Array(Buffer.from(saltB64, 'base64')),
    expected.length,
    { N: Number(n), r: Number(r), p: Number(p), maxmem: 64 * 1024 * 1024 },
  );
  return timingSafeEqual(new Uint8Array(actual), new Uint8Array(expected));
}

async function loadWorkspaces(): Promise<Workspace[]> {
  const file = process.env.PASSWORD_WORKSPACES_FILE;
  if (!file) return [];
  try {
    const parsed = JSON.parse(await readFile(file, 'utf8'));
    return Array.isArray(parsed) ? parsed : [];
  } catch (e) {
    console.error('[password-login] cannot read workspaces file', e);
    return [];
  }
}

// ---------------
// Rate limiting (in-memory; one dashboard container)

const WINDOW_MS = 10 * 60 * 1000;
const PER_CLIENT_LIMIT = 10;
const GLOBAL_LIMIT = 100;
const attempts = new Map<string, { count: number; resetAt: number }>();

function hit(key: string, limit: number) {
  const now = Date.now();
  const cur = attempts.get(key);
  if (!cur || cur.resetAt <= now) {
    attempts.set(key, { count: 1, resetAt: now + WINDOW_MS });
    return true;
  }
  cur.count += 1;
  return cur.count <= limit;
}

function checkRateLimit(clientKey: string) {
  // Both counters advance on every attempt; failing either blocks.
  const clientOk = hit(`client:${clientKey}`, PER_CLIENT_LIMIT);
  const globalOk = hit('global', GLOBAL_LIMIT);
  if (!clientOk || !globalOk) {
    throw new PasswordLoginError(
      429,
      'rate-limited',
      'Too many attempts. Try again in a few minutes.',
    );
  }
}

// ---------------
// Token minting via the CLI ticket flow

function backendURI() {
  const uri =
    process.env.INSTANT_INTERNAL_API_URI ||
    process.env.INSTANT_API_URI ||
    process.env.INSTANT_BACKEND_URL;
  if (!uri) throw new PasswordLoginError(500, 'upstream', 'No backend URI');
  return uri.replace(/\/$/, '');
}

async function backend(path: string, init: RequestInit & { token?: string }) {
  const { token, ...rest } = init;
  const res = await fetch(`${backendURI()}${path}`, {
    ...rest,
    headers: {
      'content-type': 'application/json',
      ...(token ? { authorization: `Bearer ${token}` } : {}),
    },
    cache: 'no-store',
  });
  if (!res.ok) {
    const body = await res.text();
    console.error(`[password-login] ${path} -> ${res.status} ${body}`);
    throw new PasswordLoginError(502, 'upstream', 'Login backend error');
  }
  return res.json();
}

async function mintToken(masterToken: string) {
  const { secret, ticket } = await backend('/dash/cli/auth/register', {
    method: 'POST',
    body: '{}',
  });
  await backend('/dash/cli/auth/claim', {
    method: 'POST',
    token: masterToken,
    body: JSON.stringify({ ticket }),
  });
  const { token } = await backend('/dash/cli/auth/check', {
    method: 'POST',
    body: JSON.stringify({ secret }),
  });
  const { user } = await backend('/dash/me', { method: 'GET', token });
  return { token: token as string, user };
}

export async function passwordLogin(
  password: string,
  clientKey: string,
): Promise<PasswordLoginResult> {
  const workspaces = await loadWorkspaces();
  if (!workspaces.length) {
    throw new PasswordLoginError(404, 'disabled', 'Password login is off');
  }
  checkRateLimit(clientKey);

  // Check every entry so timing doesn't reveal which workspace matched.
  let match: Workspace | undefined;
  for (const ws of workspaces) {
    if ((await verifyPassword(password, ws.passwordHash)) && !match) {
      match = ws;
    }
  }
  if (!match) {
    throw new PasswordLoginError(401, 'invalid-password', 'Wrong password');
  }

  const { token, user } = await mintToken(match.masterToken);
  return { token, user, workspace: match.name };
}
