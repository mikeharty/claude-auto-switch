import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fetchTokenOwner, verifyAccountIdentities } from './identity-check.js';
import {
  credentialFingerprint,
  credentialPath,
  installCredential,
  rollbackCredential,
} from './credential-vault.js';
import { hasLogin } from './account-login.js';
import { settleNewLogin } from '../login/settle-login.js';
import { loginAccount } from '../login/login.js';
import { addAccount, getAccount } from './registry.js';
import { loadConfig } from '../config/config.js';
import type { CliContext } from '../context.js';
import { refreshCredentialIfExpired } from '../usage/oauth-refresh.js';
import { readOauthToken } from '../usage/limit-probe.js';
import {
  readKeychainCredential,
  writeKeychainCredential,
  deleteKeychainCredential,
} from './keychain.js';
import { readCredential, writeCredential, removeCredential } from './credential-storage.js';
import { renameAccount } from './rename.js';
import { removeSessionDir } from '../session/session-dir.js';
import { removeCommand } from '../commands/remove.js';
import { propagateRenewal } from './shared-login.js';

const keychain = vi.hoisted(() => new Map<string, string>());
vi.mock('./keychain.js', () => ({
  readKeychainCredential: vi.fn((dir: string) => keychain.get(dir) ?? null),
  writeKeychainCredential: vi.fn((dir: string, text: string) => {
    keychain.set(dir, text);
  }),
  deleteKeychainCredential: vi.fn((dir: string) => {
    keychain.delete(dir);
  }),
}));

const credential = (token: string, expiresAt = Date.now() + 3600000): string =>
  JSON.stringify({
    claudeAiOauth: { accessToken: token, refreshToken: `refresh-${token}`, expiresAt },
  });

let home: string;
let dir: string;
let context: CliContext;
let lines: string[];
beforeEach(() => {
  vi.clearAllMocks();
  keychain.clear();
  home = mkdtempSync(path.join(tmpdir(), 'ccx-keychain-'));
  dir = path.join(home, 'profile');
  lines = [];
  const ctx = { env: { HOME: home, USERPROFILE: home, CLAUDE_AUTO_SWITCH_HOME: home } };
  context = {
    ctx,
    config: loadConfig(ctx),
    out: (line) => lines.push(line),
    json: false,
    quiet: false,
  };
  addAccount({ name: 'work', dir }, ctx);
  keychain.set(dir, credential('work-token'));
});
afterEach(() => {
  rmSync(home, { recursive: true, force: true });
});

const api = vi.fn(async (_url: unknown, init?: RequestInit) => {
  const token = new Headers(init?.headers).get('authorization');
  return token === 'Bearer work-token'
    ? new Response(JSON.stringify({ account: { email_address: 'work@example.com' } }))
    : new Response('{}', { status: 401 });
});

describe('Keychain-only profiles', () => {
  it('confirms the token owner and records the account after login without exporting credentials', async () => {
    expect(existsSync(credentialPath(dir))).toBe(false);
    const result = await settleNewLogin(
      context,
      { name: 'work', dir },
      {
        lookupOwner: (profile) => fetchTokenOwner(profile, api),
      },
    );
    expect(result).toEqual({ ok: true, owner: 'work@example.com' });
    expect(getAccount('work', context.ctx)?.email).toBe('work@example.com');
    expect(lines.join('\n')).not.toContain('offline');
    expect(existsSync(credentialPath(dir))).toBe(false);
    expect(await verifyAccountIdentities([{ name: 'work', dir }], api)).toMatchObject([
      { kind: 'ok', actual: 'work@example.com' },
    ]);
  });

  it('recognizes a usable login and notices a new login stored only in Keychain', async () => {
    expect(hasLogin(dir)).toBe(true);
    const before = credentialFingerprint(dir);
    expect(before).not.toBeNull();
    const result = await loginAccount(
      { name: 'work', dir },
      {
        claude: { bin: 'fake-claude', prefixArgs: [] },
        startAuthLogin: () => ({
          urlHint: async () => undefined,
          done: async () => {
            keychain.set(dir, credential('new-token'));
            return 0;
          },
        }),
        browser: { authorize: async () => 'authorized' },
        debugPort: 9222,
      },
    );
    expect(result.ok).toBe(true);
    expect(credentialFingerprint(dir)).not.toBe(before);
  });

  it('takes the initial fingerprint before starting a fast login process', async () => {
    const result = await loginAccount(
      { name: 'work', dir },
      {
        claude: { bin: 'fake-claude', prefixArgs: [] },
        startAuthLogin: () => {
          keychain.set(dir, credential('new-token'));
          return { urlHint: async () => undefined, done: async () => 1 };
        },
        browser: { authorize: async () => 'failed' },
        debugPort: 9222,
      },
    );
    expect(result).toMatchObject({ ok: true, detail: 'logged in (completed manually)' });
  });

  it('refuses a shared refresh token offline and removes only the refused Keychain entry', async () => {
    const other = path.join(home, 'other');
    keychain.set(other, credential('work-token'));
    addAccount({ name: 'other', dir: other }, context.ctx);
    const lookupOwner = vi.fn(async () => null);
    expect(await settleNewLogin(context, { name: 'work', dir }, { lookupOwner })).toMatchObject({
      ok: false,
      twin: 'other',
    });
    expect(lookupOwner).not.toHaveBeenCalled();
    expect(keychain.has(dir)).toBe(false);
    expect(keychain.has(other)).toBe(true);
  });

  it('copies into a session, updates an existing Keychain login, and rolls it back', () => {
    const session = path.join(home, 'session');
    expect(installCredential(session, credentialPath(dir))).toBe(true);
    expect(readOauthToken(credentialPath(session))).toBe('work-token');
    keychain.set(session, credential('session-renewed'));
    expect(installCredential(dir, credentialPath(session))).toBe(true);
    expect(readOauthToken(credentialPath(dir))).toBe('session-renewed');
    expect(existsSync(credentialPath(dir))).toBe(false);
    expect(rollbackCredential(dir)).toBe(true);
    expect(readOauthToken(credentialPath(dir))).toBe('work-token');
  });

  it('uses Keychain ahead of a stale fallback file and persists renewals to Keychain', async () => {
    writeFileSync(credentialPath(home), credential('stale-file'));
    keychain.set(home, credential('expiring-token', 1));
    const fetchImpl = vi.fn(
      async (_url: unknown, _init?: RequestInit) =>
        new Response(
          JSON.stringify({
            access_token: 'renewed',
            refresh_token: 'renewed-refresh',
            expires_in: 3600,
          }),
        ),
    );
    expect(await refreshCredentialIfExpired(home, { fetchImpl })).toMatchObject({
      status: 'refreshed',
    });
    expect(JSON.parse(String(fetchImpl.mock.calls[0]?.[1]?.body)).refresh_token).toBe(
      'refresh-expiring-token',
    );
    expect(readOauthToken(credentialPath(home))).toBe('renewed');
  });

  it('does not read or overwrite a stale file when Keychain is inaccessible', () => {
    const file = credentialPath(home);
    const stale = credential('stale');
    writeFileSync(file, stale);
    vi.mocked(readKeychainCredential).mockImplementationOnce(() => {
      throw new Error('locked');
    });
    expect(() => readCredential(file)).toThrow('locked');
    vi.mocked(readKeychainCredential).mockImplementationOnce(() => {
      throw new Error('locked');
    });
    expect(() => writeCredential(file, credential('replacement'))).toThrow('locked');
    expect(readFileSync(file, 'utf8')).toBe(stale);
  });

  it('surfaces failed Keychain writes without falling back to a file', () => {
    vi.mocked(writeKeychainCredential).mockImplementationOnce(() => {
      throw new Error('locked');
    });
    expect(() => writeCredential(credentialPath(dir), credential('replacement'))).toThrow('locked');
    expect(existsSync(credentialPath(dir))).toBe(false);
    expect(readOauthToken(credentialPath(dir))).toBe('work-token');
  });

  it('removes both credential stores, and does not claim success when Keychain deletion fails', () => {
    mkdirSync(dir);
    writeFileSync(credentialPath(dir), credential('stale'));
    vi.mocked(deleteKeychainCredential).mockImplementationOnce(() => {
      throw new Error('locked');
    });
    expect(() => removeCredential(credentialPath(dir))).toThrow('locked');
    expect(keychain.has(dir)).toBe(true);
    removeCredential(credentialPath(dir));
    expect(keychain.has(dir)).toBe(false);
    expect(existsSync(credentialPath(dir))).toBe(false);
  });

  it('keeps a Keychain-backed profile path stable when renaming its account', () => {
    const oldDir = path.join(home, 'profiles', 'old');
    mkdirSync(oldDir, { recursive: true });
    keychain.set(oldDir, credential('old'));
    addAccount({ name: 'old', dir: oldDir }, context.ctx);
    expect(renameAccount('old', 'new', {}, context.ctx)).toMatchObject({ folderMoved: false });
    expect(getAccount('new', context.ctx)?.dir).toBe(oldDir);
    expect(readOauthToken(credentialPath(oldDir))).toBe('old');
  });

  it('cleans up session and purged profile Keychain entries', () => {
    mkdirSync(dir);
    expect(removeSessionDir(dir)).toBe(true);
    expect(keychain.has(dir)).toBe(false);
    const purgeDir = path.join(home, 'profiles', 'purge');
    mkdirSync(purgeDir, { recursive: true });
    keychain.set(purgeDir, credential('purge'));
    addAccount({ name: 'purge', dir: purgeDir }, context.ctx);
    expect(removeCommand(context, 'purge', { purge: true })).toBe(0);
    expect(keychain.has(purgeDir)).toBe(false);
    expect(existsSync(purgeDir)).toBe(false);
  });

  it('propagates a verified renewal from a Keychain snapshot to a matching sibling', () => {
    const sibling = path.join(home, 'sibling');
    mkdirSync(dir);
    mkdirSync(sibling);
    keychain.set(sibling, keychain.get(dir)!);
    const retired = credentialFingerprint(dir);
    keychain.set(dir, credential('renewed'));
    expect(
      propagateRenewal({
        renewedDir: dir,
        retired,
        renewed: credentialFingerprint(dir),
        siblings: [{ name: 'sibling', dir: sibling }],
      }),
    ).toEqual(['sibling']);
    expect(readOauthToken(credentialPath(sibling))).toBe('renewed');
  });
});
