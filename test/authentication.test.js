// Authentication hardening: two-factor sign-in, password policy, forced password change,
// mandatory admin 2FA, session management, Origin checks.
import { after, before, describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { as, baseUrl, Client, createUser, query, resetLoginThrottle, start, stop } from './helpers.js';
import { base32Decode, base32Encode, currentStep, hotp, verifyTotp } from '../src/mfa.js';
import { passwordProblem } from '../src/passwords.js';

before(start);
after(stop);

const codeFor = (secret, offsetSteps = 0) => hotp(base32Decode(secret), currentStep() + offsetSteps);

/** Turn on 2FA for a signed-in client. Returns { secret, recoveryCodes }. */
async function enableMfa(client) {
  const setup = await client.post('/api/auth/mfa/setup');
  assert.equal(setup.status, 200);
  assert.match(setup.data.qrDataUrl, /^data:image\/svg\+xml;base64,/);
  const enable = await client.post('/api/auth/mfa/enable', { json: { code: codeFor(setup.data.secret) } });
  assert.equal(enable.status, 200, JSON.stringify(enable.data));
  return { secret: setup.data.secret, recoveryCodes: enable.data.recoveryCodes };
}

async function passwordStep(email, password) {
  const c = new Client();
  const r = await c.post('/api/auth/login', { json: { email, password } });
  return { c, r };
}

describe('A-01 TOTP matches the published RFC test vectors', () => {
  test('RFC 4226 HOTP vectors for the key "12345678901234567890"', () => {
    const key = Buffer.from('12345678901234567890');
    assert.deepEqual([0, 1, 2, 3, 9].map((c) => hotp(key, c)), ['755224', '287082', '359152', '969429', '520489']);
  });

  test('base32 round-trips', () => {
    const buf = Buffer.from('any random bytes!!');
    assert.deepEqual(base32Decode(base32Encode(buf)), buf);
  });

  test('a code is accepted once, then refused for the same or an earlier time-step', () => {
    const secret = base32Encode(Buffer.from('12345678901234567890'));
    const now = Date.now();
    const code = hotp(base32Decode(secret), currentStep(now));
    const step = verifyTotp(secret, code, 0, now);
    assert.equal(step, currentStep(now));
    assert.equal(verifyTotp(secret, code, step, now), null, 'replay must be refused');
    assert.equal(verifyTotp(secret, '000000x', 0, now), null);
    assert.equal(verifyTotp(secret, hotp(base32Decode(secret), currentStep(now) - 5), 0, now), null, 'old codes are refused');
  });
});

describe('A-02 two-factor sign-in end to end', () => {
  test('password alone does not create a session once 2FA is on', async () => {
    const admin = await as('admin');
    const { client, email, password } = await createUser(admin, { role: 'owner', name: 'Mfa Owner', prefix: 'mfa' });
    const { secret, recoveryCodes } = await enableMfa(client);
    assert.equal(recoveryCodes.length, 10);

    const { c, r } = await passwordStep(email, password);
    assert.equal(r.status, 200);
    assert.equal(r.data.mfaRequired, true);
    assert.equal(r.data.user, undefined);
    assert.equal(c.cookie, '', 'no session cookie after the password step');
    assert.equal((await c.get('/api/documents')).status, 401);

    // Wrong code refused, right code signs in.
    const wrong = await c.post('/api/auth/mfa', { json: { mfaToken: r.data.mfaToken, code: '000000' } });
    assert.equal(wrong.status, 401);
    const code = codeFor(secret, 1);
    const ok = await c.post('/api/auth/mfa', { json: { mfaToken: r.data.mfaToken, code } });
    assert.equal(ok.status, 200, JSON.stringify(ok.data));
    c.csrf = ok.data.csrfToken;
    assert.equal((await c.get('/api/documents')).status, 200);

    // The same code cannot be used again, even with a fresh password step.
    const again = await passwordStep(email, password);
    const replay = await again.c.post('/api/auth/mfa', { json: { mfaToken: again.r.data.mfaToken, code } });
    assert.equal(replay.status, 401, 'a used code must not work twice');

    // A recovery code works exactly once.
    const rc = recoveryCodes[0];
    const first = await again.c.post('/api/auth/mfa', { json: { mfaToken: again.r.data.mfaToken, recoveryCode: rc } });
    assert.equal(first.status, 200);
    const third = await passwordStep(email, password);
    const reuse = await third.c.post('/api/auth/mfa', { json: { mfaToken: third.r.data.mfaToken, recoveryCode: rc } });
    assert.equal(reuse.status, 401);
  });

  test('five wrong codes burn the sign-in ticket', async () => {
    const admin = await as('admin');
    const { client, email, password } = await createUser(admin, { role: 'viewer', name: 'Brute Target', prefix: 'brute' });
    const { secret } = await enableMfa(client);
    const { c, r } = await passwordStep(email, password);
    for (let i = 0; i < 5; i++) await c.post('/api/auth/mfa', { json: { mfaToken: r.data.mfaToken, code: String(100000 + i) } });
    const late = await c.post('/api/auth/mfa', { json: { mfaToken: r.data.mfaToken, code: codeFor(secret, 1) } });
    assert.equal(late.status, 401, 'even the right code fails after the ticket is burned');
  });

  test('an expired or forged ticket is refused', async () => {
    const admin = await as('admin');
    const { client, email, password } = await createUser(admin, { role: 'viewer', name: 'Slow Typist', prefix: 'slow' });
    const { secret } = await enableMfa(client);
    const { c, r } = await passwordStep(email, password);
    await query(`UPDATE pending_logins SET expires_at = now() - interval '1 second'`);
    assert.equal((await c.post('/api/auth/mfa', { json: { mfaToken: r.data.mfaToken, code: codeFor(secret, 1) } })).status, 401);
    assert.equal((await c.post('/api/auth/mfa', { json: { mfaToken: 'forged', code: codeFor(secret, 1) } })).status, 401);
  });

  test('the TOTP secret is encrypted at rest and never returned by /me', async () => {
    const admin = await as('admin');
    const { client, id } = await createUser(admin, { role: 'viewer', name: 'Secret Keeper', prefix: 'sk' });
    const { secret } = await enableMfa(client);
    const [row] = await query('SELECT mfa_secret_enc FROM users WHERE id = $1', [id]);
    assert.ok(!row.mfa_secret_enc.includes(secret));
    const me = await client.get('/api/me');
    assert.ok(!JSON.stringify(me.data).includes(secret));
    assert.ok(!JSON.stringify(me.data).includes('scrypt$'));
  });
});

describe('A-03 account gates', () => {
  test('a new account must replace its admin-set password before doing anything else', async () => {
    const admin = await as('admin');
    const email = `gated-${Date.now()}@example.test`;
    const initial = 'Initial-Password-Xy9';
    await admin.post('/api/admin/users', { json: { email, name: 'Gated', role: 'owner', password: initial } });
    const c = await new Client().login(email, initial);
    assert.equal(c.user.mustChangePassword, true);
    const r = await c.get('/api/documents');
    assert.equal(r.status, 403);
    assert.equal(r.data.details.code, 'PASSWORD_CHANGE_REQUIRED');
    assert.equal((await c.post('/api/auth/password', { json: { currentPassword: initial, newPassword: 'A-brand-new-passphrase' } })).status, 200);
    assert.equal((await c.get('/api/documents')).status, 200);
  });

  test('a real administrator account cannot use admin pages until 2FA is set up, and cannot turn it off', async () => {
    const admin = await as('admin');
    const { client: newAdmin } = await createUser(admin, { role: 'admin', name: 'Second Admin', prefix: 'admin2' });
    const blocked = await newAdmin.get('/api/admin/overview');
    assert.equal(blocked.status, 403);
    assert.equal(blocked.data.details.code, 'MFA_SETUP_REQUIRED');
    const { secret } = await enableMfa(newAdmin);
    assert.equal((await newAdmin.get('/api/admin/overview')).status, 200);
    const off = await newAdmin.post('/api/auth/mfa/disable', { json: { password: 'x', code: codeFor(secret, 1) } });
    assert.equal(off.status, 400);
  });
});

describe('A-04 password policy', () => {
  test('weak passwords are rejected with a reason', () => {
    const who = { email: 'priya.shah@example.test', name: 'Priya Shah' };
    for (const bad of ['short1!', 'password123', 'Password1234', 'qwertyuiop', 'aaaaaaaaaaaaaa', 'priyashah2026!!', 'my-shah-password', '1234567890ab']) {
      assert.ok(passwordProblem(bad, who), `${bad} should be rejected`);
    }
    for (const good of ['correct horse battery staple', 'Monsoon-Train-Chai-42']) {
      assert.equal(passwordProblem(good, who), null, `${good} should be accepted`);
    }
  });

  test('the API enforces it when an admin creates a user', async () => {
    const admin = await as('admin');
    const r = await admin.post('/api/admin/users', { json: { email: 'weak@example.test', name: 'Weak', role: 'viewer', password: 'password1234' } });
    assert.equal(r.status, 400);
  });
});

describe('A-05 changing your password', () => {
  test('needs the current password, ends other sessions, keeps this one, retires the old password', async () => {
    const admin = await as('admin');
    const { client, email, password } = await createUser(admin, { role: 'viewer', name: 'Changer', prefix: 'chg' });
    const laptop = await new Client().login(email, password);
    assert.equal((await client.post('/api/auth/password', { json: { currentPassword: 'wrong', newPassword: 'Another-Good-Passphrase' } })).status, 400);
    assert.equal((await client.post('/api/auth/password', { json: { currentPassword: password, newPassword: 'Another-Good-Passphrase' } })).status, 200);
    assert.equal((await client.get('/api/me')).status, 200, 'current session continues');
    assert.equal((await laptop.get('/api/me')).status, 401, 'other session ended');
    resetLoginThrottle();
    await assert.rejects(new Client().login(email, password), 'old password no longer works');
    await new Client().login(email, 'Another-Good-Passphrase');
  });

  test('the shared demo accounts cannot have their password or 2FA changed', async () => {
    const vik = await as('vik');
    assert.equal((await vik.post('/api/auth/password', { json: { currentPassword: 'Viewer#Vault2026', newPassword: 'Totally-New-Passphrase' } })).status, 400);
    assert.equal((await vik.post('/api/auth/mfa/setup')).status, 400);
  });
});

describe('A-06 session management', () => {
  test('users see and end only their own sessions', async () => {
    const admin = await as('admin');
    const { client: alice, email, password } = await createUser(admin, { role: 'viewer', name: 'Alice Sessions', prefix: 'alice' });
    const { client: bob } = await createUser(admin, { role: 'viewer', name: 'Bob Sessions', prefix: 'bob' });
    const alicePhone = await new Client().login(email, password);

    const mine = (await alice.get('/api/auth/sessions')).data.sessions;
    assert.equal(mine.length, 2);
    assert.equal(mine.filter((s) => s.current).length, 1);
    assert.ok(mine.every((s) => !('token_hash' in s) && !('csrf_token' in s)));

    // Bob cannot end Alice's session even with its id.
    const phoneId = mine.find((s) => !s.current).id;
    assert.equal((await bob.del(`/api/auth/sessions/${phoneId}`)).status, 404);
    assert.equal((await alicePhone.get('/api/me')).status, 200);

    assert.equal((await alice.post('/api/auth/sessions/revoke-others')).data.ended, 1);
    assert.equal((await alicePhone.get('/api/me')).status, 401);
  });

  test('an admin password reset ends every session and forces a new password', async () => {
    const admin = await as('admin');
    const { client: user, id } = await createUser(admin, { role: 'viewer', name: 'Forgetful', prefix: 'forgot' });
    assert.equal((await admin.post(`/api/admin/users/${id}/reset-password`, { json: { password: 'Temporary-Reset-Pass-7' } })).status, 200);
    assert.equal((await user.get('/api/me')).status, 401);
    assert.equal((await admin.post(`/api/admin/users/${admin.user.id}/reset-password`, { json: { password: 'Temporary-Reset-Pass-7' } })).status, 400, 'not on yourself');
    assert.equal((await (await as('vik')).post(`/api/admin/users/${id}/reset-password`, { json: { password: 'Temporary-Reset-Pass-7' } })).status, 403);
  });
});

describe('A-07 Origin check', () => {
  test('a cross-site sign-in or state change is refused', async () => {
    const login = await fetch(`${baseUrl}/api/auth/login`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', origin: 'https://evil.example' },
      body: JSON.stringify({ email: 'vik.viewer@trustvault.demo', password: 'Viewer#Vault2026' }),
    });
    assert.equal(login.status, 403);
    assert.equal(login.headers.get('set-cookie'), null);
    const same = await fetch(`${baseUrl}/api/auth/login`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', origin: baseUrl },
      body: JSON.stringify({ email: 'vik.viewer@trustvault.demo', password: 'Viewer#Vault2026' }),
    });
    assert.equal(same.status, 200);
  });
});
