// Self sign-up, email/SMS one-time codes, password reset, phone numbers and SMS two-factor.
import { after, before, beforeEach, describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { as, Client, fileForm, makePdf, query, resetLoginThrottle, start, stop } from './helpers.js';
import { outbox } from '../src/notify.js';
import { resetOtpLimits } from '../src/otp.js';
import { base32Decode, currentStep, hotp } from '../src/mfa.js';

before(start);
after(stop);
beforeEach(() => {
  resetOtpLimits();
  resetLoginThrottle();
});

const uniq = (p) => `${p}-${randomBytes(4).toString('hex')}@example.test`;
const PASSWORD = 'Saffron-Kite-Harbour-61';
const lastCodeFor = (to) => {
  const msg = [...outbox].reverse().find((m) => m.to === to);
  return msg ? (msg.text.match(/\b(\d{6})\b/) || [])[1] : undefined;
};
const sentCount = (to) => outbox.filter((m) => m.to === to).length;
// Skip the 60-second resend cooldown in tests by ageing earlier codes.
const ageCodes = () => query(`UPDATE otp_codes SET created_at = created_at - interval '2 minutes'`);

async function signUp(email, extra = {}) {
  const c = new Client();
  const r = await c.post('/api/auth/signup', { json: { name: 'Priya Shah', email, password: PASSWORD, ...extra } });
  assert.equal(r.status, 201, JSON.stringify(r.data));
  const v = await c.post('/api/auth/signup/verify', { json: { ticket: r.data.ticket, code: lastCodeFor(email) } });
  assert.equal(v.status, 200, JSON.stringify(v.data));
  c.csrf = v.data.csrfToken;
  c.user = v.data.user;
  return c;
}

describe('O-01 self sign-up with email verification', () => {
  test('code by email, wrong code refused, right code signs in as a viewer, code single-use', async () => {
    const email = uniq('new');
    const c = new Client();
    const r = await c.post('/api/auth/signup', { json: { name: 'Priya Shah', email, password: PASSWORD } });
    assert.equal(r.status, 201);
    assert.ok(r.data.ticket);
    const code = lastCodeFor(email);
    assert.match(code, /^\d{6}$/);
    assert.equal((await c.post('/api/auth/signup/verify', { json: { ticket: r.data.ticket, code: code === '000000' ? '111111' : '000000' } })).status, 400);
    const ok = await c.post('/api/auth/signup/verify', { json: { ticket: r.data.ticket, code } });
    assert.equal(ok.status, 200);
    assert.equal(ok.data.user.role, 'viewer');
    assert.equal(ok.data.user.emailVerified, true);
    c.csrf = ok.data.csrfToken;
    assert.equal((await c.get('/api/documents')).status, 200);
    // A self-registered viewer cannot upload.
    assert.equal((await c.post('/api/documents', { form: fileForm('a.pdf', makePdf(['x']), { title: 'x', category: 'HR' }) })).status, 403);
    // Reusing the code fails.
    assert.equal((await new Client().post('/api/auth/signup/verify', { json: { ticket: r.data.ticket, code } })).status, 400);
  });

  test('weak passwords and bad input are refused before anything is created', async () => {
    const email = uniq('weak');
    const c = new Client();
    assert.equal((await c.post('/api/auth/signup', { json: { name: 'Weak', email, password: 'password123' } })).status, 400);
    assert.equal((await c.post('/api/auth/signup', { json: { name: 'Bad', email: 'not-an-email', password: PASSWORD } })).status, 400);
    assert.equal((await c.post('/api/auth/signup', { json: { name: 'Bad Phone', email, password: PASSWORD, phone: '12' } })).status, 400);
    const [{ n }] = await query('SELECT count(*)::int AS n FROM users WHERE email = $1', [email]);
    assert.equal(n, 0);
  });
});

describe('O-02 no account enumeration', () => {
  test('signing up with a registered email looks identical and sends nothing', async () => {
    const before = sentCount('olivia.owner@trustvault.demo');
    const r = await new Client().post('/api/auth/signup', { json: { name: 'Imposter', email: 'olivia.owner@trustvault.demo', password: PASSWORD } });
    assert.equal(r.status, 201);
    assert.deepEqual(Object.keys(r.data).sort(), ['sentTo', 'ticket']);
    assert.equal(sentCount('olivia.owner@trustvault.demo'), before);
    const [u] = await query(`SELECT name FROM users WHERE email = 'olivia.owner@trustvault.demo'`);
    assert.equal(u.name, 'Olivia Hart', 'existing account untouched');
  });

  test('email-code and password-reset start behave identically for unknown and known emails, including the cooldown', async () => {
    const known = (await signUp(uniq('known'))).user.email;
    const unknown = uniq('nobody');
    await ageCodes();
    for (const path of ['/api/auth/email-code/start', '/api/auth/password-reset/start']) {
      const seq = async (email) => {
        const first = await new Client().post(path, { json: { email } });
        const second = await new Client().post(path, { json: { email } }); // inside the 60 s cooldown
        return [first.status, Object.keys(first.data).sort().join(), second.status];
      };
      assert.deepEqual(await seq(known), await seq(unknown), `${path} leaks whether the account exists`);
      await ageCodes();
    }
    // ...and an address with no account is never actually emailed (no spam relay).
    assert.equal(sentCount(unknown), 0, 'codes must not be sent to addresses without an account');
  });

  test('demo accounts (undeliverable addresses) never get codes', async () => {
    const before = sentCount('admin@trustvault.demo');
    await new Client().post('/api/auth/email-code/start', { json: { email: 'admin@trustvault.demo' } });
    await new Client().post('/api/auth/password-reset/start', { json: { email: 'admin@trustvault.demo' } });
    assert.equal(sentCount('admin@trustvault.demo'), before);
  });
});

describe('O-03 unverified accounts cannot sign in', () => {
  test('correct password on an unverified account gets a fresh code, not a session', async () => {
    const email = uniq('unverified');
    await new Client().post('/api/auth/signup', { json: { name: 'Late Verifier', email, password: PASSWORD } });
    await ageCodes();
    const c = new Client();
    const r = await c.post('/api/auth/login', { json: { email, password: PASSWORD } });
    assert.equal(r.status, 403);
    assert.equal(r.data.details.code, 'EMAIL_NOT_VERIFIED');
    assert.equal(c.cookie, '');
    const v = await c.post('/api/auth/signup/verify', { json: { ticket: r.data.details.ticket, code: lastCodeFor(email) } });
    assert.equal(v.status, 200);
  });
});

describe('O-04 account pre-hijacking', () => {
  test("an attacker who registers someone else's email first cannot keep the account", async () => {
    const victim = uniq('victim');
    await new Client().post('/api/auth/signup', { json: { name: 'Attacker', email: victim, password: 'Attacker-Owns-This-1' } });
    await ageCodes();
    const real = await signUp(victim); // the inbox owner signs up and verifies
    assert.equal(real.user.name, 'Priya Shah');
    resetLoginThrottle();
    const attacker = await new Client().post('/api/auth/login', { json: { email: victim, password: 'Attacker-Owns-This-1' } });
    assert.equal(attacker.status, 401, "the attacker's password no longer works");
  });
});

describe('O-05 passwordless sign-in with an email code', () => {
  test('code + its own ticket signs in; a code under another ticket does not', async () => {
    const email = uniq('pwless');
    await signUp(email);
    await ageCodes();
    const c = new Client();
    const s = await c.post('/api/auth/email-code/start', { json: { email } });
    const code = lastCodeFor(email);
    await ageCodes();
    const other = await new Client().post('/api/auth/email-code/start', { json: { email } });
    assert.equal((await new Client().post('/api/auth/email-code/verify', { json: { ticket: other.data.ticket, code } })).status, 400, 'code is bound to its ticket');
    const ok = await c.post('/api/auth/email-code/verify', { json: { ticket: s.data.ticket, code } });
    assert.equal(ok.status, 200);
    assert.ok(ok.data.lastSignIn, 'previous sign-in info is returned');
  });

  test('five wrong guesses burn the code, and expired codes fail', async () => {
    const email = uniq('guess');
    await signUp(email);
    await ageCodes();
    const s = await new Client().post('/api/auth/email-code/start', { json: { email } });
    const code = lastCodeFor(email);
    for (let i = 0; i < 5; i++) await new Client().post('/api/auth/email-code/verify', { json: { ticket: s.data.ticket, code: String(100000 + i) } });
    assert.equal((await new Client().post('/api/auth/email-code/verify', { json: { ticket: s.data.ticket, code } })).status, 400);

    await ageCodes();
    const s2 = await new Client().post('/api/auth/email-code/start', { json: { email } });
    const code2 = lastCodeFor(email);
    await query(`UPDATE otp_codes SET expires_at = now() - interval '1 second' WHERE consumed_at IS NULL`);
    assert.equal((await new Client().post('/api/auth/email-code/verify', { json: { ticket: s2.data.ticket, code: code2 } })).status, 400);
  });

  test('codes are stored as HMACs, never in plain text', async () => {
    const rows = await query('SELECT code_hash FROM otp_codes');
    assert.ok(rows.length > 0);
    assert.ok(rows.every((r) => /^[0-9a-f]{64}$/.test(r.code_hash)));
  });

  test('passwordless sign-in still requires the authenticator when it is on', async () => {
    const email = uniq('pwless2fa');
    const c = await signUp(email);
    const setup = await c.post('/api/auth/mfa/setup');
    const totp = (o = 0) => hotp(base32Decode(setup.data.secret), currentStep() + o);
    assert.equal((await c.post('/api/auth/mfa/enable', { json: { code: totp() } })).status, 200);
    await ageCodes();
    const s = await new Client().post('/api/auth/email-code/start', { json: { email } });
    const v = await new Client().post('/api/auth/email-code/verify', { json: { ticket: s.data.ticket, code: lastCodeFor(email) } });
    assert.equal(v.status, 200);
    assert.equal(v.data.mfaRequired, true);
    assert.equal(v.data.method, 'totp');
    assert.equal(v.data.user, undefined);
  });
});

describe('O-06 resend cooldown', () => {
  test('a second code to the same address within 60 seconds is refused', async () => {
    const email = uniq('cool');
    await signUp(email);
    await ageCodes();
    assert.equal((await new Client().post('/api/auth/email-code/start', { json: { email } })).status, 200);
    const again = await new Client().post('/api/auth/email-code/start', { json: { email } });
    assert.equal(again.status, 429);
    assert.equal(again.data.details.code, 'RESEND_COOLDOWN');
  });
});

describe('O-07 forgotten password', () => {
  test('reset by email code ends every session, retires the old password, and keeps 2FA', async () => {
    const email = uniq('reset');
    const c = await signUp(email);
    const setup = await c.post('/api/auth/mfa/setup');
    const totp = (o = 0) => hotp(base32Decode(setup.data.secret), currentStep() + o);
    await c.post('/api/auth/mfa/enable', { json: { code: totp() } });
    await ageCodes();

    const s = await new Client().post('/api/auth/password-reset/start', { json: { email } });
    const code = lastCodeFor(email);
    // A weak password is refused without burning the code.
    assert.equal((await new Client().post('/api/auth/password-reset/complete', { json: { ticket: s.data.ticket, code, newPassword: 'short' } })).status, 400);
    const done = await new Client().post('/api/auth/password-reset/complete', { json: { ticket: s.data.ticket, code, newPassword: 'Brand-New-Monsoon-Pass-9' } });
    assert.equal(done.status, 200);
    assert.equal((await c.get('/api/me')).status, 401, 'existing session ended');

    resetLoginThrottle();
    assert.equal((await new Client().post('/api/auth/login', { json: { email, password: PASSWORD } })).status, 401, 'old password retired');
    const r = await new Client().post('/api/auth/login', { json: { email, password: 'Brand-New-Monsoon-Pass-9' } });
    assert.equal(r.data.mfaRequired, true, 'reset does not bypass the authenticator');
  });
});

describe('O-08 mobile number and SMS', () => {
  test('verify a phone, turn on SMS 2FA, sign in with password + SMS, and with SMS + password', async () => {
    const email = uniq('phone');
    const phone = `+9198${String(Date.now()).slice(-8)}`;
    const c = await signUp(email);
    const p = await c.post('/api/auth/phone/start', { json: { phone } });
    assert.equal(p.status, 200, JSON.stringify(p.data));
    assert.equal((await c.post('/api/auth/phone/verify', { json: { ticket: p.data.ticket, code: lastCodeFor(phone) } })).status, 200);
    assert.equal((await c.post('/api/auth/sms-2fa', { json: { enabled: true, password: 'wrong' } })).status, 400, 'needs the password');
    assert.equal((await c.post('/api/auth/sms-2fa', { json: { enabled: true, password: PASSWORD } })).status, 200);

    // Password first, SMS second.
    await ageCodes();
    const l = new Client();
    const step1 = await l.post('/api/auth/login', { json: { email, password: PASSWORD } });
    assert.equal(step1.data.method, 'sms');
    assert.equal((await l.post('/api/auth/mfa', { json: { mfaToken: step1.data.mfaToken, smsTicket: step1.data.smsTicket, code: '000001' } })).status, 401);
    const step2 = await l.post('/api/auth/mfa', { json: { mfaToken: step1.data.mfaToken, smsTicket: step1.data.smsTicket, code: lastCodeFor(phone) } });
    assert.equal(step2.status, 200);

    // SMS first: the second factor becomes the password, never SMS twice.
    await ageCodes();
    const m = new Client();
    const s = await m.post('/api/auth/sms-code/start', { json: { phone: phone.replace('+91', '') } });
    const v = await m.post('/api/auth/sms-code/verify', { json: { ticket: s.data.ticket, code: lastCodeFor(phone) } });
    assert.equal(v.data.method, 'password');
    assert.equal((await m.post('/api/auth/mfa', { json: { mfaToken: v.data.mfaToken, password: PASSWORD } })).status, 200);
  });

  test('signing in right after a text was sent opens the SMS step (with a cooldown), instead of locking the person out', async () => {
    const email = uniq('quick');
    const phone = `+9195${String(Date.now()).slice(-8)}`;
    const c = await signUp(email);
    const p = await c.post('/api/auth/phone/start', { json: { phone } });
    await c.post('/api/auth/phone/verify', { json: { ticket: p.data.ticket, code: lastCodeFor(phone) } });
    await c.post('/api/auth/sms-2fa', { json: { enabled: true, password: PASSWORD } });
    // No ageing: the phone-verification text was sent seconds ago.
    const l = new Client();
    const r = await l.post('/api/auth/login', { json: { email, password: PASSWORD } });
    assert.equal(r.status, 200, `correct password must not be refused: ${JSON.stringify(r.data)}`);
    assert.equal(r.data.method, 'sms');
    assert.ok(r.data.smsCooldown > 0);
    await ageCodes();
    const again = await l.post('/api/auth/mfa/resend-sms', { json: { mfaToken: r.data.mfaToken } });
    assert.equal(again.status, 200);
    const done = await l.post('/api/auth/mfa', { json: { mfaToken: r.data.mfaToken, smsTicket: again.data.smsTicket, code: lastCodeFor(phone) } });
    assert.equal(done.status, 200);
  });

  test('a verified number cannot be claimed by a second account', async () => {
    const phone = `+9197${String(Date.now()).slice(-8)}`;
    const a = await signUp(uniq('pa'));
    const pa = await a.post('/api/auth/phone/start', { json: { phone } });
    await a.post('/api/auth/phone/verify', { json: { ticket: pa.data.ticket, code: lastCodeFor(phone) } });
    const b = await signUp(uniq('pb'));
    assert.equal((await b.post('/api/auth/phone/start', { json: { phone } })).status, 409);
  });

  test("a phone code issued to one account cannot verify another account's phone", async () => {
    const phone = `+9196${String(Date.now()).slice(-8)}`;
    const a = await signUp(uniq('ca'));
    const pa = await a.post('/api/auth/phone/start', { json: { phone } });
    const b = await signUp(uniq('cb'));
    assert.equal((await b.post('/api/auth/phone/verify', { json: { ticket: pa.data.ticket, code: lastCodeFor(phone) } })).status, 400);
  });

  test('demo accounts cannot add phones; anonymous users cannot reach account routes', async () => {
    assert.equal((await (await as('vik')).post('/api/auth/phone/start', { json: { phone: '+919876543210' } })).status, 400);
    assert.equal((await new Client().get('/api/auth/activity')).status, 401);
  });
});

describe('O-09 security activity is visible to the account owner', () => {
  test('failed sign-ins against my account appear in my activity', async () => {
    const email = uniq('activity');
    const c = await signUp(email);
    await new Client().post('/api/auth/login', { json: { email, password: 'Wrong-Password-Guess-1' } });
    const act = (await c.get('/api/auth/activity')).data.activity;
    assert.ok(act.some((a) => a.action === 'auth.login' && a.outcome === 'denied'));
    assert.ok(act.some((a) => a.action === 'auth.email_verified'));
  });
});
