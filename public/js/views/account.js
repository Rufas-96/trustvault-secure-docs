// Account security: password, two-factor sign-in, and active sessions.
import { h, icon, toast, modal, confirmDialog, fmtDateTime, fmtAgo } from '../ui.js';
import { get, post, del } from '../api.js';
import { state, navigate, refreshUser } from '../app.js';

function describeAgent(ua = '') {
  const browser = /Edg\//.test(ua) ? 'Edge' : /Chrome\//.test(ua) ? 'Chrome' : /Firefox\//.test(ua) ? 'Firefox' : /Safari\//.test(ua) ? 'Safari' : /curl|node|undici/i.test(ua) ? 'Script / API client' : 'Browser';
  const os = /Windows/.test(ua) ? 'Windows' : /Android/.test(ua) ? 'Android' : /iPhone|iPad/.test(ua) ? 'iOS' : /Mac OS/.test(ua) ? 'macOS' : /Linux/.test(ua) ? 'Linux' : '';
  return os ? `${browser} on ${os}` : browser;
}

function gateBanner(u) {
  if (u.mustChangePassword) return h('div', { class: 'chain bad' }, icon('key'), h('div', {}, h('b', {}, 'Choose a new password to continue'), h('p', {}, 'Your account was set up (or reset) by an administrator, who knows the current password. Replace it before you can open documents.')));
  if (u.mfaRequired && !u.mfaEnabled) return h('div', { class: 'chain bad' }, icon('shield'), h('div', {}, h('b', {}, 'Set up two-factor sign-in to continue'), h('p', {}, 'Administrator accounts must use an authenticator app. Admin pages unlock once it is on.')));
  return null;
}

export async function accountPage() {
  const u = state.user;
  const [{ sessions }, recovery, { activity }] = await Promise.all([
    get('/auth/sessions'),
    u.mfaEnabled ? get('/auth/mfa/recovery-codes') : Promise.resolve(null),
    get('/auth/activity'),
  ]);
  const reload = () => navigate('#/account');

  // ── Password ──
  const current = h('input', { class: 'input', type: 'password', autocomplete: 'current-password' });
  const next = h('input', { class: 'input', type: 'password', autocomplete: 'new-password', minlength: String(state.config?.passwordMinLength || 12) });
  const confirm = h('input', { class: 'input', type: 'password', autocomplete: 'new-password' });
  const pwError = h('div', { class: 'form-error hidden', role: 'alert' });
  const pwForm = h('form', { class: 'stack', onsubmit: async (e) => {
    e.preventDefault();
    pwError.classList.add('hidden');
    if (next.value !== confirm.value) { pwError.textContent = 'The new passwords do not match'; pwError.classList.remove('hidden'); return; }
    try {
      await post('/auth/password', { currentPassword: current.value, newPassword: next.value });
      toast('Password changed. Every other session for your account has been signed out.');
      await refreshUser();
      reload();
    } catch (err) { pwError.textContent = err.message; pwError.classList.remove('hidden'); }
  } },
  pwError,
  h('label', { class: 'field' }, 'Current password', current),
  h('label', { class: 'field' }, `New password (at least ${state.config?.passwordMinLength || 12} characters)`, next),
  h('label', { class: 'field' }, 'Confirm new password', confirm),
  h('div', { class: 'note' }, icon('info'), h('div', {}, 'Length beats symbols: a few unrelated words make a strong password. Common passwords and ones containing your name or email are refused.')),
  h('div', {}, h('button', { class: 'btn primary', type: 'submit', disabled: u.isDemo }, 'Change password')));

  // ── Two-factor ──
  let mfaBody;
  if (u.isDemo) {
    mfaBody = h('div', { class: 'note' }, icon('info'), h('div', {}, 'This is a shared demo account, so its password and two-factor settings are locked: otherwise one evaluator could lock the others out. To try two-factor sign-in, sign in as the administrator, add a person under People, and sign in as them.'));
  } else if (u.mfaEnabled) {
    mfaBody = h('div', { class: 'stack' },
      h('div', { class: 'chain ok' }, icon('shield'), h('div', {}, h('b', {}, 'Two-factor sign-in is on'), h('p', {}, `Every sign-in needs a code from your authenticator app. ${recovery.remaining} of 10 recovery codes left.`))),
      u.mfaRequired ? h('p', { class: 'muted small' }, 'Required for administrators, so it cannot be turned off.')
        : h('div', {}, h('button', { class: 'btn danger', onclick: () => disableMfaDialog().then((ok) => ok && refreshUser().then(reload)) }, 'Turn off two-factor')));
  } else {
    mfaBody = h('div', { class: 'stack' },
      h('p', { class: 'muted' }, 'Protect your account even if your password leaks. You will need an authenticator app such as Google Authenticator, Microsoft Authenticator, 1Password or Authy.'),
      h('div', {}, h('button', { class: 'btn primary', onclick: () => setupMfaDialog().then((ok) => ok && refreshUser().then(reload)) }, icon('shield'), 'Set up two-factor sign-in')));
  }

  // ── Sessions ──
  const others = sessions.filter((s) => !s.current).length;
  const sessionList = h('div', { class: 'list' }, sessions.map((s) => h('div', { class: 'list-item' },
    h('div', { class: 'tl-dot ok' }),
    h('div', { class: 'who' }, h('b', {}, describeAgent(s.user_agent), s.current ? h('span', { class: 'pill ok' }, 'This device') : null),
      h('span', {}, `${s.ip || 'unknown IP'} · signed in ${fmtDateTime(s.created_at)} · active ${fmtAgo(s.last_seen_at)}`)),
    s.current ? null : h('button', { class: 'btn danger sm', onclick: async () => {
      try { await del(`/auth/sessions/${s.id}`); toast('Signed out that session.'); reload(); } catch (e) { toast(e.message, 'error'); }
    } }, 'Sign out'))));

  return h('div', { class: 'stack' },
    h('div', { class: 'page-head' }, h('div', { class: 'titles' }, h('h1', {}, 'Account security'), h('p', {}, `${u.name} · ${u.email}`))),
    gateBanner(u),
    securityChecklist(u, sessions),
    h('div', { class: 'detail-grid' },
      h('div', { class: 'stack' },
        activityCard(activity),
        h('div', { class: 'card' }, h('div', { class: 'card-head' }, h('div', { class: 'grow' }, h('h3', {}, 'Two-factor sign-in'), h('p', {}, 'A one-time code from your phone on every sign-in.'))), h('div', { class: 'card-pad' }, mfaBody)),
        h('div', { class: 'card' },
          h('div', { class: 'card-head' }, h('div', { class: 'grow' }, h('h3', {}, 'Where you are signed in'), h('p', {}, 'Sessions end after 30 minutes idle or 8 hours total. Sign out any you do not recognise.')),
            others ? h('button', { class: 'btn sm', onclick: async () => {
              if (!(await confirmDialog({ title: 'Sign out everywhere else?', text: `Ends ${others} other session(s) immediately. This device stays signed in.`, confirm: 'Sign out others', danger: true }))) return;
              const r = await post('/auth/sessions/revoke-others');
              toast(`Signed out ${r.ended} other session(s).`);
              reload();
            } }, 'Sign out all others') : null),
          sessionList)),
      h('div', { class: 'card' }, h('div', { class: 'card-head' }, h('h3', {}, 'Password')), h('div', { class: 'card-pad' },
        u.isDemo ? h('div', { class: 'note' }, icon('info'), h('div', {}, 'Locked on shared demo accounts.')) : pwForm))));
}

function codeInput() {
  return h('input', { class: 'input mono', inputmode: 'numeric', autocomplete: 'one-time-code', maxlength: '7', placeholder: '123 456' });
}

function setupMfaDialog() {
  return modal((close) => {
    const body = h('div', { class: 'stack' }, h('p', { class: 'muted' }, 'Preparing…'));
    const code = codeInput();
    const error = h('div', { class: 'form-error hidden', role: 'alert' });
    const confirmBtn = h('button', { class: 'btn primary', onclick: async () => {
      error.classList.add('hidden');
      try {
        const { recoveryCodes } = await post('/auth/mfa/enable', { code: code.value.replace(/\s/g, '') });
        body.replaceChildren(
          h('div', { class: 'chain ok' }, icon('check'), h('div', {}, h('b', {}, 'Two-factor sign-in is on'), h('p', {}, 'Your other sessions were signed out.'))),
          h('p', {}, h('b', {}, 'Save these recovery codes now.'), ' Each one signs you in once if you lose your phone. They will not be shown again.'),
          h('div', { class: 'recovery-grid mono' }, recoveryCodes.map((c) => h('span', {}, c))),
          h('button', { class: 'btn', onclick: () => navigator.clipboard?.writeText(recoveryCodes.join('\n')).then(() => toast('Copied.')) }, 'Copy codes'));
        confirmBtn.replaceWith(h('button', { class: 'btn primary', onclick: () => close(true) }, 'I have saved them'));
      } catch (err) { error.textContent = err.message; error.classList.remove('hidden'); }
    } }, 'Turn on');

    post('/auth/mfa/setup').then((s) => {
      body.replaceChildren(
        h('ol', { class: 'steps' },
          h('li', {}, 'Open your authenticator app and add an account.'),
          h('li', {}, 'Scan this QR code, or type the key by hand.'),
          h('li', {}, 'Enter the 6-digit code it shows.')),
        h('div', { class: 'qr-wrap' }, h('img', { src: s.qrDataUrl, alt: 'QR code for your authenticator app', width: '180', height: '180' }),
          h('div', { class: 'stack' }, h('div', { class: 'small muted' }, 'Key'), h('code', { class: 'secret' }, s.secret.match(/.{1,4}/g).join(' ')))),
        error,
        h('label', { class: 'field' }, '6-digit code', code));
      code.focus();
    }).catch((err) => { body.replaceChildren(h('div', { class: 'form-error' }, err.message)); });

    return { title: 'Set up two-factor sign-in', body, footer: [h('button', { class: 'btn', onclick: () => close(false) }, 'Cancel'), confirmBtn] };
  });
}

function disableMfaDialog() {
  const password = h('input', { class: 'input', type: 'password', autocomplete: 'current-password' });
  const code = codeInput();
  const error = h('div', { class: 'form-error hidden', role: 'alert' });
  return modal((close) => ({
    title: 'Turn off two-factor sign-in?',
    subtitle: 'Your account will be protected by your password alone.',
    body: [error, h('label', { class: 'field' }, 'Password', password), h('label', { class: 'field' }, 'Current 6-digit code', code)],
    footer: [h('button', { class: 'btn', onclick: () => close(false) }, 'Cancel'),
      h('button', { class: 'btn danger', onclick: async () => {
        try { await post('/auth/mfa/disable', { password: password.value, code: code.value.replace(/\s/g, '') }); toast('Two-factor sign-in turned off.'); close(true); }
        catch (e) { error.textContent = e.message; error.classList.remove('hidden'); }
      } }, 'Turn off')],
  }));
}

// ── Security checklist ───────────────────────────────────────────────────────
function securityChecklist(u, sessions) {
  const items = [
    { ok: u.emailVerified, title: 'Email verified', text: u.emailVerified ? 'Codes and resets can reach you.' : 'Verify your email.' },
    { ok: !u.mustChangePassword && !u.isDemo, title: 'Your own strong password', text: u.isDemo ? 'Shared demo account: password is published in the README.' : u.mustChangePassword ? 'Replace the password your administrator set.' : '12+ characters, checked against common passwords, hashed with scrypt.' },
    { ok: u.mfaEnabled, title: 'Two-factor sign-in', text: u.mfaEnabled ? 'Authenticator app required at every sign-in.' : 'Add an authenticator app for a second factor.' },
    { ok: sessions.length <= 2, title: 'Few active sessions', text: `${sessions.length} device${sessions.length === 1 ? '' : 's'} signed in. Sign out any you do not recognise.` },
  ];
  const score = items.filter((i) => i.ok).length;
  const pct = Math.round((score / items.length) * 100);
  const level = pct >= 80 ? 'strong' : pct >= 50 ? 'fair' : 'weak';
  const ring = h('div', { class: `score-ring ${level}`, role: 'img', 'aria-label': `Security score ${pct} percent` }, h('b', {}, `${pct}%`), h('span', {}, level));
  ring.style.setProperty('--pct', String(pct));
  return h('div', { class: 'card security-card' },
    h('div', { class: 'security-head' }, ring,
      h('div', { class: 'grow' }, h('h3', {}, 'Your account protection'),
        h('p', { class: 'muted' }, `${score} of ${items.length} protections in place. Every sign-in, code and setting change below is written to the tamper-evident audit trail.`))),
    h('div', { class: 'checklist' }, items.map((i) => h('div', { class: `check-item ${i.ok ? 'ok' : ''}` },
      h('div', { class: 'check-dot' }, icon(i.ok ? 'check' : 'alert')),
      h('div', {}, h('b', {}, i.title), h('span', {}, i.text))))));
}

// ── Recent security activity ─────────────────────────────────────────────────
const AUTH_LABELS = {
  'auth.login': ['Signed in', 'Failed sign-in'],
  'auth.first_factor': ['First step passed', 'First step failed'],
  'auth.second_factor': ['Second factor passed', 'Wrong second-factor code'],
  'auth.logout': ['Signed out'],
  'auth.signup': ['Account created', 'Sign-up attempt with your email'],
  'auth.email_verified': ['Email verified'],
  'auth.password_change': ['Password changed', 'Wrong current password'],
  'auth.password_reset': ['Password reset by email code'],
  'auth.password_reset_request': ['Password reset requested'],
  'auth.mfa_enable': ['Authenticator turned on'],
  'auth.mfa_disable': ['Authenticator turned off', 'Failed attempt to turn off authenticator'],
  'auth.session_revoke': ['Signed out another session'],
};

function activityCard(activity) {
  const label = (a) => {
    const l = AUTH_LABELS[a.action] || [a.action];
    return a.outcome === 'denied' ? (l[1] || `${l[0]} (refused)`) : l[0];
  };
  const detail = (a) => [a.details?.factors ? `using ${a.details.factors.join(' + ')}` : '', a.details?.reason || ''].filter(Boolean).join(' · ');
  return h('div', { class: 'card' },
    h('div', { class: 'card-head' }, h('div', { class: 'grow' }, h('h3', {}, 'Recent security activity'), h('p', {}, 'Sign-ins, failed attempts and setting changes on your account. If something here was not you, change your password and sign out other sessions.'))),
    activity.length ? h('div', { class: 'timeline' }, activity.map((a) => h('div', { class: 'tl-item' },
      h('div', { class: `tl-dot ${a.outcome}` }),
      h('div', {}, h('div', { class: 'row wrap' }, h('span', { class: 'what' }, label(a)), a.outcome === 'denied' ? h('span', { class: 'pill denied' }, 'Refused') : null),
        h('div', { class: 'when' }, `${fmtDateTime(a.at)}${a.ip ? ` · ${a.ip}` : ''}${detail(a) ? ` · ${detail(a)}` : ''}`)))))
      : h('div', { class: 'empty' }, 'No activity yet.'));
}
