// Sign in (password or email code), create account, verify email, forgot
// password, and the second-factor step. Every rule shown here is enforced again by the
// server; the UI only explains it.
import { h, icon, avatar, rolePill, toast } from '../ui.js';
import { post } from '../api.js';

const DEMO = [
  { label: 'Administrator', name: 'Ava Administrator', email: 'admin@trustvault.demo', password: 'Admin#Vault2026', role: 'admin' },
  { label: 'Owner · HR', name: 'Olivia Hart', email: 'olivia.owner@trustvault.demo', password: 'Owner#Vault2026', role: 'owner' },
  { label: 'Owner · Legal', name: 'Omar Lewis', email: 'omar.owner@trustvault.demo', password: 'Owner2#Vault2026', role: 'owner' },
  { label: 'Viewer · Employee', name: 'Vik Varma', email: 'vik.viewer@trustvault.demo', password: 'Viewer#Vault2026', role: 'viewer' },
  { label: 'Viewer · External partner', name: 'Vera Patel', email: 'vera.partner@trustvault.demo', password: 'Partner#Vault2026', role: 'viewer' },
];

// ── Small building blocks ────────────────────────────────────────────────────
const errorBox = () => h('div', { class: 'form-error hidden', role: 'alert' });
function showError(box, err) {
  box.textContent = err.message || String(err);
  box.classList.remove('hidden');
}
const hideError = (box) => box.classList.add('hidden');

function codeInput(label = '6-digit code') {
  return h('input', { class: 'input mono code-input', inputmode: 'numeric', autocomplete: 'one-time-code', maxlength: '7', placeholder: '123 456', 'aria-label': label });
}

/** A "Resend code" button with a visible 60-second cooldown, matching the server's. */
function resendButton(onResend, initial = 60) {
  const btn = h('button', { type: 'button', class: 'btn ghost sm' });
  let left = initial;
  let timer;
  const tick = () => {
    btn.disabled = left > 0;
    btn.textContent = left > 0 ? `Resend code in ${left}s` : 'Resend code';
    if (left-- > 0) timer = setTimeout(tick, 1000);
  };
  btn.addEventListener('click', async () => {
    btn.disabled = true;
    try {
      await onResend();
      toast('A new code is on its way.');
      left = 60;
    } catch (err) {
      toast(err.message, 'error');
      left = err.details?.retryAfter ?? 0;
    }
    clearTimeout(timer);
    tick();
  });
  tick();
  return btn;
}

/** Client-side estimate for the meter. The server's policy is what actually decides. */
export function passwordStrength(pw, { email = '', name = '' } = {}) {
  const hints = [];
  let score = 0;
  if (pw.length >= 12) score++; else hints.push('at least 12 characters');
  if (pw.length >= 16) score++;
  const kinds = [/[a-z]/, /[A-Z]/, /\d/, /[^A-Za-z0-9]/].filter((r) => r.test(pw)).length;
  if (kinds >= 3) score++; else hints.push('mix letters, numbers or symbols');
  if (/\s|-/.test(pw) && pw.split(/[\s-]+/).filter(Boolean).length >= 3) score++;
  const low = pw.toLowerCase();
  if (/password|qwerty|123456|letmein|welcome|admin/.test(low)) { score = 0; hints.unshift('avoid common words like "password"'); }
  const local = email.split('@')[0]?.toLowerCase();
  if (local && local.length >= 4 && low.includes(local)) { score = Math.min(score, 1); hints.unshift('do not use your email'); }
  for (const part of name.toLowerCase().split(/\s+/)) if (part.length >= 4 && low.includes(part)) { score = Math.min(score, 1); hints.unshift('do not use your name'); break; }
  const labels = ['Too weak', 'Weak', 'Fair', 'Strong', 'Excellent'];
  return { score: Math.min(score, 4), label: labels[Math.min(score, 4)], hints };
}

export function strengthMeter(input, who = () => ({})) {
  const bar = h('div', { class: 'meter-bar' });
  const text = h('div', { class: 'meter-text small' });
  const wrap = h('div', { class: 'meter', 'aria-live': 'polite' }, h('div', { class: 'meter-track' }, bar), text);
  const update = () => {
    if (!input.value) { wrap.dataset.score = ''; text.textContent = 'Use 12+ characters. A few unrelated words make a strong, memorable password.'; return; }
    const s = passwordStrength(input.value, who());
    wrap.dataset.score = String(s.score);
    text.textContent = `${s.label}${s.hints.length ? `: ${s.hints.join(', ')}` : ''}`;
  };
  input.addEventListener('input', update);
  update();
  return wrap;
}

function securityBadges() {
  const b = (ic, text) => h('span', { class: 'sec-badge' }, icon(ic), text);
  return h('div', { class: 'sec-badges' },
    b('lock', 'AES-256-GCM at rest'), b('shield', 'Two-factor sign-in'), b('history', 'HMAC-chained audit'),
    b('key', 'scrypt password hashing'), b('eye', 'Every access recorded'), b('restore', 'Instant revocation'));
}

// ── Page ─────────────────────────────────────────────────────────────────────
export function renderAuthPage(root, { mode = 'signin', config, onSignedIn }) {
  const panel = h('div', { class: 'auth-panel' });
  const channels = config?.channels || { email: false };

  function show(view) {
    panel.replaceChildren(view);
    view.querySelector('input:not([type=hidden])')?.focus();
  }

  // Factor 1 done: either signed in, or a second factor is needed.
  function afterFirst(r) {
    if (r.mfaRequired) return show(secondStepView(r));
    onSignedIn(r);
  }

  function tabs(active) {
    const t = (key, label, go) => h('button', { type: 'button', class: `auth-tab ${active === key ? 'active' : ''}`, onclick: go, 'aria-pressed': String(active === key) }, label);
    return h('div', { class: 'auth-tabs', role: 'group', 'aria-label': 'Choose' },
      t('signin', 'Sign in', () => { history.replaceState(null, '', '#/login'); show(signInView()); }),
      t('signup', 'Create account', () => { history.replaceState(null, '', '#/signup'); show(signUpView()); }));
  }

  // ── Sign in ──
  function signInView(method = 'password') {
    const error = errorBox();
    const methods = h('div', { class: 'seg seg-block', role: 'tablist' });
    const body = h('div', { class: 'stack' });
    const setMethod = (m) => {
      method = m;
      methods.replaceChildren(
        ...[['password', 'Password', 'key'], ['email', 'Email code', 'info']].map(([k, label, ic]) =>
          h('button', { type: 'button', role: 'tab', class: k === method ? 'on' : '', 'aria-selected': String(k === method), onclick: () => setMethod(k) }, icon(ic), label)));
      hideError(error);
      body.replaceChildren(method === 'password' ? passwordForm() : codeStartForm());
      body.querySelector('input')?.focus();
    };

    function passwordForm() {
      const email = h('input', { class: 'input', type: 'email', name: 'email', autocomplete: 'username', required: true, placeholder: 'you@company.com' });
      const password = h('input', { class: 'input', type: 'password', name: 'password', autocomplete: 'current-password', required: true, placeholder: '••••••••••' });
      const submit = h('button', { class: 'btn primary block', type: 'submit' }, icon('lock'), 'Sign in');
      const form = h('form', { class: 'stack', onsubmit: async (e) => {
        e.preventDefault();
        hideError(error);
        submit.disabled = true;
        try {
          afterFirst(await post('/auth/login', { email: email.value, password: password.value }));
        } catch (err) {
          if (err.code === 'EMAIL_NOT_VERIFIED') return show(verifyEmailView(email.value, err.details.ticket, err.details.sentTo));
          showError(error, err);
        } finally {
          submit.disabled = false;
        }
      } },
      h('label', { class: 'field' }, 'Email', email),
      h('label', { class: 'field' }, h('span', { class: 'row' }, h('span', { class: 'grow' }, 'Password'),
        h('a', { href: '#/login', class: 'small', onclick: (e) => { e.preventDefault(); show(forgotView(email.value)); } }, 'Forgot password?')), password),
      submit,
      h('div', { class: 'demo-accounts' },
        h('div', { class: 'hd' }, 'Demo accounts: click to fill'),
        DEMO.map((d) => h('button', { type: 'button', class: 'demo-btn', onclick: () => { email.value = d.email; password.value = d.password; submit.focus(); } },
          avatar(d.name, 'sm'), h('div', { class: 'who' }, h('b', {}, `${d.name} · ${d.label}`), h('span', {}, d.email)), rolePill(d.role)))));
      return form;
    }

    function codeStartForm() {
      if (!channels.email) return h('div', { class: 'note' }, icon('info'), h('div', {}, 'Email sign-in codes are not enabled on this deployment.'));
      const input = h('input', { class: 'input', type: 'email', autocomplete: 'username', required: true, placeholder: 'you@company.com' });
      const submit = h('button', { class: 'btn primary block', type: 'submit' }, icon('upload'), 'Send code');
      return h('form', { class: 'stack', onsubmit: async (e) => {
        e.preventDefault();
        hideError(error);
        submit.disabled = true;
        try {
          const body = { email: input.value };
          const r = await post('/auth/email-code/start', body);
          show(codeEntryView({ ticket: r.ticket, sentTo: r.sentTo, resend: () => post('/auth/email-code/start', body) }));
        } catch (err) {
          showError(error, err);
        } finally {
          submit.disabled = false;
        }
      } },
      h('label', { class: 'field' }, 'Email', input),
      h('p', { class: 'muted small' }, 'We email a 6-digit code that works once, for 10 minutes. No password needed; if you use an authenticator app it is still required.'),
      submit);
    }

    const view = h('div', { class: 'stack' }, tabs('signin'),
      h('div', {}, h('h2', {}, 'Welcome back'), h('p', { class: 'muted' }, 'Choose how you want to sign in.')),
      methods, error, body);
    setMethod(method);
    return view;
  }

  // ── Code entry for passwordless sign-in ──
  function codeEntryView({ ticket, sentTo, resend }) {
    const error = errorBox();
    const code = codeInput();
    const submit = h('button', { class: 'btn primary block', type: 'submit' }, 'Verify and sign in');
    return h('form', { class: 'stack', onsubmit: async (e) => {
      e.preventDefault();
      hideError(error);
      submit.disabled = true;
      try {
        afterFirst(await post('/auth/email-code/verify', { ticket, code: code.value }));
      } catch (err) {
        showError(error, err);
      } finally {
        submit.disabled = false;
      }
    } },
    h('div', { class: 'mfa-badge' }, icon('info')),
    h('div', {}, h('h2', {}, 'Check your email'),
      h('p', { class: 'muted' }, `If an account matches, we sent a 6-digit code to ${sentTo}. It expires in 10 minutes and works once.`)),
    error, h('label', { class: 'field' }, '6-digit code', code), submit,
    h('div', { class: 'row wrap' }, resendButton(async () => { ticket = (await resend()).ticket; }),
      h('button', { type: 'button', class: 'btn ghost sm', onclick: () => show(signInView('email')) }, 'Use a different address')));
  }

  // ── Second factor ──
  function secondStepView(r) {
    const error = errorBox();
    const mfaToken = r.mfaToken;
    let useRecovery = false;
    const input = codeInput();
    const label = h('span', {}, '6-digit code from your authenticator app');
    const submit = h('button', { class: 'btn primary block', type: 'submit' }, 'Verify');
    const toggle = h('button', { type: 'button', class: 'btn ghost sm', onclick: () => {
      useRecovery = !useRecovery;
      label.textContent = useRecovery ? 'Recovery code (e.g. 7KQ4-M2XD)' : '6-digit code from your authenticator app';
      input.setAttribute('inputmode', useRecovery ? 'text' : 'numeric');
      input.setAttribute('maxlength', useRecovery ? '9' : '7');
      input.setAttribute('placeholder', useRecovery ? 'XXXX-XXXX' : '123 456');
      toggle.textContent = useRecovery ? 'Use authenticator code instead' : 'Lost your phone? Use a recovery code';
      input.value = '';
      input.focus();
    } }, 'Lost your phone? Use a recovery code');
    return h('form', { class: 'stack', onsubmit: async (e) => {
      e.preventDefault();
      hideError(error);
      submit.disabled = true;
      try {
        onSignedIn(await post('/auth/mfa', useRecovery ? { mfaToken, recoveryCode: input.value } : { mfaToken, code: input.value.replace(/\s/g, '') }));
      } catch (err) {
        showError(error, err);
        if (/again/i.test(err.message)) setTimeout(() => show(signInView()), 1800);
      } finally {
        submit.disabled = false;
      }
    } },
    h('div', { class: 'mfa-badge' }, icon('shield')),
    h('div', {}, h('h2', {}, 'Two-factor sign-in'), h('p', { class: 'muted' }, 'First step done. Enter the code from your authenticator app to finish signing in.')),
    error, h('label', { class: 'field' }, label, input), submit,
    h('div', { class: 'row wrap' }, toggle, h('button', { type: 'button', class: 'btn ghost sm', onclick: () => show(signInView()) }, 'Start over')));
  }

  // ── Create account ──
  function signUpView() {
    if (!channels.email) {
      return h('div', { class: 'stack' }, tabs('signup'),
        h('div', {}, h('h2', {}, 'Create your account')),
        h('div', { class: 'note' }, icon('info'), h('div', {}, 'Self sign-up verifies your email with a one-time code, and email delivery is not configured on this deployment yet, so sign-up is switched off rather than failing. Use a demo account, or ask an administrator to add you.')));
    }
    const error = errorBox();
    const name = h('input', { class: 'input', autocomplete: 'name', required: true, maxlength: '100', placeholder: 'Priya Shah' });
    const email = h('input', { class: 'input', type: 'email', autocomplete: 'email', required: true, placeholder: 'you@company.com' });
    const password = h('input', { class: 'input', type: 'password', autocomplete: 'new-password', required: true, minlength: String(config?.passwordMinLength || 12) });
    const confirm = h('input', { class: 'input', type: 'password', autocomplete: 'new-password', required: true });
    const submit = h('button', { class: 'btn primary block', type: 'submit' }, icon('user'), 'Create account');
    return h('form', { class: 'stack', onsubmit: async (e) => {
      e.preventDefault();
      hideError(error);
      if (password.value !== confirm.value) return showError(error, new Error('The passwords do not match'));
      submit.disabled = true;
      try {
        const r = await post('/auth/signup', { name: name.value, email: email.value, password: password.value });
        show(verifyEmailView(email.value, r.ticket, r.sentTo));
      } catch (err) {
        showError(error, err);
      } finally {
        submit.disabled = false;
      }
    } },
    tabs('signup'),
    h('div', {}, h('h2', {}, 'Create your account'), h('p', { class: 'muted' }, 'New accounts can open documents shared with them. An administrator can make you an owner so you can upload.')),
    error,
    h('label', { class: 'field' }, 'Full name', name),
    h('label', { class: 'field' }, 'Work email', email),
    h('label', { class: 'field' }, 'Password', password),
    strengthMeter(password, () => ({ email: email.value, name: name.value })),
    h('label', { class: 'field' }, 'Confirm password', confirm),
    submit,
    h('div', { class: 'note' }, icon('shield'), h('div', {}, 'We verify your email with a one-time code before the account works. Your password is hashed with scrypt; we never store it.')));
  }

  function verifyEmailView(emailValue, ticket, sentTo) {
    const error = errorBox();
    const code = codeInput();
    const submit = h('button', { class: 'btn primary block', type: 'submit' }, 'Verify email');
    return h('form', { class: 'stack', onsubmit: async (e) => {
      e.preventDefault();
      hideError(error);
      submit.disabled = true;
      try {
        const r = await post('/auth/signup/verify', { ticket, code: code.value });
        toast('Email verified. Welcome to TrustVault.');
        afterFirst(r);
      } catch (err) {
        showError(error, err);
      } finally {
        submit.disabled = false;
      }
    } },
    h('div', { class: 'mfa-badge' }, icon('check')),
    h('div', {}, h('h2', {}, 'Confirm your email'), h('p', { class: 'muted' }, `We sent a 6-digit code to ${sentTo}. Check spam if you cannot see it. It expires in 10 minutes.`)),
    error, h('label', { class: 'field' }, '6-digit code', code), submit,
    h('div', { class: 'row wrap' }, resendButton(async () => { ticket = (await post('/auth/signup/resend', { email: emailValue })).ticket; }),
      h('button', { type: 'button', class: 'btn ghost sm', onclick: () => show(signInView()) }, 'Back to sign in')));
  }

  // ── Forgot password ──
  function forgotView(prefill = '') {
    const error = errorBox();
    const email = h('input', { class: 'input', type: 'email', autocomplete: 'username', required: true, value: prefill, placeholder: 'you@company.com' });
    const submit = h('button', { class: 'btn primary block', type: 'submit' }, 'Email me a reset code');
    return h('form', { class: 'stack', onsubmit: async (e) => {
      e.preventDefault();
      hideError(error);
      submit.disabled = true;
      try {
        const r = await post('/auth/password-reset/start', { email: email.value });
        show(resetView(email.value, r.ticket, r.sentTo));
      } catch (err) {
        showError(error, err);
      } finally {
        submit.disabled = false;
      }
    } },
    h('div', { class: 'mfa-badge' }, icon('key')),
    h('div', {}, h('h2', {}, 'Reset your password'), h('p', { class: 'muted' }, 'We email a one-time code. Resetting signs out every session on the account, and your two-factor sign-in stays on.')),
    error, h('label', { class: 'field' }, 'Email', email), submit,
    channels.email ? null : h('div', { class: 'note' }, icon('info'), h('div', {}, 'Email delivery is not configured on this deployment; ask an administrator to reset your password.')),
    h('button', { type: 'button', class: 'btn ghost sm', onclick: () => show(signInView()) }, 'Back to sign in'));
  }

  function resetView(emailValue, ticket, sentTo) {
    const error = errorBox();
    const code = codeInput();
    const password = h('input', { class: 'input', type: 'password', autocomplete: 'new-password', required: true });
    const submit = h('button', { class: 'btn primary block', type: 'submit' }, 'Set new password');
    return h('form', { class: 'stack', onsubmit: async (e) => {
      e.preventDefault();
      hideError(error);
      submit.disabled = true;
      try {
        await post('/auth/password-reset/complete', { ticket, code: code.value, newPassword: password.value });
        toast('Password changed. Every other session was signed out. Sign in with your new password.');
        show(signInView());
      } catch (err) {
        showError(error, err);
      } finally {
        submit.disabled = false;
      }
    } },
    h('div', { class: 'mfa-badge' }, icon('key')),
    h('div', {}, h('h2', {}, 'Choose a new password'), h('p', { class: 'muted' }, `If an account matches, a code was sent to ${sentTo}.`)),
    error, h('label', { class: 'field' }, '6-digit code', code), h('label', { class: 'field' }, 'New password', password),
    strengthMeter(password, () => ({ email: emailValue })), submit,
    h('div', { class: 'row wrap' }, resendButton(async () => { ticket = (await post('/auth/password-reset/start', { email: emailValue })).ticket; }),
      h('button', { type: 'button', class: 'btn ghost sm', onclick: () => show(signInView()) }, 'Back to sign in')));
  }

  // ── Layout ──
  const pillar = (ic, title, text) => h('div', { class: 'pillar' }, h('div', { class: 'pi' }, icon(ic)), h('div', {}, h('b', {}, title), h('span', {}, text)));
  root.className = '';
  root.replaceChildren(h('div', { class: 'login' },
    h('section', { class: 'login-art' },
      h('div', { class: 'brand' }, h('div', { class: 'brand-mark' }, icon('shield')), 'TrustVault'),
      h('div', {},
        h('h1', {}, 'Share confidential documents. ', h('span', {}, 'Prove who opened them.')),
        h('p', { class: 'lede' }, 'Per-document permissions checked by the server on every request, instant revocation, and a tamper-evident record of every access, including the ones that were refused.'),
        securityBadges()),
      h('div', { class: 'pillars' },
        pillar('lock', 'Only named people', 'Access is granted per document, to a person, with read or edit, and an optional expiry.'),
        pillar('shield', 'Strong sign-in', 'Verified email, one-time codes, authenticator apps as a second factor, and rate limits on every guess.'),
        pillar('history', 'Evidence, not logs', 'An append-only, HMAC-chained audit trail. Any edit or deletion is detected.')),
      h('div', { class: 'foot' }, 'TrustVault · RISE hiring challenge 2026')),
    h('section', { class: 'login-form-wrap' }, h('div', { class: 'login-form' }, panel))));
  show(mode === 'signup' ? signUpView() : signInView());
}
