// App entry: session bootstrap, hash router, sign-in page and the app shell.
import { h, icon, avatar, rolePill, toast } from './ui.js';
import { get, post, setCsrf, setUnauthorizedHandler } from './api.js';
import { documentsPage, documentDetailPage, trashPage } from './views/documents.js';
import { adminOverviewPage, adminAuditPage, adminUsersPage, adminDocumentsPage } from './views/admin.js';

export const state = { user: null, config: null };
const root = document.getElementById('app');

const DEMO = [
  { label: 'Administrator', name: 'Ava Administrator', email: 'admin@trustvault.demo', password: 'Admin#Vault2026', role: 'admin' },
  { label: 'Owner · HR', name: 'Olivia Hart', email: 'olivia.owner@trustvault.demo', password: 'Owner#Vault2026', role: 'owner' },
  { label: 'Owner · Legal', name: 'Omar Lewis', email: 'omar.owner@trustvault.demo', password: 'Owner2#Vault2026', role: 'owner' },
  { label: 'Viewer · Employee', name: 'Vik Varma', email: 'vik.viewer@trustvault.demo', password: 'Viewer#Vault2026', role: 'viewer' },
  { label: 'Viewer · External partner', name: 'Vera Patel', email: 'vera.partner@trustvault.demo', password: 'Partner#Vault2026', role: 'viewer' },
];

// ── Routes ───────────────────────────────────────────────────────────────────
const routes = [
  { re: /^#\/documents$/, nav: 'all', render: () => documentsPage({ scope: 'all' }) },
  { re: /^#\/mine$/, nav: 'mine', roles: ['owner'], render: () => documentsPage({ scope: 'mine' }) },
  { re: /^#\/shared$/, nav: 'shared', render: () => documentsPage({ scope: 'shared' }) },
  { re: /^#\/trash$/, nav: 'trash', roles: ['owner'], render: () => trashPage() },
  { re: /^#\/documents\/([0-9a-f-]{36})$/i, nav: 'all', render: (m) => documentDetailPage(m[1]) },
  { re: /^#\/admin$/, nav: 'admin', roles: ['admin'], render: () => adminOverviewPage() },
  { re: /^#\/admin\/audit$/, nav: 'audit', roles: ['admin'], render: () => adminAuditPage() },
  { re: /^#\/admin\/users$/, nav: 'users', roles: ['admin'], render: () => adminUsersPage() },
  { re: /^#\/admin\/documents$/, nav: 'admindocs', roles: ['admin'], render: () => adminDocumentsPage() },
];

const homeFor = (user) => (user.role === 'admin' ? '#/admin' : '#/documents');

export function navigate(hash) {
  if (location.hash === hash) render();
  else location.hash = hash;
}

async function render() {
  if (!state.user) return renderLogin();
  const route = routes.find((r) => r.re.test(location.hash));
  if (!route || (route.roles && !route.roles.includes(state.user.role))) {
    location.replace(homeFor(state.user));
    return;
  }
  const page = h('main', { class: 'page', id: 'page' });
  renderShell(route.nav, page);
  try {
    page.append(await route.render(location.hash.match(route.re)));
  } catch (err) {
    page.append(h('div', { class: 'card empty' }, icon('alert'), h('b', {}, err.status === 404 ? 'Not found' : 'Something went wrong'),
      h('p', {}, err.status === 404 ? 'This document does not exist, or you do not have access to it.' : err.message),
      h('a', { class: 'btn', href: homeFor(state.user) }, 'Back to documents')));
  }
}

// ── Shell ────────────────────────────────────────────────────────────────────
function renderShell(active, page) {
  const u = state.user;
  const link = (key, hash, ic, label) => h('a', { href: hash, class: active === key ? 'active' : '' }, icon(ic), label);
  const sections = [];
  if (u.role !== 'admin') {
    sections.push(h('nav', { class: 'nav', 'aria-label': 'Documents' },
      h('div', { class: 'nav-label' }, 'Documents'),
      link('all', '#/documents', 'files', 'All documents'),
      u.role === 'owner' ? link('mine', '#/mine', 'folder', 'My documents') : null,
      link('shared', '#/shared', 'share', 'Shared with me'),
      u.role === 'owner' ? link('trash', '#/trash', 'trash', 'Trash') : null));
  } else {
    sections.push(h('nav', { class: 'nav', 'aria-label': 'Administration' },
      h('div', { class: 'nav-label' }, 'Administration'),
      link('admin', '#/admin', 'gauge', 'Overview'),
      link('audit', '#/admin/audit', 'activity', 'Audit trail'),
      link('admindocs', '#/admin/documents', 'files', 'Documents'),
      link('users', '#/admin/users', 'users', 'People')));
  }

  const shell = h('div', { class: 'shell' });
  const closeNav = () => shell.classList.remove('nav-open');
  const sidebar = h('aside', { class: 'sidebar', onclick: (e) => e.target.closest('a') && closeNav() },
    h('div', { class: 'brand' }, h('div', { class: 'brand-mark' }, icon('shield')), 'TrustVault'),
    sections,
    h('div', { class: 'me' }, avatar(u.name),
      h('div', { class: 'who' }, h('b', {}, u.name), h('span', {}, `${u.role[0].toUpperCase()}${u.role.slice(1)} · ${u.department || ''}`)),
      h('button', { class: 'btn ghost sm', title: 'Sign out', 'aria-label': 'Sign out', onclick: signOut }, icon('logout'))));

  const topbar = h('div', { class: 'topbar' },
    h('button', { class: 'btn ghost sm', 'aria-label': 'Menu', onclick: () => shell.classList.toggle('nav-open') }, icon('menu')),
    h('div', { class: 'brand grow' }, 'TrustVault'), rolePill(u.role));

  shell.append(sidebar, h('div', { class: 'main' }, topbar, page));
  root.className = '';
  root.replaceChildren(shell);
}

// ── Sign-in ──────────────────────────────────────────────────────────────────
function renderLogin() {
  if (location.hash && location.hash !== '#/login') sessionStorage.setItem('tv_after_login', location.hash);
  history.replaceState(null, '', '#/login');

  const email = h('input', { class: 'input', type: 'email', name: 'email', autocomplete: 'username', required: true, placeholder: 'you@company.com' });
  const password = h('input', { class: 'input', type: 'password', name: 'password', autocomplete: 'current-password', required: true, placeholder: '••••••••••' });
  const error = h('div', { class: 'form-error hidden', role: 'alert' });
  const submit = h('button', { class: 'btn primary block', type: 'submit' }, 'Sign in');

  const form = h('form', { class: 'login-form', onsubmit: async (e) => {
    e.preventDefault();
    error.classList.add('hidden');
    submit.disabled = true;
    try {
      const r = await post('/auth/login', { email: email.value, password: password.value });
      setCsrf(r.csrfToken);
      state.user = r.user;
      const next = sessionStorage.getItem('tv_after_login');
      sessionStorage.removeItem('tv_after_login');
      navigate(next && next !== '#/login' ? next : homeFor(r.user));
    } catch (err) {
      error.textContent = err.message;
      error.classList.remove('hidden');
    } finally {
      submit.disabled = false;
    }
  } },
    h('div', {}, h('h2', {}, 'Sign in'), h('p', { class: 'muted' }, 'Use your company account, or one of the demo accounts below.')),
    error,
    h('label', { class: 'field' }, 'Email', email),
    h('label', { class: 'field' }, 'Password', password),
    submit,
    h('div', { class: 'demo-accounts' },
      h('div', { class: 'hd' }, 'Demo accounts: click to fill'),
      DEMO.map((d) => h('button', { type: 'button', class: 'demo-btn', onclick: () => { email.value = d.email; password.value = d.password; submit.focus(); } },
        avatar(d.name, 'sm'),
        h('div', { class: 'who' }, h('b', {}, `${d.name} · ${d.label}`), h('span', {}, d.email)), rolePill(d.role)))));

  const pillar = (ic, title, text) => h('div', { class: 'pillar' }, h('div', { class: 'pi' }, icon(ic)), h('div', {}, h('b', {}, title), h('span', {}, text)));
  root.className = '';
  root.replaceChildren(h('div', { class: 'login' },
    h('section', { class: 'login-art' },
      h('div', { class: 'brand' }, h('div', { class: 'brand-mark' }, icon('shield')), 'TrustVault'),
      h('div', {},
        h('h1', {}, 'Share confidential documents. ', h('span', {}, 'Prove who opened them.')),
        h('p', { class: 'lede' }, 'Per-document permissions checked by the server on every request, instant revocation, and a tamper-evident record of every access, including the ones that were refused.')),
      h('div', { class: 'pillars' },
        pillar('lock', 'Only named people', 'Access is granted per document, to a person, with read or edit, and an optional expiry.'),
        pillar('restore', 'Revocation is immediate', 'No links or tokens that outlive a revoke. The next request is refused.'),
        pillar('history', 'Evidence, not logs', 'An append-only, HMAC-chained audit trail. Any edit or deletion is detected.')),
      h('div', { class: 'foot' }, 'TrustVault · RISE hiring challenge 2026')),
    h('section', { class: 'login-form-wrap' }, form)));
  email.focus();
}

async function signOut() {
  try {
    await post('/auth/logout');
  } catch { /* already signed out */ }
  state.user = null;
  setCsrf('');
  location.hash = '#/login';
  render();
}

setUnauthorizedHandler(() => {
  if (!state.user) return;
  state.user = null;
  toast('Your session has ended. Please sign in again.', 'error');
  render();
});

// ── Boot ─────────────────────────────────────────────────────────────────────
async function boot() {
  try {
    state.config = await get('/config');
    const me = await get('/session');
    state.user = me.user;
    setCsrf(me.csrfToken);
  } catch {
    state.user = null;
  }
  if (state.user && (!location.hash || location.hash === '#/login')) location.replace(homeFor(state.user));
  render();
}

window.addEventListener('hashchange', render);
boot();
