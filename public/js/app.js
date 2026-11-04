// App entry: session bootstrap, hash router, sign-in page and the app shell.
import { h, icon, avatar, rolePill, toast } from './ui.js';
import { get, post, setCsrf, setGateHandler, setUnauthorizedHandler, lastRequestAt } from './api.js';
import { documentsPage, documentDetailPage, trashPage, uploadDialog } from './views/documents.js';
import { enhance, installRipple, mountFab, mountSecurityOrb } from './fx.js';
import { adminOverviewPage, adminAuditPage, adminUsersPage, adminDocumentsPage } from './views/admin.js';
import { accountPage } from './views/account.js';
import { renderAuthPage } from './views/auth.js';

export const state = { user: null, config: null };
const root = document.getElementById('app');

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
  { re: /^#\/account$/, nav: 'account', render: () => accountPage() },
];

// A user who must change their password, or an admin without two-factor, can only reach
// the account page. (The server enforces the same rule; this just avoids dead-end pages.)
const isGated = (u) => u.mustChangePassword || (u.mfaRequired && !u.mfaEnabled);

export async function refreshUser() {
  const me = await get('/me');
  state.user = me.user;
  setCsrf(me.csrfToken);
}

const homeFor = (user) => (user.role === 'admin' ? '#/admin' : '#/documents');

export function navigate(hash) {
  if (location.hash === hash) render();
  else location.hash = hash;
}

async function render() {
  if (!state.user) return renderLogin();
  if (isGated(state.user) && location.hash !== '#/account') {
    location.replace('#/account');
    return;
  }
  const route = routes.find((r) => r.re.test(location.hash));
  if (!route || (route.roles && !route.roles.includes(state.user.role))) {
    location.replace(homeFor(state.user));
    return;
  }
  const page = h('main', { class: 'page', id: 'page' });
  renderShell(route.nav, page);
  try {
    page.append(await route.render(location.hash.match(route.re)));
    enhance(page);
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
  sections.push(h('nav', { class: 'nav', 'aria-label': 'Account' },
    h('div', { class: 'nav-label' }, 'Account'),
    link('account', '#/account', 'lock', 'Account security')));

  const shell = h('div', { class: 'shell' });
  const closeNav = () => shell.classList.remove('nav-open');
  const sidebar = h('aside', { class: 'sidebar', onclick: (e) => e.target.closest('a') && closeNav() },
    h('div', { class: 'brand' }, h('div', { class: 'brand-mark' }, icon('shield')), 'TrustVault'),
    sections,
    h('div', { class: 'me' }, avatar(u.name),
      h('div', { class: 'who' }, h('b', {}, u.name), h('span', {}, `${u.role[0].toUpperCase()}${u.role.slice(1)}${u.department ? ` · ${u.department}` : ''}`)),
      h('button', { class: 'btn ghost sm', title: 'Sign out', 'aria-label': 'Sign out', onclick: signOut }, icon('logout'))));

  const topbar = h('div', { class: 'topbar' },
    h('button', { class: 'btn ghost sm', 'aria-label': 'Menu', onclick: () => shell.classList.toggle('nav-open') }, icon('menu')),
    h('div', { class: 'brand grow' }, 'TrustVault'), rolePill(u.role));

  shell.append(sidebar, h('div', { class: 'main' }, topbar, page));
  root.className = '';
  root.replaceChildren(shell);
  mountFab(quickActions(u));
  mountSecurityOrb({ user: u, idleMinutes: state.config?.sessionIdleMinutes || 30, lastRequestAt: () => lastRequestAt, onAccount: () => navigate('#/account') });
}

// Floating quick actions. Convenience only: every action still goes through the server's checks.
function quickActions(u) {
  const go = (hash) => () => navigate(hash);
  const focusSearch = () => {
    const open = () => document.querySelector('.filters input[type=search]')?.focus();
    if (/^#\/(documents|mine|shared)$/.test(location.hash)) open();
    else { navigate('#/documents'); setTimeout(open, 400); }
  };
  if (u.role === 'admin') {
    return [
      { icon: 'activity', label: 'Audit trail', onClick: go('#/admin/audit') },
      { icon: 'users', label: 'People', onClick: go('#/admin/users') },
      { icon: 'files', label: 'Documents', onClick: go('#/admin/documents') },
      { icon: 'lock', label: 'Account security', onClick: go('#/account') },
    ];
  }
  const actions = [];
  if (u.role === 'owner') actions.push({ icon: 'upload', label: 'Upload document', onClick: () => uploadDialog().then((doc) => doc && navigate(`#/documents/${doc.id}`)) });
  actions.push(
    { icon: 'search', label: 'Search documents', onClick: focusSearch },
    { icon: 'share', label: 'Shared with me', onClick: go('#/shared') },
    { icon: 'lock', label: 'Account security', onClick: go('#/account') },
  );
  return actions;
}

// ── Sign-in / sign-up ────────────────────────────────────────────────────────
function renderLogin() {
  const h0 = location.hash;
  if (h0 && h0 !== '#/login' && h0 !== '#/signup') sessionStorage.setItem('tv_after_login', h0);
  const mode = h0 === '#/signup' ? 'signup' : 'signin';
  history.replaceState(null, '', mode === 'signup' ? '#/signup' : '#/login');
  renderAuthPage(root, { mode, config: state.config, onSignedIn: finishLogin });
}

function finishLogin(r) {
  setCsrf(r.csrfToken);
  state.user = r.user;
  // Show the previous sign-in, so an unexpected one is noticed straight away.
  const last = r.lastSignIn;
  if (last && last.at) {
    const when = new Date(last.at).toLocaleString(undefined, { day: 'numeric', month: 'short', hour: '2-digit', minute: '2-digit' });
    const failed = last.failedSince ? ` · ${last.failedSince} failed attempt${last.failedSince > 1 ? 's' : ''} since` : '';
    toast(`Last sign-in: ${when} from ${last.ip || 'unknown IP'}${failed}`, last.failedSince ? 'error' : 'ok');
  }
  const next = sessionStorage.getItem('tv_after_login');
  sessionStorage.removeItem('tv_after_login');
  navigate(next && next !== '#/login' && next !== '#/signup' ? next : homeFor(r.user));
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

setGateHandler(() => refreshUser().then(() => navigate('#/account')).catch(() => {}));

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

installRipple();
window.addEventListener('hashchange', render);
boot();
