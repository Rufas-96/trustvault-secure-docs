// DOM helpers. Everything is built with createElement + textContent, never innerHTML,
// so a document title like <img onerror=...> is shown as text, not executed.

export function h(tag, attrs = {}, ...children) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v === undefined || v === null || v === false) continue;
    if (k === 'class') el.className = v;
    else if (k.startsWith('on') && typeof v === 'function') el.addEventListener(k.slice(2).toLowerCase(), v);
    else if (k === 'dataset') Object.assign(el.dataset, v);
    else if (k in el && typeof v !== 'string') el[k] = v;
    else el.setAttribute(k, v === true ? '' : String(v));
  }
  append(el, children);
  return el;
}

function append(el, children) {
  for (const c of children.flat(Infinity)) {
    if (c === null || c === undefined || c === false) continue;
    el.append(c instanceof Node ? c : document.createTextNode(String(c)));
  }
}

const ICONS = {
  shield: 'M12 3l8 3v6c0 4.97-3.4 9.3-8 10.5C7.4 21.3 4 16.97 4 12V6l8-3z',
  lock: 'M6 11h12v10H6zM8.5 11V7.5a3.5 3.5 0 017 0V11',
  files: 'M14 3H7a2 2 0 00-2 2v14a2 2 0 002 2h10a2 2 0 002-2V8l-5-5zM14 3v5h5',
  folder: 'M3 7a2 2 0 012-2h4l2 2h8a2 2 0 012 2v8a2 2 0 01-2 2H5a2 2 0 01-2-2z',
  share: 'M16 6a3 3 0 100 .01M6 12a3 3 0 100 .01M16 18a3 3 0 100 .01M8.6 13.5l4.8 3M13.4 7.5l-4.8 3',
  users: 'M16 19v-1a4 4 0 00-4-4H6a4 4 0 00-4 4v1M9 10a3.5 3.5 0 100-7 3.5 3.5 0 000 7zM22 19v-1a4 4 0 00-3-3.87M16 3.13a4 4 0 010 7.75',
  trash: 'M4 7h16M10 11v6M14 11v6M5 7l1 13h12l1-13M9 7V4h6v3',
  upload: 'M12 16V4M7 9l5-5 5 5M4 20h16',
  download: 'M12 4v12M7 11l5 5 5-5M4 20h16',
  search: 'M11 18a7 7 0 100-14 7 7 0 000 14zM20 20l-3.5-3.5',
  activity: 'M3 12h4l3-8 4 16 3-8h4',
  list: 'M8 6h13M8 12h13M8 18h13M3 6h.01M3 12h.01M3 18h.01',
  gauge: 'M12 14l4-4M3.5 18a9 9 0 1117 0',
  logout: 'M15 4h3a2 2 0 012 2v12a2 2 0 01-2 2h-3M10 16l-4-4 4-4M6 12h11',
  plus: 'M12 5v14M5 12h14',
  x: 'M6 6l12 12M18 6L6 18',
  check: 'M5 12.5l4.5 4.5L19 7',
  alert: 'M12 9v4M12 17h.01M10.3 3.9L2.4 18a2 2 0 001.7 3h15.8a2 2 0 001.7-3L13.7 3.9a2 2 0 00-3.4 0z',
  eye: 'M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7S2 12 2 12zM12 15a3 3 0 100-6 3 3 0 000 6z',
  edit: 'M4 20h4L19 9l-4-4L4 16v4zM13.5 6.5l4 4',
  restore: 'M3 12a9 9 0 109-9 9.7 9.7 0 00-6.7 2.8L3 8M3 3v5h5',
  key: 'M15 7a4 4 0 11-3.9 4.9L3 20v-3h3v-3h3l2.1-2.1A4 4 0 0115 7z',
  menu: 'M4 6h16M4 12h16M4 18h16',
  history: 'M3 12a9 9 0 109-9 9.7 9.7 0 00-6.7 2.8L3 8M3 3v5h5M12 7v5l3 3',
  link: 'M10 14a5 5 0 007.07 0l3-3a5 5 0 00-7.07-7.07l-1 1M14 10a5 5 0 00-7.07 0l-3 3a5 5 0 007.07 7.07l1-1',
  info: 'M12 16v-4M12 8h.01M12 21a9 9 0 100-18 9 9 0 000 18z',
  transfer: 'M7 7h13l-4-4M17 17H4l4 4',
  user: 'M20 21v-2a4 4 0 00-4-4H8a4 4 0 00-4 4v2M12 11a4 4 0 100-8 4 4 0 000 8z',
};

export function icon(name, cls = '') {
  const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
  svg.setAttribute('viewBox', '0 0 24 24');
  svg.setAttribute('class', `icon ${cls}`.trim());
  svg.setAttribute('aria-hidden', 'true');
  const path = document.createElementNS('http://www.w3.org/2000/svg', 'path');
  path.setAttribute('d', ICONS[name] || ICONS.info);
  svg.append(path);
  return svg;
}

export function toast(message, kind = 'ok') {
  const t = h('div', { class: `toast ${kind}`, role: kind === 'error' ? 'alert' : 'status' }, icon(kind === 'error' ? 'alert' : 'check'), h('div', {}, message));
  document.getElementById('toasts').append(t);
  setTimeout(() => t.remove(), kind === 'error' ? 6000 : 3500);
}

/** Open a modal. `build(close)` returns { title, body, footer }. Resolves when closed. */
export function modal(build) {
  return new Promise((resolve) => {
    const backdrop = h('div', { class: 'modal-backdrop' });
    const close = (value) => {
      backdrop.remove();
      document.removeEventListener('keydown', onKey);
      resolve(value);
    };
    const onKey = (e) => e.key === 'Escape' && close();
    const { title, subtitle, body, footer } = build(close);
    const box = h('div', { class: 'modal', role: 'dialog', 'aria-modal': 'true', 'aria-label': title },
      h('div', { class: 'modal-head' },
        h('div', { class: 'grow' }, h('h2', {}, title), subtitle ? h('p', { class: 'muted small' }, subtitle) : null),
        h('button', { class: 'btn ghost sm', 'aria-label': 'Close', onclick: () => close() }, icon('x'))),
      h('div', { class: 'modal-body' }, body),
      footer ? h('div', { class: 'modal-foot' }, footer) : null);
    backdrop.addEventListener('mousedown', (e) => e.target === backdrop && close());
    document.addEventListener('keydown', onKey);
    backdrop.append(box);
    document.body.append(backdrop);
    box.querySelector('input, select, textarea, button.primary')?.focus();
  });
}

export function confirmDialog({ title, text, confirm = 'Confirm', danger = false }) {
  return modal((close) => ({
    title,
    body: h('p', { class: 'muted' }, text),
    footer: [
      h('button', { class: 'btn', onclick: () => close(false) }, 'Cancel'),
      h('button', { class: `btn ${danger ? 'danger' : 'primary'}`, onclick: () => close(true) }, confirm),
    ],
  }));
}

export function initials(name = '') {
  return name.replace(/\(.*\)/, '').trim().split(/\s+/).slice(0, 2).map((p) => p[0]?.toUpperCase() || '').join('') || '?';
}

export function avatar(name, cls = '') {
  return h('div', { class: `avatar ${cls}`, 'aria-hidden': 'true' }, initials(name));
}

export function fmtDate(v) {
  if (!v) return '';
  return new Date(v).toLocaleDateString(undefined, { day: 'numeric', month: 'short', year: 'numeric' });
}

export function fmtDateTime(v) {
  if (!v) return '';
  return new Date(v).toLocaleString(undefined, { day: 'numeric', month: 'short', hour: '2-digit', minute: '2-digit', second: '2-digit' });
}

export function fmtAgo(v) {
  const s = (Date.now() - new Date(v).getTime()) / 1000;
  if (s < 60) return 'just now';
  if (s < 3600) return `${Math.floor(s / 60)} min ago`;
  if (s < 86400) return `${Math.floor(s / 3600)} h ago`;
  if (s < 86400 * 7) return `${Math.floor(s / 86400)} d ago`;
  return fmtDate(v);
}

export function fmtSize(bytes) {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / 1024 / 1024).toFixed(1)} MB`;
}

export function fileIcon(filename = '') {
  const ext = filename.split('.').pop().toLowerCase();
  const map = { pdf: 'pdf', png: 'img', jpg: 'img', jpeg: 'img', txt: 'txt', md: 'txt', csv: 'sheet', xlsx: 'sheet', docx: 'doc', pptx: 'ppt' };
  return h('div', { class: `file-icon ${map[ext] || 'txt'}`, 'aria-hidden': 'true' }, ext.slice(0, 4).toUpperCase());
}

export function accessPill(level) {
  const label = { owner: 'Owner', edit: 'Can edit', read: 'Can view' }[level] || level;
  return h('span', { class: `pill ${level}` }, h('span', { class: 'dot' }), label);
}

export function rolePill(role) {
  return h('span', { class: `pill ${role}` }, role[0].toUpperCase() + role.slice(1));
}

export function outcomePill(outcome) {
  return h('span', { class: `pill ${outcome}` }, h('span', { class: 'dot' }), outcome === 'ok' ? 'Allowed' : outcome === 'denied' ? 'Refused' : 'Error');
}

const ACTION_LABELS = {
  'document.upload': 'Uploaded',
  'document.download': 'Downloaded',
  'document.view': 'Opened',
  'document.edit': 'Edited details',
  'document.new_version': 'Uploaded a new version',
  'document.delete': 'Moved to trash',
  'document.restore': 'Restored from trash',
  'document.transfer': 'Ownership transferred',
  'document.share': 'Tried to share',
  'document.list-versions': 'Listed versions',
  'document.upload-version': 'Tried to upload a version',
  'document.view-grants': 'Tried to view sharing',
  'document.view-activity': 'Tried to view activity',
  'permission.grant': 'Granted access',
  'permission.change': 'Changed access',
  'permission.revoke': 'Revoked access',
  'auth.login': 'Signed in',
  'auth.logout': 'Signed out',
  'user.create': 'Created user',
  'user.disable': 'Disabled user',
  'user.enable': 'Enabled user',
  'user.role_change': 'Changed role',
  'role.check': 'Tried a restricted page',
  'server.error': 'Server error',
};

export function actionLabel(action, outcome) {
  const base = ACTION_LABELS[action] || action;
  if (outcome === 'denied' && action === 'auth.login') return 'Failed sign-in';
  if (outcome === 'denied' && action.startsWith('document.') && !base.startsWith('Tried')) return `Tried: ${base.toLowerCase()}`;
  return base;
}
