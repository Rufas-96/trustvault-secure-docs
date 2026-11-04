// Administrator views: overview with alerts, audit trail, people, document metadata.
import { h, icon, toast, modal, confirmDialog, avatar, fmtDateTime, fmtAgo, rolePill, outcomePill, actionLabel } from '../ui.js';
import { get, post, patch } from '../api.js';
import { navigate } from '../app.js';

function chainBanner(chain) {
  return chain.ok
    ? h('div', { class: 'chain ok' }, icon('shield'), h('div', {}, h('b', {}, 'Audit trail intact'), h('p', {}, `All ${chain.checked} entries verified against their HMAC chain. Nothing has been edited, removed or inserted.`)))
    : h('div', { class: 'chain bad' }, icon('alert'), h('div', {}, h('b', {}, `Audit trail TAMPERED at entry #${chain.brokenAt}`), h('p', {}, chain.reason)));
}

// ── Overview ─────────────────────────────────────────────────────────────────
export async function adminOverviewPage() {
  const [{ counts, alerts, chain }, recent] = await Promise.all([get('/admin/overview'), get('/admin/audit?outcome=denied')]);
  const stat = (label, value, ic, alert) => h('div', { class: `card stat ${alert ? 'alert' : ''}` }, h('div', { class: 'label' }, icon(ic), label), h('div', { class: 'value' }, String(value)));
  return h('div', { class: 'stack' },
    h('div', { class: 'page-head' }, h('div', { class: 'titles' }, h('h1', {}, 'Security overview'), h('p', {}, 'What is happening across TrustVault, and what deserves a closer look.'))),
    chainBanner(chain),
    h('div', { class: 'stats' },
      stat('Active people', counts.active_users, 'users'),
      stat('Documents', counts.documents, 'files'),
      stat('Live grants', counts.live_grants, 'key'),
      stat('Downloads (24h)', counts.downloads_24h, 'download'),
      stat('Refused (24h)', counts.denied_24h, 'alert', counts.denied_24h > 0)),
    h('div', { class: 'card' },
      h('div', { class: 'card-head' }, h('div', { class: 'grow' }, h('h3', {}, 'Worth noticing'), h('p', {}, 'Probing, bulk downloads, repeated failed sign-ins, grants held by disabled accounts, orphaned documents.'))),
      alerts.length
        ? h('div', { class: 'alert-list' }, alerts.map((a) => h('div', { class: 'alert-row' }, h('span', { class: `pill ${a.level}` }, a.level), h('div', {}, a.text))))
        : h('div', { class: 'empty' }, icon('check'), h('b', {}, 'Nothing unusual right now'))),
    h('div', { class: 'card' },
      h('div', { class: 'card-head' }, h('div', { class: 'grow' }, h('h3', {}, 'Recent refused attempts'), h('p', {}, 'Every time the server said no.')), h('a', { class: 'btn sm', href: '#/admin/audit' }, 'Open audit trail')),
      auditTable(recent.entries.slice(0, 12))));
}

// ── Audit trail ──────────────────────────────────────────────────────────────
function auditTable(entries) {
  if (!entries.length) return h('div', { class: 'empty' }, icon('activity'), h('b', {}, 'No entries'));
  return h('div', { class: 'table-wrap' }, h('table', {},
    h('thead', {}, h('tr', {}, h('th', {}, '#'), h('th', {}, 'When'), h('th', {}, 'Who'), h('th', {}, 'What'), h('th', {}, 'Result'), h('th', {}, 'Document / target'), h('th', {}, 'Details'))),
    h('tbody', {}, entries.map((e) => h('tr', {},
      h('td', { class: 'mono muted' }, String(e.seq)),
      h('td', { class: 'small nowrap', title: e.at }, fmtDateTime(e.at)),
      h('td', {}, h('div', {}, e.actor_email || 'system'), h('div', { class: 'small muted' }, e.ip || '')),
      h('td', {}, actionLabel(e.action, e.outcome), h('div', { class: 'small muted mono' }, e.action)),
      h('td', {}, outcomePill(e.outcome)),
      h('td', { class: 'small' }, e.document_title || (e.document_id ? h('span', { class: 'mono' }, e.document_id.slice(0, 8)) : ''), e.target_email ? h('div', { class: 'muted' }, `→ ${e.target_email}`) : null),
      h('td', {}, h('div', { class: 'details-json', title: JSON.stringify(e.details) }, JSON.stringify(e.details)), h('div', { class: 'hash', title: e.hash }, `hmac ${e.hash.slice(0, 16)}…`)))))));
}

export async function adminAuditPage() {
  const actor = h('input', { class: 'input', type: 'search', placeholder: 'Who (email)' });
  const action = h('select', {}, [['', 'All actions'], ['document.download', 'Downloads'], ['document.upload', 'Uploads'], ['document.edit', 'Edits'], ['document.new_version', 'New versions'], ['document.delete', 'Deletions'], ['permission.', 'Permission changes'], ['auth.login', 'Sign-ins'], ['user.', 'User management']].map(([v, l]) => h('option', { value: v }, l)));
  const outcome = h('select', {}, [['', 'Any result'], ['ok', 'Allowed'], ['denied', 'Refused'], ['error', 'Error']].map(([v, l]) => h('option', { value: v }, l)));
  const body = h('div', {});
  const banner = h('div', {});
  let oldest = null;
  let docFilter = sessionStorage.getItem('tv_audit_doc');
  sessionStorage.removeItem('tv_audit_doc');
  const docChip = h('div', { class: docFilter ? 'row' : 'hidden' }, h('span', { class: 'pill owner' }, 'Filtered to one document'),
    h('button', { class: 'btn ghost sm', onclick: () => { docFilter = null; docChip.className = 'hidden'; load(); } }, icon('x'), 'Clear'));
  const more = h('button', { class: 'btn sm hidden', onclick: () => load(true) }, 'Load older entries');

  async function load(append = false) {
    const p = new URLSearchParams();
    if (actor.value.trim()) p.set('actor', actor.value.trim());
    if (action.value) p.set('action', action.value);
    if (outcome.value) p.set('outcome', outcome.value);
    if (docFilter) p.set('document', docFilter);
    if (append && oldest) p.set('before', oldest);
    const { entries } = await get(`/admin/audit?${p}`);
    oldest = entries.length ? entries[entries.length - 1].seq : oldest;
    more.classList.toggle('hidden', entries.length < 100);
    if (append) body.querySelector('tbody')?.append(...auditTable(entries).querySelectorAll('tbody tr'));
    else body.replaceChildren(auditTable(entries));
  }
  async function verify() {
    banner.replaceChildren(chainBanner(await get('/admin/audit/verify')));
  }
  let t;
  actor.addEventListener('input', () => { clearTimeout(t); t = setTimeout(() => load(), 250); });
  action.addEventListener('change', () => load());
  outcome.addEventListener('change', () => load());
  await Promise.all([load(), verify()]);

  return h('div', { class: 'stack' },
    h('div', { class: 'page-head' },
      h('div', { class: 'titles' }, h('h1', {}, 'Audit trail'), h('p', {}, 'Append-only. Each entry is HMAC-chained to the one before it, so any edit, deletion or insertion breaks verification.')),
      h('button', { class: 'btn', onclick: () => verify().then(() => toast('Chain re-verified.')) }, icon('shield'), 'Verify chain')),
    banner,
    h('div', { class: 'card' }, h('div', { class: 'filters' }, h('div', { class: 'search' }, icon('search'), actor), action, outcome, docChip), body,
      h('div', { class: 'card-pad row' }, more)));
}

// ── People ───────────────────────────────────────────────────────────────────
export async function adminUsersPage() {
  const { users } = await get('/admin/users');
  const reload = () => navigate('#/admin/users');
  return h('div', { class: 'stack' },
    h('div', { class: 'page-head' },
      h('div', { class: 'titles' }, h('h1', {}, 'People'), h('p', {}, 'Disabling someone ends their sessions and access immediately. Their grants stay on record.')),
      h('button', { class: 'btn primary', onclick: () => createUserDialog().then((ok) => ok && reload()) }, icon('plus'), 'Add person')),
    h('div', { class: 'card' }, h('div', { class: 'table-wrap' }, h('table', {},
      h('thead', {}, h('tr', {}, h('th', {}, 'Person'), h('th', {}, 'Role'), h('th', {}, 'Owns'), h('th', {}, 'Live grants'), h('th', {}, 'Sessions'), h('th', {}, 'Status'), h('th', {}, ''))),
      h('tbody', {}, users.map((u) => h('tr', {},
        h('td', {}, h('div', { class: 'row' }, avatar(u.name, 'sm'), h('div', {}, h('b', {}, u.name), h('div', { class: 'small muted' }, `${u.email}${u.department ? ` · ${u.department}` : ''}`)))),
        h('td', {}, rolePill(u.role)),
        h('td', {}, String(u.owned_documents)),
        h('td', {}, String(u.live_grants)),
        h('td', {}, String(u.sessions)),
        h('td', {}, u.is_active ? h('span', { class: 'pill ok' }, 'Active') : h('span', { class: 'pill denied' }, 'Disabled'), u.is_demo ? h('div', { class: 'small muted' }, 'demo, protected') : null),
        h('td', {}, u.is_demo || u.role === 'admin' ? null : h('button', { class: `btn sm ${u.is_active ? 'danger' : ''}`, onclick: async () => {
          if (u.is_active && !(await confirmDialog({ title: `Disable ${u.name}?`, text: 'All of their sessions end now and every request they make is refused. Documents they own stay in place; transfer them from the Documents page.', confirm: 'Disable', danger: true }))) return;
          try { await patch(`/admin/users/${u.id}`, { isActive: !u.is_active }); toast(u.is_active ? `${u.name} disabled.` : `${u.name} enabled.`); reload(); } catch (e) { toast(e.message, 'error'); }
        } }, u.is_active ? 'Disable' : 'Enable')))))))));
}

function createUserDialog() {
  const name = h('input', { class: 'input', maxlength: '100' });
  const email = h('input', { class: 'input', type: 'email', maxlength: '254' });
  const department = h('input', { class: 'input', maxlength: '60' });
  const role = h('select', {}, h('option', { value: 'viewer' }, 'Viewer: can only open what is shared with them'), h('option', { value: 'owner' }, 'Owner: can upload and share their own documents'), h('option', { value: 'admin' }, 'Administrator: manages people and audit, no document access'));
  const password = h('input', { class: 'input', type: 'password', minlength: '10', autocomplete: 'new-password' });
  const error = h('div', { class: 'form-error hidden', role: 'alert' });
  return modal((close) => ({
    title: 'Add a person',
    body: [error, h('label', { class: 'field' }, 'Full name', name), h('label', { class: 'field' }, 'Email', email), h('label', { class: 'field' }, 'Department', department), h('label', { class: 'field' }, 'Role', role), h('label', { class: 'field' }, 'Initial password (10+ characters)', password)],
    footer: [h('button', { class: 'btn', onclick: () => close(false) }, 'Cancel'),
      h('button', { class: 'btn primary', onclick: async () => {
        try {
          await post('/admin/users', { name: name.value, email: email.value, department: department.value, role: role.value, password: password.value });
          toast('Person added.');
          close(true);
        } catch (e) { error.textContent = e.message; error.classList.remove('hidden'); }
      } }, 'Add person')],
  }));
}

// ── Documents (metadata only) ────────────────────────────────────────────────
export async function adminDocumentsPage() {
  const [{ documents }, { users }] = await Promise.all([get('/admin/documents'), get('/admin/users')]);
  const owners = users.filter((u) => u.role === 'owner' && u.is_active);
  return h('div', { class: 'stack' },
    h('div', { class: 'page-head' }, h('div', { class: 'titles' }, h('h1', {}, 'Documents'), h('p', {}, 'Metadata and activity only. Administrators cannot open or download document contents.'))),
    h('div', { class: 'card' }, h('div', { class: 'table-wrap' }, h('table', {},
      h('thead', {}, h('tr', {}, h('th', {}, 'Document'), h('th', {}, 'Owner'), h('th', {}, 'Live grants'), h('th', {}, 'Downloads'), h('th', {}, 'Refused'), h('th', {}, 'Updated'), h('th', {}, ''))),
      h('tbody', {}, documents.map((d) => h('tr', {},
        h('td', {}, h('b', {}, d.title), h('div', { class: 'small muted' }, `${d.category} · v${d.current_version}${d.deleted_at ? ' · in trash' : ''}`)),
        h('td', {}, d.owner_name, d.owner_active ? null : h('div', {}, h('span', { class: 'pill medium' }, 'owner disabled'))),
        h('td', {}, String(d.live_grants)),
        h('td', {}, String(d.downloads)),
        h('td', {}, d.denials ? h('span', { class: 'pill denied' }, String(d.denials)) : '0'),
        h('td', { class: 'small muted' }, fmtAgo(d.updated_at)),
        h('td', {}, h('div', { class: 'row' },
          h('a', { class: 'btn sm', href: `#/admin/audit`, onclick: (e) => { e.preventDefault(); sessionStorage.setItem('tv_audit_doc', d.id); navigate('#/admin/audit'); } }, 'Activity'),
          h('button', { class: 'btn sm', onclick: () => transferDialog(d, owners).then((ok) => ok && navigate('#/admin/documents')) }, icon('transfer'), 'Transfer'))))))))));
}

function transferDialog(d, owners) {
  const select = h('select', {}, owners.filter((o) => o.email !== d.owner_email).map((o) => h('option', { value: o.id }, `${o.name} (${o.email})`)));
  const error = h('div', { class: 'form-error hidden', role: 'alert' });
  return modal((close) => ({
    title: 'Transfer ownership',
    subtitle: d.title,
    body: [error, h('p', { class: 'muted' }, `Use this when ${d.owner_name} leaves or changes team. The current owner loses access immediately unless they hold a separate grant. Recorded in the audit trail.`), h('label', { class: 'field' }, 'New owner', select)],
    footer: [h('button', { class: 'btn', onclick: () => close(false) }, 'Cancel'),
      h('button', { class: 'btn primary', onclick: async () => {
        try { await post(`/admin/documents/${d.id}/transfer`, { newOwnerId: select.value }); toast('Ownership transferred.'); close(true); } catch (e) { error.textContent = e.message; error.classList.remove('hidden'); }
      } }, 'Transfer')],
  }));
}
