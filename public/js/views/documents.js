// Document list/search, detail (overview, versions, sharing, activity), upload and trash.
import { h, icon, toast, modal, confirmDialog, avatar, fmtDate, fmtDateTime, fmtAgo, fmtSize, fileIcon, accessPill, rolePill, outcomePill, actionLabel } from '../ui.js';
import { get, post, patch, del, download } from '../api.js';
import { state, navigate } from '../app.js';

const SCOPE_TEXT = {
  all: ['All documents', 'Everything you own or that has been shared with you.'],
  mine: ['My documents', 'Documents you own. Only you decide who else can see them.'],
  shared: ['Shared with me', 'Documents other people have granted you access to.'],
};

// ── List & search ────────────────────────────────────────────────────────────
export async function documentsPage({ scope }) {
  const [title, sub] = SCOPE_TEXT[scope];
  const cats = state.config?.categories || [];
  const q = h('input', { class: 'input', type: 'search', placeholder: 'Search by name, file or description', 'aria-label': 'Search' });
  const owner = h('input', { class: 'input', type: 'search', placeholder: 'Owner name or email', 'aria-label': 'Owner' });
  const category = h('select', { 'aria-label': 'Category' }, h('option', { value: '' }, 'All categories'), cats.map((c) => h('option', { value: c }, c)));
  const from = h('input', { class: 'input', type: 'date', 'aria-label': 'Created from', title: 'Created from' });
  const to = h('input', { class: 'input', type: 'date', 'aria-label': 'Created to', title: 'Created to' });
  const sort = h('select', { 'aria-label': 'Sort' }, h('option', { value: 'newest' }, 'Newest'), h('option', { value: 'oldest' }, 'Oldest'), h('option', { value: 'title' }, 'Title A–Z'));
  const body = h('div', {});

  async function load() {
    const params = new URLSearchParams({ scope, sort: sort.value });
    if (q.value.trim()) params.set('q', q.value.trim());
    if (owner.value.trim()) params.set('owner', owner.value.trim());
    if (category.value) params.set('category', category.value);
    if (from.value) params.set('from', from.value);
    if (to.value) params.set('to', to.value);
    try {
      const { documents } = await get(`/documents?${params}`);
      body.replaceChildren(documents.length ? docTable(documents) : emptyState(scope, params.size > 2));
    } catch (err) {
      body.replaceChildren(h('div', { class: 'empty' }, icon('alert'), h('b', {}, err.message)));
    }
  }

  let timer;
  const debounced = () => { clearTimeout(timer); timer = setTimeout(load, 250); };
  for (const el of [q, owner]) el.addEventListener('input', debounced);
  for (const el of [category, from, to, sort]) el.addEventListener('change', load);

  const canUpload = state.user.role === 'owner';
  const page = h('div', { class: 'stack' },
    h('div', { class: 'page-head' },
      h('div', { class: 'titles' }, h('h1', {}, title), h('p', {}, sub)),
      canUpload ? h('button', { class: 'btn primary', onclick: () => uploadDialog().then((doc) => doc && navigate(`#/documents/${doc.id}`)) }, icon('upload'), 'Upload document') : null),
    h('div', { class: 'card' },
      h('div', { class: 'filters' },
        h('div', { class: 'search' }, icon('search'), q), owner, category, from, to, sort),
      body));
  await load();
  return page;
}

function docTable(docs) {
  return h('div', { class: 'table-wrap' }, h('table', {},
    h('thead', {}, h('tr', {}, h('th', {}, 'Document'), h('th', {}, 'Category'), h('th', {}, 'Owner'), h('th', {}, 'Updated'), h('th', {}, 'Your access'))),
    h('tbody', {}, docs.map((d) => h('tr', { class: 'clickable', tabindex: '0', onclick: () => navigate(`#/documents/${d.id}`), onkeydown: (e) => e.key === 'Enter' && navigate(`#/documents/${d.id}`) },
      h('td', {}, h('div', { class: 'doc-cell' }, fileIcon(d.filename), h('div', {}, h('b', {}, d.title), h('span', {}, `${d.filename} · ${fmtSize(d.size_bytes)} · v${d.current_version}`)))),
      h('td', {}, h('span', { class: 'cat' }, d.category)),
      h('td', {}, h('div', { class: 'row' }, avatar(d.owner_name, 'sm'), h('span', {}, d.owner_id === state.user.id ? 'You' : d.owner_name))),
      h('td', { class: 'muted' }, fmtAgo(d.updated_at)),
      h('td', {}, accessPill(d.my_access)))))));
}

function emptyState(scope, filtered) {
  if (filtered) return h('div', { class: 'empty' }, icon('search'), h('b', {}, 'No matching documents'), h('p', {}, 'Try different search terms or clear the filters.'));
  if (scope === 'shared') return h('div', { class: 'empty' }, icon('share'), h('b', {}, 'Nothing shared with you yet'), h('p', {}, 'When someone grants you access to a document it appears here.'));
  return h('div', { class: 'empty' }, icon('files'), h('b', {}, 'No documents yet'), h('p', {}, state.user.role === 'owner' ? 'Upload your first document to get started.' : 'Documents shared with you will appear here.'));
}

// ── Upload ───────────────────────────────────────────────────────────────────
function filePicker(onFile) {
  const allowed = state.config?.allowedExtensions || [];
  const input = h('input', { type: 'file', class: 'sr-only', accept: allowed.join(',') });
  const label = h('div', {}, h('b', {}, 'Choose a file or drop it here'), h('span', { class: 'small' }, `${allowed.join(' ')} · up to ${Math.round((state.config?.maxUploadBytes || 0) / 1048576)} MB`));
  const zone = h('div', { class: 'dropzone', tabindex: '0', role: 'button', onclick: () => input.click(), onkeydown: (e) => e.key === 'Enter' && input.click() }, icon('upload'), label);
  const pick = (f) => {
    if (!f) return;
    label.replaceChildren(h('b', {}, f.name), h('span', { class: 'small' }, fmtSize(f.size)));
    onFile(f);
  };
  input.addEventListener('change', () => pick(input.files[0]));
  zone.addEventListener('dragover', (e) => { e.preventDefault(); zone.classList.add('over'); });
  zone.addEventListener('dragleave', () => zone.classList.remove('over'));
  zone.addEventListener('drop', (e) => { e.preventDefault(); zone.classList.remove('over'); pick(e.dataTransfer.files[0]); });
  return h('div', {}, zone, input);
}

export function uploadDialog() {
  let file = null;
  const title = h('input', { class: 'input', maxlength: '150', required: true, placeholder: 'e.g. Salary letter: Priya Shah' });
  const category = h('select', {}, (state.config?.categories || []).map((c) => h('option', { value: c }, c)));
  const description = h('textarea', { maxlength: '1000', placeholder: 'Optional: what is this and who is it for?' });
  const error = h('div', { class: 'form-error hidden', role: 'alert' });
  return modal((close) => {
    const submit = h('button', { class: 'btn primary', onclick: async () => {
      error.classList.add('hidden');
      if (!file) { error.textContent = 'Choose a file to upload'; error.classList.remove('hidden'); return; }
      const fd = new FormData();
      fd.append('title', title.value);
      fd.append('category', category.value);
      fd.append('description', description.value);
      fd.append('file', file);
      submit.disabled = true;
      try {
        const { document } = await post('/documents', fd);
        toast('Uploaded. Only you can see it until you share it.');
        close(document);
      } catch (err) {
        error.textContent = err.message;
        error.classList.remove('hidden');
      } finally {
        submit.disabled = false;
      }
    } }, icon('upload'), 'Upload');
    return {
      title: 'Upload a document',
      subtitle: 'Encrypted at rest. Private to you until you share it.',
      body: [error, filePicker((f) => { file = f; if (!title.value) title.value = f.name.replace(/\.[^.]+$/, ''); }),
        h('label', { class: 'field' }, 'Title', title), h('label', { class: 'field' }, 'Category', category), h('label', { class: 'field' }, 'Description', description)],
      footer: [h('button', { class: 'btn', onclick: () => close() }, 'Cancel'), submit],
    };
  });
}

// ── Detail ───────────────────────────────────────────────────────────────────
const ACCESS_TEXT = {
  owner: ['You own this document', 'You can edit it, share it with named people, revoke access, and see every access attempt.'],
  edit: ['You can edit this document', 'Granted by the owner. You can change its details and upload new versions, but not share or delete it.'],
  read: ['You can view this document', 'Granted by the owner. You can open and download it. Every download is recorded.'],
};

export async function documentDetailPage(id) {
  const { document: d, myAccess } = await get(`/documents/${id}`);
  const container = h('div', { class: 'stack' });
  const tabs = [['overview', 'Overview', 'info'], ['versions', 'Versions', 'history']];
  if (myAccess === 'owner') tabs.push(['sharing', 'Sharing', 'users'], ['activity', 'Activity', 'activity']);
  let current = 'overview';
  const tabBar = h('div', { class: 'tabs', role: 'tablist' });
  const panel = h('div', {});

  async function show(key) {
    current = key;
    tabBar.replaceChildren(...tabs.map(([k, label, ic]) => h('button', { class: `tab ${k === current ? 'active' : ''}`, role: 'tab', 'aria-selected': String(k === current), onclick: () => show(k) }, icon(ic), label)));
    panel.replaceChildren(h('div', { class: 'empty' }, 'Loading…'));
    try {
      const builders = { overview: overviewTab, versions: versionsTab, sharing: sharingTab, activity: activityTab };
      panel.replaceChildren(await builders[key](d, myAccess, refresh));
    } catch (err) {
      panel.replaceChildren(h('div', { class: 'empty' }, icon('alert'), h('b', {}, err.message)));
    }
  }
  async function refresh() {
    const page = await documentDetailPage(id);
    container.replaceWith(page);
  }

  const actions = [h('button', { class: 'btn primary', onclick: () => download(d.id).then(() => toast('Download recorded in the audit trail.')).catch((e) => toast(e.message, 'error')) }, icon('download'), 'Download')];
  if (myAccess === 'owner' || myAccess === 'edit') {
    actions.unshift(h('button', { class: 'btn', onclick: () => editDialog(d).then((ok) => ok && refresh()) }, icon('edit'), 'Edit'),
      h('button', { class: 'btn', onclick: () => newVersionDialog(d).then((ok) => ok && refresh()) }, icon('upload'), 'New version'));
  }
  if (myAccess === 'owner') {
    actions.push(h('button', { class: 'btn danger', title: 'Move to trash', onclick: async () => {
      if (!(await confirmDialog({ title: 'Move to trash?', text: 'Everyone you shared it with loses access immediately. You can restore it from Trash.', confirm: 'Move to trash', danger: true }))) return;
      try { await del(`/documents/${d.id}`); toast('Moved to trash.'); navigate('#/documents'); } catch (e) { toast(e.message, 'error'); }
    } }, icon('trash')));
  }

  const [accessTitle, accessText] = ACCESS_TEXT[myAccess];
  container.append(
    h('div', { class: 'page-head' },
      h('div', { class: 'titles' },
        h('div', { class: 'crumbs' }, h('a', { href: '#/documents' }, 'Documents'), '/', h('span', {}, d.category)),
        h('div', { class: 'row' }, fileIcon(d.filename), h('h1', {}, d.title)),
        h('p', {}, `${d.filename} · ${fmtSize(d.size_bytes)} · version ${d.current_version} · owned by ${d.owner_id === state.user.id ? 'you' : d.owner_name}`)),
      h('div', { class: 'row wrap' }, actions)),
    h('div', { class: 'detail-grid' },
      h('div', { class: 'card' }, tabBar, panel),
      h('div', { class: 'stack' },
        h('div', { class: 'access-box' }, icon('key'), h('div', {}, h('b', {}, accessTitle), h('p', {}, accessText))),
        h('div', { class: 'card card-pad' }, h('dl', { class: 'meta' },
          h('dt', {}, 'Owner'), h('dd', {}, `${d.owner_name}`), h('dt', {}, 'Category'), h('dd', {}, h('span', { class: 'cat' }, d.category)),
          h('dt', {}, 'Created'), h('dd', {}, fmtDateTime(d.created_at)), h('dt', {}, 'Updated'), h('dd', {}, fmtDateTime(d.updated_at)),
          h('dt', {}, 'Your access'), h('dd', {}, accessPill(myAccess)))))));
  await show('overview');
  return container;
}

async function overviewTab(d) {
  return h('div', { class: 'card-pad stack' },
    h('div', {}, h('h3', {}, 'Description'), h('p', { class: d.description ? '' : 'muted' }, d.description || 'No description.')),
    h('div', { class: 'note' }, icon('lock'), h('div', {}, 'Stored encrypted (AES-256-GCM). Downloads are served only after the server checks your access, and every download, including refused ones, is written to the audit trail.')));
}

async function versionsTab(d) {
  const { versions } = await get(`/documents/${d.id}/versions`);
  return h('div', { class: 'list' }, versions.map((v) => h('div', { class: 'list-item' },
    h('span', { class: `pill ${v.version === d.current_version ? 'owner' : ''}` }, `v${v.version}`),
    h('div', { class: 'who' }, h('b', {}, v.filename), h('span', {}, `${fmtSize(v.size_bytes)} · uploaded by ${v.uploaded_by_name} · ${fmtDateTime(v.created_at)}`), h('div', { class: 'hash', title: 'SHA-256 of the file' }, `sha256 ${v.sha256.slice(0, 24)}…`)),
    h('button', { class: 'btn sm', onclick: () => download(d.id, v.version).then(() => toast(`Downloaded version ${v.version}.`)).catch((e) => toast(e.message, 'error')) }, icon('download'), 'Download'))));
}

async function sharingTab(d, myAccess, refresh) {
  const { grants } = await get(`/documents/${d.id}/grants`);
  const live = grants.filter((g) => !g.revoked_at);
  const past = grants.filter((g) => g.revoked_at);
  const expired = (g) => g.expires_at && new Date(g.expires_at) < new Date();
  return h('div', {},
    h('div', { class: 'card-head' }, h('div', { class: 'grow' }, h('h3', {}, 'People with access'), h('p', {}, 'Only the people listed here can open this document. Revoking takes effect on their very next request.')),
      h('button', { class: 'btn primary sm', onclick: () => shareDialog(d).then((ok) => ok && refresh()) }, icon('plus'), 'Share')),
    h('div', { class: 'list' },
      h('div', { class: 'list-item' }, avatar(d.owner_name, 'sm'), h('div', { class: 'who' }, h('b', {}, `${d.owner_name}${d.owner_id === state.user.id ? ' (you)' : ''}`), h('span', {}, d.owner_email)), accessPill('owner')),
      live.map((g) => h('div', { class: 'list-item' }, avatar(g.name, 'sm'),
        h('div', { class: 'who' }, h('b', {}, g.name, g.is_active ? '' : ' (disabled)'), h('span', {}, `${g.email} · granted ${fmtDate(g.created_at)} by ${g.granted_by_name}${g.expires_at ? ` · ${expired(g) ? 'expired' : 'expires'} ${fmtDate(g.expires_at)}` : ''}`)),
        expired(g) ? h('span', { class: 'pill medium' }, 'Expired') : accessPill(g.permission),
        h('button', { class: 'btn danger sm', onclick: async () => {
          if (!(await confirmDialog({ title: `Revoke access for ${g.name}?`, text: 'They lose access on their next request, including any download they try after this moment.', confirm: 'Revoke', danger: true }))) return;
          try { await del(`/documents/${d.id}/grants/${g.id}`); toast(`Access revoked for ${g.name}.`); refresh(); } catch (e) { toast(e.message, 'error'); }
        } }, 'Revoke'))),
      live.length === 0 ? h('div', { class: 'list-item muted' }, 'Not shared with anyone. Only you can see it.') : null),
    past.length ? h('div', {}, h('div', { class: 'card-head' }, h('h3', {}, 'Access history')),
      h('div', { class: 'list' }, past.map((g) => h('div', { class: 'list-item revoked' }, avatar(g.name, 'sm'),
        h('div', { class: 'who' }, h('b', {}, g.name), h('span', {}, `${g.permission} · granted ${fmtDate(g.created_at)} by ${g.granted_by_name} · ended ${fmtDateTime(g.revoked_at)}${g.revoked_by_name ? ` by ${g.revoked_by_name}` : ''}`)),
        h('span', { class: 'pill' }, 'Revoked'))))) : null);
}

async function activityTab(d) {
  const { activity } = await get(`/documents/${d.id}/activity`);
  if (!activity.length) return h('div', { class: 'empty' }, 'No activity yet.');
  return h('div', { class: 'timeline' }, activity.map((a) => h('div', { class: 'tl-item' },
    h('div', { class: `tl-dot ${a.outcome}` }),
    h('div', {},
      h('div', { class: 'row wrap' }, h('span', { class: 'what' }, actionLabel(a.action, a.outcome)), outcomePill(a.outcome)),
      h('div', { class: 'when' }, `${a.actor_email || 'system'}${a.target_email ? ` → ${a.target_email}` : ''} · ${fmtDateTime(a.at)}${a.ip && a.ip !== 'seed' ? ` · ${a.ip}` : ''}${a.details?.reason ? ` · ${a.details.reason}` : ''}${a.details?.version ? ` · v${a.details.version}` : ''}`)))));
}

// ── Dialogs ──────────────────────────────────────────────────────────────────
function shareDialog(d) {
  let selected = null;
  let permission = 'read';
  const search = h('input', { class: 'input', type: 'search', placeholder: 'Search people by name or email' });
  const picker = h('div', { class: 'picker' });
  const expires = h('input', { class: 'input', type: 'date', min: new Date(Date.now() + 86400000).toISOString().slice(0, 10) });
  const error = h('div', { class: 'form-error hidden', role: 'alert' });
  const seg = h('div', { class: 'seg' });
  const renderSeg = () => seg.replaceChildren(...['read', 'edit'].map((p) => h('button', { type: 'button', class: p === permission ? 'on' : '', disabled: p === 'edit' && selected?.role === 'viewer', onclick: () => { permission = p; renderSeg(); } }, p === 'read' ? 'Can view' : 'Can edit')));

  async function loadPeople() {
    const { users } = await get(`/users/directory?q=${encodeURIComponent(search.value.trim())}`);
    picker.replaceChildren(...(users.length ? users.map((u) => h('button', { type: 'button', class: selected?.id === u.id ? 'selected' : '', onclick: () => {
      selected = u;
      if (u.role === 'viewer') permission = 'read';
      renderSeg();
      loadPeople();
    } }, avatar(u.name, 'sm'), h('div', { class: 'grow' }, h('div', {}, u.name), h('span', {}, `${u.email}${u.department ? ` · ${u.department}` : ''}`)), rolePill(u.role))) : [h('div', { class: 'empty small' }, 'No matching people')]));
  }
  let t;
  search.addEventListener('input', () => { clearTimeout(t); t = setTimeout(loadPeople, 200); });
  renderSeg();
  loadPeople();

  return modal((close) => ({
    title: 'Share document',
    subtitle: d.title,
    body: [error, search, picker,
      h('div', { class: 'row wrap' }, h('div', { class: 'grow' }, h('div', { class: 'small muted' }, 'Permission'), seg), h('label', { class: 'field grow' }, 'Expires (optional)', expires)),
      h('div', { class: 'note' }, icon('info'), h('div', {}, 'Viewers can only be given view access. Administrators cannot be given document access. Sharing again with someone who already has access replaces their permission.'))],
    footer: [h('button', { class: 'btn', onclick: () => close(false) }, 'Cancel'),
      h('button', { class: 'btn primary', onclick: async () => {
        error.classList.add('hidden');
        if (!selected) { error.textContent = 'Choose a person'; error.classList.remove('hidden'); return; }
        try {
          await post(`/documents/${d.id}/grants`, { userId: selected.id, permission, expiresAt: expires.value || undefined });
          toast(`${selected.name} can now ${permission === 'edit' ? 'edit' : 'view'} this document.`);
          close(true);
        } catch (e) { error.textContent = e.message; error.classList.remove('hidden'); }
      } }, icon('share'), 'Share')],
  }));
}

function editDialog(d) {
  const title = h('input', { class: 'input', maxlength: '150', value: d.title });
  const category = h('select', {}, (state.config?.categories || []).map((c) => h('option', { value: c, selected: c === d.category }, c)));
  const description = h('textarea', { maxlength: '1000' }, d.description || '');
  const error = h('div', { class: 'form-error hidden', role: 'alert' });
  return modal((close) => ({
    title: 'Edit details',
    body: [error, h('label', { class: 'field' }, 'Title', title), h('label', { class: 'field' }, 'Category', category), h('label', { class: 'field' }, 'Description', description)],
    footer: [h('button', { class: 'btn', onclick: () => close(false) }, 'Cancel'),
      h('button', { class: 'btn primary', onclick: async () => {
        try {
          await patch(`/documents/${d.id}`, { title: title.value, category: category.value, description: description.value });
          toast('Saved.');
          close(true);
        } catch (e) { error.textContent = e.message; error.classList.remove('hidden'); }
      } }, 'Save')],
  }));
}

function newVersionDialog(d) {
  let file = null;
  const error = h('div', { class: 'form-error hidden', role: 'alert' });
  return modal((close) => ({
    title: 'Upload a new version',
    subtitle: `Current: v${d.current_version} · ${d.filename}. Earlier versions are kept.`,
    body: [error, filePicker((f) => { file = f; })],
    footer: [h('button', { class: 'btn', onclick: () => close(false) }, 'Cancel'),
      h('button', { class: 'btn primary', onclick: async () => {
        if (!file) { error.textContent = 'Choose a file'; error.classList.remove('hidden'); return; }
        const fd = new FormData();
        fd.append('file', file);
        try {
          await post(`/documents/${d.id}/versions`, fd);
          toast('New version uploaded.');
          close(true);
        } catch (e) { error.textContent = e.message; error.classList.remove('hidden'); }
      } }, icon('upload'), 'Upload')],
  }));
}

// ── Trash ────────────────────────────────────────────────────────────────────
export async function trashPage() {
  const { documents } = await get('/documents/trash');
  const body = documents.length
    ? h('div', { class: 'list' }, documents.map((d) => h('div', { class: 'list-item' }, fileIcon(d.filename),
      h('div', { class: 'who' }, h('b', {}, d.title), h('span', {}, `${d.filename} · deleted ${fmtDateTime(d.deleted_at)}`)),
      h('button', { class: 'btn sm', onclick: async () => {
        try { await post(`/documents/${d.id}/restore`); toast('Restored. Existing grants apply again.'); navigate(`#/documents/${d.id}`); } catch (e) { toast(e.message, 'error'); }
      } }, icon('restore'), 'Restore'))))
    : h('div', { class: 'empty' }, icon('trash'), h('b', {}, 'Trash is empty'), h('p', {}, 'Deleted documents stay here so you can restore them.'));
  return h('div', { class: 'stack' },
    h('div', { class: 'page-head' }, h('div', { class: 'titles' }, h('h1', {}, 'Trash'), h('p', {}, 'Nobody can open a document while it is in the trash, including people it was shared with.'))),
    h('div', { class: 'card' }, body));
}
