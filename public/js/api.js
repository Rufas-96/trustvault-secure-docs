// Thin fetch wrapper. Sends the CSRF token on every state-changing request.
// Note: nothing here decides access. The UI hides buttons for convenience only;
// the server re-checks every request.

let csrfToken = '';
export const setCsrf = (t) => { csrfToken = t || ''; };

export class ApiError extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
  }
}

let onUnauthorized = () => {};
export const setUnauthorizedHandler = (fn) => { onUnauthorized = fn; };
// The server answers 403 + code PASSWORD_CHANGE_REQUIRED / MFA_SETUP_REQUIRED while the
// account is gated; the app sends the user to the account page to fix it.
let onGate = () => {};
export const setGateHandler = (fn) => { onGate = fn; };

export async function api(method, path, body) {
  const headers = {};
  let payload;
  if (body instanceof FormData) payload = body;
  else if (body !== undefined) {
    headers['content-type'] = 'application/json';
    payload = JSON.stringify(body);
  }
  if (method !== 'GET') headers['x-csrf-token'] = csrfToken;
  const res = await fetch(`/api${path}`, { method, headers, body: payload, credentials: 'same-origin' });
  const data = res.headers.get('content-type')?.includes('application/json') ? await res.json() : null;
  if (!res.ok) {
    if (res.status === 401 && state401(path)) onUnauthorized();
    const err = new ApiError(res.status, data?.error || `Request failed (${res.status})`);
    err.code = data?.details?.code;
    err.details = data?.details;
    if (res.status === 403 && (err.code === 'PASSWORD_CHANGE_REQUIRED' || err.code === 'MFA_SETUP_REQUIRED')) onGate(err.code);
    throw err;
  }
  return data;
}

export const get = (p) => api('GET', p);
export const post = (p, b) => api('POST', p, b);
export const patch = (p, b) => api('PATCH', p, b);
export const del = (p) => api('DELETE', p);

/** Download via fetch so errors show as a message instead of saving an error page. */
export async function download(docId, version) {
  const res = await fetch(`/api/documents/${encodeURIComponent(docId)}/download${version ? `?version=${version}` : ''}`, { credentials: 'same-origin' });
  if (!res.ok) {
    const data = await res.json().catch(() => ({}));
    if (res.status === 401) onUnauthorized();
    throw new ApiError(res.status, data.error || 'Download failed');
  }
  const disposition = res.headers.get('content-disposition') || '';
  const match = /filename\*=UTF-8''([^;]+)/.exec(disposition);
  const filename = match ? decodeURIComponent(match[1]) : 'document';
  const url = URL.createObjectURL(await res.blob());
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.append(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 10_000);
}

// A 401 from a sign-in step means "wrong code/password", not "your session ended".
function state401(path) {
  return !path.startsWith('/auth/') || path.startsWith('/auth/sessions') || path.startsWith('/auth/activity');
}
