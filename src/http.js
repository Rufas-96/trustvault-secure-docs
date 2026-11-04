// Small HTTP helpers shared by all routes.

export class HttpError extends Error {
  constructor(status, message, details) {
    super(message);
    this.status = status;
    this.details = details;
  }
}

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
export const isUuid = (v) => typeof v === 'string' && UUID_RE.test(v);

export const CATEGORIES = Object.freeze(['HR', 'Legal', 'Finance', 'Engineering', 'Sales', 'Audit', 'Other']);

/** Trimmed string within limits, or throws 400. */
export function str(value, field, { min = 0, max = 200, optional = false } = {}) {
  if (value === undefined || value === null || value === '') {
    if (optional) return undefined;
    if (min === 0) return '';
    throw new HttpError(400, `${field} is required`);
  }
  if (typeof value !== 'string') throw new HttpError(400, `${field} must be text`);
  const v = value.trim();
  if (v.length < min) throw new HttpError(400, `${field} is required`);
  if (v.length > max) throw new HttpError(400, `${field} must be at most ${max} characters`);
  // Control characters have no business in titles, names or descriptions.
  if (/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/.test(v)) throw new HttpError(400, `${field} contains invalid characters`);
  return v;
}

export function category(value) {
  if (!CATEGORIES.includes(value)) throw new HttpError(400, `category must be one of: ${CATEGORIES.join(', ')}`);
  return value;
}

export function optionalDate(value, field) {
  if (value === undefined || value === null || value === '') return null;
  if (typeof value !== 'string' || !/^\d{4}-\d{2}-\d{2}/.test(value)) throw new HttpError(400, `${field} must be a date (YYYY-MM-DD)`);
  const d = new Date(value);
  if (Number.isNaN(d.getTime())) throw new HttpError(400, `${field} is not a valid date`);
  return d;
}

/** Escape % and _ so user input is matched literally inside ILIKE. */
export function likePattern(value) {
  return `%${value.replace(/[\\%_]/g, (c) => `\\${c}`)}%`;
}

export function clientIp(req) {
  return req.ip || null;
}
