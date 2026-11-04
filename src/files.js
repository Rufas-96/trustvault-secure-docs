// Upload validation. The filename and the browser-supplied Content-Type are both
// attacker-controlled, so neither decides anything on its own: the extension must be on
// the allowlist AND the file's first bytes must match what that extension claims.
import path from 'node:path';
import { HttpError } from './http.js';

const startsWith = (buf, bytes) => bytes.every((b, i) => buf[i] === b);
const ZIP = [0x50, 0x4b, 0x03, 0x04];

function isOfficeZip(buf, folder) {
  // A real .docx/.xlsx/.pptx is a zip holding [Content_Types].xml and a word/, xl/ or ppt/
  // folder. File names in a zip's local headers are stored uncompressed, so they are visible.
  if (!startsWith(buf, ZIP)) return false;
  const text = buf.toString('latin1');
  return text.includes('[Content_Types].xml') && text.includes(`${folder}/`);
}

function isPlainText(buf) {
  if (buf.includes(0)) return false;
  try {
    new TextDecoder('utf-8', { fatal: true }).decode(buf);
    return true;
  } catch {
    return false;
  }
}

// Served Content-Type comes from this table, never from the upload request.
export const FILE_TYPES = Object.freeze({
  '.pdf': { mime: 'application/pdf', check: (b) => startsWith(b, [0x25, 0x50, 0x44, 0x46, 0x2d]) }, // %PDF-
  '.png': { mime: 'image/png', check: (b) => startsWith(b, [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]) },
  '.jpg': { mime: 'image/jpeg', check: (b) => startsWith(b, [0xff, 0xd8, 0xff]) },
  '.jpeg': { mime: 'image/jpeg', check: (b) => startsWith(b, [0xff, 0xd8, 0xff]) },
  '.txt': { mime: 'text/plain; charset=utf-8', check: isPlainText },
  '.csv': { mime: 'text/csv; charset=utf-8', check: isPlainText },
  '.md': { mime: 'text/markdown; charset=utf-8', check: isPlainText },
  '.docx': { mime: 'application/vnd.openxmlformats-officedocument.wordprocessingml.document', check: (b) => isOfficeZip(b, 'word') },
  '.xlsx': { mime: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet', check: (b) => isOfficeZip(b, 'xl') },
  '.pptx': { mime: 'application/vnd.openxmlformats-officedocument.presentationml.presentation', check: (b) => isOfficeZip(b, 'ppt') },
});

export const ALLOWED_EXTENSIONS = Object.keys(FILE_TYPES);

/** Keep a filename readable but harmless: no paths, no control or quote characters. */
export function sanitiseFilename(name) {
  const base = path.basename(String(name || '').replace(/\\/g, '/'));
  const cleaned = base
    .normalize('NFC')
    .replace(/[\u0000-\u001f\u007f"<>:|?*\\/]/g, '_')
    .replace(/^\.+/, '')
    .trim()
    .slice(0, 150);
  return cleaned || 'file';
}

/** Returns { filename, mime } for a valid upload or throws 400 / 413. */
export function validateUpload(file, maxBytes) {
  if (!file || !file.buffer) throw new HttpError(400, 'Choose a file to upload');
  if (file.size === 0) throw new HttpError(400, 'The file is empty');
  if (file.size > maxBytes) throw new HttpError(413, `Files must be ${Math.round(maxBytes / 1024 / 1024)} MB or smaller`);

  const filename = sanitiseFilename(file.originalname);
  const ext = path.extname(filename).toLowerCase();
  const type = FILE_TYPES[ext];
  if (!type) throw new HttpError(400, `File type not allowed. Allowed: ${ALLOWED_EXTENSIONS.join(', ')}`);
  if (!type.check(file.buffer)) throw new HttpError(400, `The file's contents do not match a ${ext} file`);
  return { filename, mime: type.mime };
}

/** RFC 6266 Content-Disposition: ASCII fallback plus the exact UTF-8 name. */
export function contentDisposition(filename) {
  const ascii = filename.replace(/[^\x20-\x7e]/g, '_').replace(/["\\]/g, '_');
  return `attachment; filename="${ascii}"; filename*=UTF-8''${encodeURIComponent(filename)}`;
}
