// Password policy, following NIST SP 800-63B: length over composition rules, and a
// check against passwords attackers try first. No forced periodic rotation.
import { HttpError } from './http.js';

export const MIN_LENGTH = 12;
export const MAX_LENGTH = 128;

// The most common passwords and patterns from public breach corpora. A short list,
// but it covers what an online guessing attack tries first.
const COMMON = new Set([
  'password', 'password1', 'password12', 'password123', 'password1234', 'passw0rd', 'p@ssw0rd', 'p@ssword',
  '123456789012', '1234567890', 'qwertyuiop', 'qwerty123456', '1q2w3e4r5t6y', 'iloveyou1234', 'welcome123',
  'admin123456', 'administrator', 'letmein12345', 'changeme1234', 'trustno1', 'football1234', 'baseball1234',
  'princess1234', 'sunshine1234', 'monkey123456', 'dragon123456', 'superman1234', 'abc123456789', 'aaaaaaaaaaaa',
  'trustvault', 'trustvault123', 'trustvault2026', 'snovasys', 'snovasys123', 'company12345', 'secret123456',
]);

function normalise(s) {
  return s.toLowerCase().replace(/[^a-z0-9]/g, '');
}

/** Returns an error message, or null when the password is acceptable. */
export function passwordProblem(password, { email = '', name = '' } = {}) {
  if (typeof password !== 'string') return 'Password is required';
  if ([...password].length < MIN_LENGTH) return `Use at least ${MIN_LENGTH} characters. A short phrase is easier to remember than symbols.`;
  if (password.length > MAX_LENGTH) return `Use at most ${MAX_LENGTH} characters`;
  const n = normalise(password);
  if (COMMON.has(password.toLowerCase()) || COMMON.has(n)) return 'That password is too common. Attackers try it first.';
  if (/^(.)\1+$/.test(password)) return 'Do not repeat a single character';
  if (/^(0123456789|1234567890|abcdefghij)/.test(n)) return 'Avoid simple sequences';
  const local = normalise(email.split('@')[0] || '');
  if (local.length >= 4 && n.includes(local)) return 'Do not include your email address in your password';
  for (const part of name.toLowerCase().split(/\s+/)) {
    if (part.length >= 4 && n.includes(normalise(part))) return 'Do not include your name in your password';
  }
  return null;
}

export function assertStrongPassword(password, who) {
  const problem = passwordProblem(password, who);
  if (problem) throw new HttpError(400, problem);
}
