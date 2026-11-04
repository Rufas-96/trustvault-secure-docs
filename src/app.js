// Express application wiring. Order matters: headers → body limits → session → CSRF → routes.
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import express from 'express';
import multer from 'multer';
import { config } from './config.js';
import { audit } from './audit.js';
import { accountRouter, loadSession, login, loginMfa, logout, publicAuthRouter, publicUser, requireAccountReady, requireAuth, requireCsrf, requireSameOrigin } from './auth.js';
import { channels } from './notify.js';
import { MIN_LENGTH } from './passwords.js';
import { HttpError } from './http.js';
import { CATEGORIES } from './http.js';
import { ALLOWED_EXTENSIONS } from './files.js';
import { documentsRouter } from './routes/documents.js';
import { adminRouter } from './routes/admin.js';
import { usersRouter } from './routes/users.js';

const publicDir = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'public');

function securityHeaders(req, res, next) {
  res.set({
    // No inline scripts or styles anywhere, so XSS has nothing to run with.
    'Content-Security-Policy':
      "default-src 'self'; script-src 'self'; style-src 'self' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'",
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'Referrer-Policy': 'no-referrer',
    'Permissions-Policy': 'camera=(), microphone=(), geolocation=()',
    'Cross-Origin-Opener-Policy': 'same-origin',
    'Cross-Origin-Resource-Policy': 'same-origin',
  });
  if (config.isProduction) res.set('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  next();
}

// Simple fixed-window limiter per IP for the whole API, to blunt scraping and floods.
function apiRateLimit({ windowMs = 60_000, max = 300 } = {}) {
  const hits = new Map();
  return (req, res, next) => {
    const now = Date.now();
    let h = hits.get(req.ip);
    if (!h || h.resetAt < now) h = { n: 0, resetAt: now + windowMs };
    h.n += 1;
    hits.set(req.ip, h);
    if (hits.size > 10_000) for (const [k, v] of hits) if (v.resetAt < now) hits.delete(k);
    if (h.n > max) throw new HttpError(429, 'Too many requests. Slow down.');
    next();
  };
}

export function createApp() {
  const app = express();
  app.disable('x-powered-by');
  // req.ip feeds the audit trail, so it must be the real client and must not be spoofable.
  // Render forwards through more than one internal hop (10.x addresses), so trusting a fixed
  // count of 1 recorded Render's own load balancer for every request. Instead, skip only
  // proxies on private networks: a client-supplied X-Forwarded-For entry is never trusted,
  // because it sits to the left of the first public address. Override with TRUST_PROXY.
  app.set('trust proxy', config.trustProxy);
  app.use(securityHeaders);

  app.get('/healthz', (req, res) => res.json({ ok: true }));

  const api = express.Router();
  api.use((req, res, next) => {
    res.set('Cache-Control', 'no-store');
    next();
  });
  if (!config.isTest) api.use(apiRateLimit());
  api.use(express.json({ limit: '32kb' }));
  api.use(requireSameOrigin);
  api.use(loadSession);
  api.use(requireCsrf);

  // `channels` tells the UI which code deliveries really work here, so it never offers one
  // that does not (e.g. email without a configured provider).
  api.get('/config', (req, res) => res.json({ categories: CATEGORIES, allowedExtensions: ALLOWED_EXTENSIONS, maxUploadBytes: config.maxUploadBytes, passwordMinLength: MIN_LENGTH, channels: channels() }));
  api.post('/auth/login', login);
  api.post('/auth/mfa', loginMfa);
  api.use('/auth', publicAuthRouter); // sign-up, email-code sign-in, password reset
  api.post('/auth/logout', requireAuth, logout);
  api.get('/me', requireAuth, (req, res) => res.json({ user: publicUser(req.user), csrfToken: req.csrfToken }));
  // Same as /me, but 200 with user:null when signed out, so the page can boot without a 401.
  api.get('/session', (req, res) => res.json(req.user ? { user: publicUser(req.user), csrfToken: req.csrfToken } : { user: null }));
  // Account security (password, two-factor, sessions) stays reachable even while the
  // account is gated, because that is where the user fixes what the gate is asking for.
  api.use('/auth', requireAuth, accountRouter);

  api.use('/documents', requireAuth, requireAccountReady, documentsRouter);
  api.use('/users', requireAuth, requireAccountReady, usersRouter);
  api.use('/admin', requireAuth, requireAccountReady, adminRouter);
  api.use((req, res) => res.status(404).json({ error: 'Not found' }));

  app.use('/api', api);
  // `no-cache` means "revalidate every time": the browser keeps a copy but asks the server
  // (via ETag) whether it changed, so a new deploy shows up on the next page load instead of
  // up to an hour later. Unchanged files cost only a tiny 304 response.
  app.use(express.static(publicDir, {
    index: 'index.html',
    etag: true,
    setHeaders: (res) => res.setHeader('Cache-Control', 'no-cache'),
  }));
  // Single-page app: any other GET serves the shell; the client router takes over.
  app.get('/{*splat}', (req, res) => res.sendFile(path.join(publicDir, 'index.html')));

  // One error handler. Clients get a clean message; stack traces stay in the server log.
  app.use(async (err, req, res, _next) => {
    let status = err.status || 500;
    let message = err.message;
    if (err instanceof multer.MulterError) {
      status = err.code === 'LIMIT_FILE_SIZE' ? 413 : 400;
      message = err.code === 'LIMIT_FILE_SIZE' ? `Files must be ${Math.round(config.maxUploadBytes / 1024 / 1024)} MB or smaller` : 'Upload rejected: send one file in the "file" field';
    } else if (err.type === 'entity.parse.failed') {
      status = 400;
      message = 'Request body is not valid JSON';
    } else if (err.type === 'entity.too.large') {
      status = 413;
      message = 'Request body is too large';
    } else if (!(err instanceof HttpError) && status >= 500) {
      console.error(err);
      message = 'Something went wrong on our side. It has been logged.';
      try {
        await audit({ actor: req.user, action: 'server.error', outcome: 'error', details: { path: req.originalUrl.slice(0, 200), method: req.method }, ip: req.ip });
      } catch {
        /* never let audit failure mask the original error */
      }
    }
    if (res.headersSent) return;
    res.status(status).json({ error: message, ...(err.details ? { details: err.details } : {}) });
  });

  return app;
}
