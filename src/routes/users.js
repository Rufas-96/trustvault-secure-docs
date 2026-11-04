// People directory used by owners when sharing. Returns only what the share dialog needs.
import { Router } from 'express';
import { query } from '../db.js';
import { requireRole } from '../authz.js';
import { likePattern, str } from '../http.js';

export const usersRouter = Router();

usersRouter.get('/directory', requireRole('owner'), async (req, res) => {
  const q = str(req.query.q, 'q', { max: 100, optional: true });
  const params = [req.user.id];
  let filter = '';
  if (q) {
    params.push(likePattern(q));
    filter = 'AND (name ILIKE $2 OR email ILIKE $2)';
  }
  // Admins are excluded: they cannot hold document grants.
  const users = await query(
    `SELECT id, name, email, role, department FROM users
      WHERE is_active AND role <> 'admin' AND id <> $1 ${filter}
      ORDER BY name LIMIT 25`,
    params,
  );
  res.json({ users });
});
