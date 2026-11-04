// Visual effects: 3D tilt, count-up numbers, staggered entrances, button ripples, floating
// action button and back-to-top. Pure DOM + CSS: no libraries, no inline style attributes
// (the CSP forbids them; setting properties through el.style is allowed).
// Everything is skipped when the user prefers reduced motion.
import { h, icon } from './ui.js';

export const reducedMotion = () => window.matchMedia('(prefers-reduced-motion: reduce)').matches;

/** 3D tilt that follows the pointer. */
export function tilt(el, max = 8) {
  if (reducedMotion() || el.dataset.tilt === 'on') return el;
  el.dataset.tilt = 'on';
  el.classList.add('tilt');
  const reset = () => {
    el.style.setProperty('--rx', '0deg');
    el.style.setProperty('--ry', '0deg');
    el.style.setProperty('--gx', '50%');
    el.style.setProperty('--gy', '50%');
  };
  el.addEventListener('pointermove', (e) => {
    const r = el.getBoundingClientRect();
    const x = (e.clientX - r.left) / r.width;
    const y = (e.clientY - r.top) / r.height;
    el.style.setProperty('--rx', `${((0.5 - y) * max).toFixed(2)}deg`);
    el.style.setProperty('--ry', `${((x - 0.5) * max).toFixed(2)}deg`);
    el.style.setProperty('--gx', `${(x * 100).toFixed(1)}%`);
    el.style.setProperty('--gy', `${(y * 100).toFixed(1)}%`);
  });
  el.addEventListener('pointerleave', reset);
  reset();
  return el;
}

/** Animate a number from 0 to its value. */
export function countUp(el) {
  const target = Number(el.dataset.count);
  if (!Number.isFinite(target)) return;
  if (reducedMotion() || target === 0) { el.textContent = String(target); return; }
  const start = performance.now();
  const dur = 900 + Math.min(target, 50) * 12;
  const step = (now) => {
    const t = Math.min(1, (now - start) / dur);
    const eased = 1 - Math.pow(1 - t, 3);
    el.textContent = String(Math.round(target * eased));
    if (t < 1) requestAnimationFrame(step);
  };
  requestAnimationFrame(step);
}

/** Give children a stagger index so CSS can cascade their entrance. */
export function stagger(container, selector) {
  container.querySelectorAll(selector).forEach((el, i) => el.style.setProperty('--i', String(Math.min(i, 14))));
}

/** Run after a page renders: tilt, counters, staggered rows. */
export function enhance(root) {
  root.querySelectorAll('.stat, .check-item, .pillar, .security-card, .auth-card').forEach((el) => tilt(el, el.classList.contains('auth-card') ? 4 : 7));
  root.querySelectorAll('[data-count]').forEach(countUp);
  stagger(root, 'tbody tr');
  stagger(root, '.list-item');
  stagger(root, '.tl-item');
  stagger(root, '.check-item');
  stagger(root, '.alert-row');
}

// ── Button ripple (one listener for the whole page) ──
let rippleInstalled = false;
export function installRipple() {
  if (rippleInstalled) return;
  rippleInstalled = true;
  document.addEventListener('pointerdown', (e) => {
    const btn = e.target.closest('.btn, .fab-main, .fab-action, .demo-btn');
    if (!btn || reducedMotion() || btn.disabled) return;
    const r = btn.getBoundingClientRect();
    const size = Math.max(r.width, r.height) * 2;
    const dot = document.createElement('span');
    dot.className = 'ripple';
    dot.style.setProperty('--size', `${size}px`);
    dot.style.setProperty('--x', `${e.clientX - r.left - size / 2}px`);
    dot.style.setProperty('--y', `${e.clientY - r.top - size / 2}px`);
    btn.append(dot);
    setTimeout(() => dot.remove(), 650);
  });
}

/** Floating particles for a hero area. */
export function particles(count = 18) {
  const wrap = h('div', { class: 'particles', 'aria-hidden': 'true' });
  if (reducedMotion()) return wrap;
  for (let i = 0; i < count; i++) {
    const p = h('span', { class: 'particle' });
    p.style.setProperty('--x', `${Math.random() * 100}%`);
    p.style.setProperty('--d', `${8 + Math.random() * 10}s`);
    p.style.setProperty('--delay', `${-Math.random() * 12}s`);
    p.style.setProperty('--s', `${2 + Math.random() * 4}px`);
    wrap.append(p);
  }
  return wrap;
}

/** The 3D vault on the sign-in page: a shield inside three orbiting rings, with tiles. */
export function vault3d() {
  const ring = (cls) => h('div', { class: `v-ring ${cls}` }, h('span', { class: 'v-node' }));
  const tile = (cls, ic, label) => h('div', { class: `v-tile ${cls}` }, icon(ic), h('span', {}, label));
  return h('div', { class: 'vault3d', 'aria-hidden': 'true' },
    h('div', { class: 'v-stage' },
      ring('r1'), ring('r2'), ring('r3'),
      h('div', { class: 'v-core' }, h('div', { class: 'v-core-face' }, icon('shield'))),
      tile('t1', 'lock', 'AES-256'),
      tile('t2', 'history', 'HMAC chain'),
      tile('t3', 'key', '2FA')));
}

// ── Floating action button with speed dial ──
let fabEl = null;
let topEl = null;
let fabListeners = false;

/**
 * actions: [{ icon, label, onClick }]. Replaces any previous FAB (one per page shell).
 */
export function mountFab(actions) {
  fabEl?.remove();
  const menu = h('div', { class: 'fab-menu', role: 'menu' });
  const main = h('button', { class: 'fab-main', type: 'button', 'aria-label': 'Quick actions', 'aria-expanded': 'false', title: 'Quick actions' }, icon('plus'));
  const close = () => {
    fabEl.classList.remove('open');
    main.setAttribute('aria-expanded', 'false');
  };
  actions.forEach((a, i) => {
    const item = h('div', { class: 'fab-item' },
      h('span', { class: 'fab-label' }, a.label),
      h('button', { class: 'fab-action', type: 'button', role: 'menuitem', 'aria-label': a.label, title: a.label, onclick: () => { close(); a.onClick(); } }, icon(a.icon)));
    item.style.setProperty('--i', String(i));
    menu.append(item);
  });
  main.addEventListener('click', () => {
    const open = !fabEl.classList.contains('open');
    fabEl.classList.toggle('open', open);
    main.setAttribute('aria-expanded', String(open));
  });
  fabEl = h('div', { class: 'fab' }, menu, main);
  document.body.append(fabEl);
  if (!fabListeners) {
    // Installed once; they always act on whichever FAB is currently mounted.
    fabListeners = true;
    const closeCurrent = () => {
      fabEl?.classList.remove('open');
      fabEl?.querySelector('.fab-main')?.setAttribute('aria-expanded', 'false');
    };
    document.addEventListener('keydown', (e) => e.key === 'Escape' && closeCurrent());
    document.addEventListener('pointerdown', (e) => { if (fabEl && !fabEl.contains(e.target)) closeCurrent(); });
  }

  if (!topEl) {
    topEl = h('button', { class: 'to-top', type: 'button', 'aria-label': 'Back to top', title: 'Back to top', onclick: () => window.scrollTo({ top: 0, behavior: reducedMotion() ? 'auto' : 'smooth' }) }, icon('upload'));
    document.body.append(topEl);
    const onScroll = () => topEl.classList.toggle('show', window.scrollY > 320);
    window.addEventListener('scroll', onScroll, { passive: true });
    onScroll();
  }
}

export function unmountFab() {
  fabEl?.remove();
  fabEl = null;
  topEl?.classList.remove('show');
}
