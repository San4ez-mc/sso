// SSO FINEKO (#284) — єдиний вхід. Ідентичність (ХТО); доступи дає орг.структура.
import express, { type Request, type Response } from 'express';
import cookieParser from 'cookie-parser';
import cors from 'cors';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { randomBytes, randomUUID } from 'node:crypto';
import { PrismaClient } from '@prisma/client';
import { smtpEnabled, sendResetEmail } from './mailer';

const prisma = new PrismaClient();
const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true })); // форми логіну + OAuth token-запит (NextAuth шле form-urlencoded)
app.use(cookieParser());
app.use(cors({ origin: true, credentials: true }));

const PORT = Number(process.env.PORT || 4600);
const BASE_URL = process.env.SSO_BASE_URL || `http://localhost:${PORT}`;
const JWT_SECRET = process.env.JWT_SECRET || 'dev_sso_secret_change_me';
const ADMIN_API_KEY = process.env.ADMIN_API_KEY || 'dev_admin_key';
const TOKEN_TTL = 60 * 60 * 24 * 30; // 30 днів

// ── Хелпери ─────────────────────────────────────────────────
function issueToken(user: { id: string; email: string; displayName: string | null }) {
  return jwt.sign({ sub: user.id, email: user.email, name: user.displayName }, JWT_SECRET, { expiresIn: TOKEN_TTL });
}
function verifyToken(token: string): { sub: string; email: string; name?: string } | null {
  try {
    return jwt.verify(token, JWT_SECRET) as { sub: string; email: string; name?: string };
  } catch {
    return null;
  }
}
function bearer(req: Request): string {
  const h = req.header('authorization') || '';
  const m = /^Bearer\s+(.+)$/i.exec(h);
  return m ? m[1].trim() : String(req.cookies?.sso_token || '');
}
async function currentUser(req: Request) {
  const t = bearer(req);
  if (!t) return null;
  const p = verifyToken(t);
  if (!p) return null;
  return prisma.user.findUnique({ where: { id: p.sub } });
}

// ── Куки ────────────────────────────────────────────────────
// secure вмикається автоматично на https, щоб локальна розробка по http не зламалась.
const SECURE_COOKIES = BASE_URL.startsWith('https://');
const SESSION_COOKIE = { httpOnly: true, sameSite: 'lax' as const, secure: SECURE_COOKIES, maxAge: TOKEN_TTL * 1000 };

// ── Вхід в адмінку: одноразовий квиток → окрема коротка сесія ──────────
// Навіщо окремо від sso_token: звичайна сесія живе 30 днів і ходить у продукти.
// Панель доступів бачить геть усе, тому вимагає свіжого підтвердження — це
// step-up. Токен у посиланні одноразовий і живе хвилини: він обмінюється на
// куку і зникає з адресного рядка, щоб не осісти в історії чи логах.
const ADMIN_TICKET_TTL = 180; // 3 хв на перехід за посиланням
const ADMIN_SESSION_TTL = 30 * 60; // 30 хв роботи в панелі
const usedTickets = new Map<string, number>(); // jti → коли протух

setInterval(() => {
  const now = Date.now();
  for (const [jti, exp] of usedTickets) if (exp < now) usedTickets.delete(jti);
}, 60_000).unref();

function issueAdminTicket(userId: string): string {
  return jwt.sign({ sub: userId, typ: 'admin_ticket', jti: randomUUID() }, JWT_SECRET, { expiresIn: ADMIN_TICKET_TTL });
}

/** Перевіряє квиток і одразу гасить його — повторний перехід за тим самим посиланням не спрацює. */
function consumeAdminTicket(token: string): string | null {
  let p: any;
  try { p = jwt.verify(token, JWT_SECRET); } catch { return null; }
  if (p.typ !== 'admin_ticket' || !p.sub || !p.jti) return null;
  if (usedTickets.has(p.jti)) return null;
  usedTickets.set(p.jti, Date.now() + ADMIN_TICKET_TTL * 1000);
  return String(p.sub);
}

function issueAdminSession(userId: string): string {
  return jwt.sign({ sub: userId, typ: 'admin' }, JWT_SECRET, { expiresIn: ADMIN_SESSION_TTL });
}

/**
 * Доступ до панелі: свіжа адмін-сесія І чинні права ЗАРАЗ.
 * Права перечитуються з БД щоразу — відкликання діє негайно, а не через 30 хв.
 */
async function requireAdminSession(req: Request) {
  const raw = String(req.cookies?.admin_session || '');
  if (!raw) return null;
  let p: any;
  try { p = jwt.verify(raw, JWT_SECRET); } catch { return null; }
  if (p.typ !== 'admin' || !p.sub) return null;

  const user = await prisma.user.findUnique({ where: { id: String(p.sub) } });
  if (!user || user.status !== 'active') return null;
  if (OWNER_EMAILS.includes((user.email || '').toLowerCase())) return user;
  const sup = await prisma.access.findFirst({ where: { userId: user.id, role: 'superadmin' } });
  return sup ? user : null;
}

/**
 * Панель — тільки з власного походження. CORS у сервісі навмисне широкий
 * (продукти ходять з різних доменів), тож для адмінських шляхів звужуємо окремо:
 * інакше сторонній сайт міг би прочитати список користувачів кукою відвідувача.
 */
app.use('/admin', (req: Request, res: Response, next) => {
  const origin = req.header('origin');
  if (origin && origin !== BASE_URL) return void res.status(403).json({ error: 'cross-origin заборонено' });
  next();
});

// ── Health ──────────────────────────────────────────────────
app.get('/health', async (_req, res) => {
  const users = await prisma.user.count().catch(() => -1);
  res.json({ ok: true, service: 'fineko-sso', users });
});

// Favicon (брендований F)
app.get('/favicon.svg', (_req, res) => {
  res.type('image/svg+xml').send('<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64"><defs><linearGradient id="g" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="#e0364f"/><stop offset="1" stop-color="#8b1e3f"/></linearGradient></defs><rect width="64" height="64" rx="14" fill="#0b0f1a"/><text x="32" y="46" font-family="Arial,Helvetica,sans-serif" font-size="42" font-weight="800" fill="url(#g)" text-anchor="middle">F</text></svg>');
});

// ── Реєстрація (email+пароль) ───────────────────────────────
app.post('/register', async (req: Request, res: Response) => {
  try {
    const email = String(req.body?.email || '').trim().toLowerCase();
    const password = String(req.body?.password || '');
    const displayName = req.body?.displayName ? String(req.body.displayName) : null;
    if (!email || !password) return void res.status(400).json({ error: 'email і password обовʼязкові' });
    if (password.length < 6) return void res.status(422).json({ error: 'Пароль мінімум 6 символів' });
    const exists = await prisma.user.findUnique({ where: { email } });
    if (exists) return void res.status(409).json({ error: 'Акаунт з таким email вже існує' });
    const passwordHash = await bcrypt.hash(password, 10);
    const user = await prisma.user.create({
      data: { email, passwordHash, displayName, identities: { create: { provider: 'password', providerUserId: email, email } } },
    });
    const token = issueToken(user);
    res.cookie('sso_token', token, SESSION_COOKIE);
    res.json({ user: { id: user.id, email: user.email, displayName: user.displayName }, token });
  } catch (err) {
    res.status(500).json({ error: String(err) });
  }
});

// ── Вхід (email+пароль) ─────────────────────────────────────
app.post('/login', async (req: Request, res: Response) => {
  try {
    const email = String(req.body?.email || '').trim().toLowerCase();
    const password = String(req.body?.password || '');
    const user = await prisma.user.findUnique({ where: { email } });
    if (!user || !user.passwordHash || user.status !== 'active') {
      return void res.status(401).json({ error: 'Невірний email або пароль' });
    }
    const ok = await bcrypt.compare(password, user.passwordHash);
    if (!ok) return void res.status(401).json({ error: 'Невірний email або пароль' });
    const token = issueToken(user);
    res.cookie('sso_token', token, SESSION_COOKIE);
    res.json({ user: { id: user.id, email: user.email, displayName: user.displayName }, token });
  } catch (err) {
    res.status(500).json({ error: String(err) });
  }
});

app.post('/logout', (_req, res) => {
  res.cookie('sso_token', '', { httpOnly: true, maxAge: 0 });
  res.cookie('admin_session', '', { httpOnly: true, maxAge: 0 });
  res.json({ ok: true });
});

// ── Хто я (перевірка токена) ────────────────────────────────
app.get('/me', async (req: Request, res: Response) => {
  const user = await currentUser(req);
  if (!user) return void res.status(401).json({ error: 'Не автентифіковано' });
  res.json({ user: { id: user.id, email: user.email, displayName: user.displayName, status: user.status } });
});

// ── Відновлення пароля ──────────────────────────────────────
app.post('/forgot-password', async (req: Request, res: Response) => {
  try {
    const email = String(req.body?.email || '').trim().toLowerCase();
    if (!email) return void res.status(400).json({ error: 'email required' });
    const user = await prisma.user.findUnique({ where: { email } });
    let devLink: string | undefined;
    if (user) {
      await prisma.passwordResetToken.deleteMany({ where: { userId: user.id, usedAt: null } });
      const token = randomBytes(32).toString('hex');
      await prisma.passwordResetToken.create({ data: { userId: user.id, token, expiresAt: new Date(Date.now() + 3600_000) } });
      const link = `${BASE_URL}/reset-password/${token}`;
      // eslint-disable-next-line no-console
      console.log('[sso forgot-password]', email, '->', link);
      if (smtpEnabled()) {
        try {
          await sendResetEmail(email, link);
        } catch (mailErr) {
          // eslint-disable-next-line no-console
          console.error('[sso forgot-password] SMTP помилка:', mailErr);
          // Лист не пішов — не розкриваємо помилку клієнту; лінк лишається в логах.
        }
      } else {
        devLink = link; // без SMTP (локально) — віддаємо лінк у відповіді
      }
    }
    res.json({ ok: true, message: 'Якщо акаунт існує, ми надіслали посилання для скидання.', ...(devLink ? { devLink } : {}) });
  } catch (err) {
    res.status(500).json({ error: String(err) });
  }
});

app.post('/reset-password', async (req: Request, res: Response) => {
  try {
    const token = String(req.body?.token || '').trim();
    const password = String(req.body?.password || '');
    if (!token || !password) return void res.status(400).json({ error: 'token і password обовʼязкові' });
    if (password.length < 6) return void res.status(422).json({ error: 'Пароль мінімум 6 символів' });
    const rec = await prisma.passwordResetToken.findUnique({ where: { token } });
    if (!rec || rec.usedAt || rec.expiresAt < new Date()) return void res.status(400).json({ error: 'Недійсне або протерміноване посилання' });
    const passwordHash = await bcrypt.hash(password, 10);
    await prisma.user.update({ where: { id: rec.userId }, data: { passwordHash } });
    await prisma.passwordResetToken.update({ where: { id: rec.id }, data: { usedAt: new Date() } });
    res.json({ ok: true, message: 'Пароль оновлено.' });
  } catch (err) {
    res.status(500).json({ error: String(err) });
  }
});

// HTML-сторінки відновлення (форма → наявні JSON POST /forgot-password, /reset-password)
app.get('/forgot-password', (_req, res) => void res.type('html').send(forgotPage()));
app.get('/reset-password/:token', (req, res) => void res.type('html').send(resetPage(String(req.params.token || ''))));

// ── OAuth authorization_code flow (для підключення продуктів) ──
// Продукт: redirect на /authorize?client_id&redirect_uri&state
// Після входу SSO віддає ?code; продукт міняє code→token на /oauth/token.
app.get('/authorize', async (req: Request, res: Response) => {
  try {
    const clientId = String(req.query.client_id || '');
    const redirectUri = String(req.query.redirect_uri || '');
    const state = String(req.query.state || '');
    if (!clientId) return void res.type('html').send(ssoPage('FINEKO — Єдиний вхід', `<h1>🔐 FINEKO SSO</h1><p>Єдиний вхід у продукти FINEKO. Ця сторінка відкривається автоматично, коли ви входите з продукту. Оберіть систему:</p><div style="display:flex;flex-direction:column;gap:10px;margin-top:8px"><a href="https://org.fineko.space" style="color:#e0364f">→ Орг.структура</a><a href="https://content2.fineko.space" style="color:#e0364f">→ Контент</a><a href="https://tasks2.fineko.space" style="color:#e0364f">→ Трекер</a></div>`));
    const client = await prisma.oAuthClient.findUnique({ where: { clientId } });
    if (!client) return void res.status(400).send('Unknown client_id');
    const allowed: string[] = JSON.parse(client.redirectUris || '[]');
    if (allowed.length && !allowed.includes(redirectUri)) return void res.status(400).send('redirect_uri not allowed');

    // Якщо вже є активна сесія SSO — одразу видаємо код
    const user = await currentUser(req);
    if (user) {
      const code = randomBytes(24).toString('hex');
      await prisma.authCode.create({ data: { code, clientId, userId: user.id, redirectUri, expiresAt: new Date(Date.now() + 300_000) } });
      const sep = redirectUri.includes('?') ? '&' : '?';
      return void res.redirect(`${redirectUri}${sep}code=${code}${state ? `&state=${encodeURIComponent(state)}` : ''}`);
    }
    // Інакше — форма входу
    res.type('html').send(loginPage(clientId, redirectUri, state, ''));
  } catch (err) {
    res.status(500).send('SSO error: ' + String(err));
  }
});

app.post('/authorize', async (req: Request, res: Response) => {
  try {
    const { client_id: clientId, redirect_uri: redirectUri, state = '', email, password } = req.body || {};
    if (!clientId) return void res.status(400).send('client_id required');
    const client = await prisma.oAuthClient.findUnique({ where: { clientId } });
    if (!client) return void res.status(400).send('Unknown client_id');
    const user = await prisma.user.findUnique({ where: { email: String(email || '').trim().toLowerCase() } });
    if (!user || !user.passwordHash || !(await bcrypt.compare(String(password || ''), user.passwordHash)) || user.status !== 'active') {
      return void res.type('html').send(loginPage(clientId, redirectUri, state, 'Невірний email або пароль'));
    }
    const token = issueToken(user);
    res.cookie('sso_token', token, SESSION_COOKIE);
    const code = randomBytes(24).toString('hex');
    await prisma.authCode.create({ data: { code, clientId, userId: user.id, redirectUri, expiresAt: new Date(Date.now() + 300_000) } });
    const sep = redirectUri.includes('?') ? '&' : '?';
    res.redirect(`${redirectUri}${sep}code=${code}${state ? `&state=${encodeURIComponent(state)}` : ''}`);
  } catch (err) {
    res.status(500).send('SSO error: ' + String(err));
  }
});

app.post('/oauth/token', async (req: Request, res: Response) => {
  try {
    const { code, client_id: clientId, client_secret: clientSecret } = req.body || {};
    const client = await prisma.oAuthClient.findUnique({ where: { clientId } });
    if (!client || client.clientSecret !== clientSecret) return void res.status(401).json({ error: 'invalid_client' });
    const rec = await prisma.authCode.findUnique({ where: { code: String(code || '') } });
    if (!rec || rec.used || rec.clientId !== clientId || rec.expiresAt < new Date()) return void res.status(400).json({ error: 'invalid_grant' });
    await prisma.authCode.update({ where: { code: rec.code }, data: { used: true } });
    const user = await prisma.user.findUnique({ where: { id: rec.userId } });
    if (!user) return void res.status(400).json({ error: 'invalid_grant' });
    const token = issueToken(user);
    res.json({ access_token: token, token_type: 'Bearer', expires_in: TOKEN_TTL, user: { id: user.id, email: user.email, name: user.displayName } });
  } catch (err) {
    res.status(500).json({ error: String(err) });
  }
});

app.post('/oauth/introspect', (req: Request, res: Response) => {
  const token = String(req.body?.token || '');
  const p = verifyToken(token);
  if (!p) return void res.json({ active: false });
  res.json({ active: true, sub: p.sub, email: p.email, name: p.name });
});

// Продукт (flows) питає доступи користувача: роль + дозволені проєкти. Server-to-server, client-authed.
// role: 'superadmin' (усе) | 'user' (лише projectIds) | 'none' (немає доступу).
app.post('/oauth/permissions', async (req: Request, res: Response) => {
  try {
    const { client_id: clientId, client_secret: clientSecret, userId, product } = req.body || {};
    const client = await prisma.oAuthClient.findUnique({ where: { clientId } });
    if (!client || client.clientSecret !== clientSecret) return void res.status(401).json({ error: 'invalid_client' });
    if (!userId || !product) return void res.status(400).json({ error: 'userId і product обовʼязкові' });
    const acc = await prisma.access.findUnique({ where: { userId_product: { userId, product: String(product) } } });
    if (!acc) return void res.json({ role: 'none', projectIds: [], pageIds: [] });
    let projectIds: string[] = [];
    try { projectIds = JSON.parse(acc.projectIds || '[]'); } catch { /* [] */ }
    let pageIds: string[] = [];
    try { pageIds = JSON.parse(acc.pageIds || '[]'); } catch { /* [] */ }
    res.json({ role: acc.role, projectIds, pageIds });
  } catch (err) {
    res.status(500).json({ error: String(err) });
  }
});

// ── Google OAuth (потрібні GOOGLE_CLIENT_ID/SECRET) ─────────
app.get('/auth/google', (req: Request, res: Response) => {
  const cid = process.env.GOOGLE_CLIENT_ID;
  if (!cid) return void res.status(501).json({ error: 'Google вхід не налаштовано (GOOGLE_CLIENT_ID)' });
  const redirect = `${BASE_URL}/auth/google/callback`;
  const params = new URLSearchParams({ client_id: cid, redirect_uri: redirect, response_type: 'code', scope: 'openid email profile', state: String(req.query.state || '') });
  res.redirect(`https://accounts.google.com/o/oauth2/v2/auth?${params}`);
});
// callback — обмін коду, мердж за email, видача токена (спрощено; повний обмін — коли будуть креди)

// ── Адмінка (для власника) ─────────────────────────────────
function requireAdmin(req: Request, res: Response): boolean {
  if ((req.header('x-admin-key') || '') !== ADMIN_API_KEY) {
    res.status(401).json({ error: 'admin key required' });
    return false;
  }
  return true;
}
app.get('/admin/users', async (req: Request, res: Response) => {
  if (!requireAdmin(req, res)) return;
  const users = await prisma.user.findMany({ orderBy: { createdAt: 'desc' }, include: { identities: { select: { provider: true } } } });
  res.json({ users: users.map((u) => ({ id: u.id, email: u.email, displayName: u.displayName, status: u.status, providers: u.identities.map((i) => i.provider), createdAt: u.createdAt })) });
});
app.patch('/admin/users/:id', async (req: Request, res: Response) => {
  if (!requireAdmin(req, res)) return;
  const status = req.body?.status;
  if (!['active', 'disabled'].includes(status)) return void res.status(422).json({ error: 'status active|disabled' });
  const user = await prisma.user.update({ where: { id: req.params.id }, data: { status } });
  res.json({ user: { id: user.id, email: user.email, status: user.status } });
});
app.post('/admin/clients', async (req: Request, res: Response) => {
  if (!requireAdmin(req, res)) return;
  const { name, redirectUris } = req.body || {};
  if (!name) return void res.status(400).json({ error: 'name required' });
  const clientId = 'cli_' + randomBytes(10).toString('hex');
  const clientSecret = randomBytes(24).toString('hex');
  await prisma.oAuthClient.create({ data: { clientId, clientSecret, name, redirectUris: JSON.stringify(Array.isArray(redirectUris) ? redirectUris : []) } });
  res.json({ clientId, clientSecret, name });
});

// ── Доступи («Компанії») ────────────────────────────────────
// Список користувачів із їхньою роллю/проєктами для продукту (за замовч. flows).
app.get('/admin/access', async (req: Request, res: Response) => {
  if (!requireAdmin(req, res)) return;
  const product = String(req.query.product || 'flows');
  const users = await prisma.user.findMany({ orderBy: { createdAt: 'desc' } });
  const accesses = await prisma.access.findMany({ where: { product } });
  const byUser = new Map(accesses.map((a) => [a.userId, a]));
  res.json({
    product,
    users: users.map((u) => {
      const a = byUser.get(u.id);
      let projectIds: string[] = [];
      try { projectIds = a ? JSON.parse(a.projectIds || '[]') : []; } catch { /* [] */ }
      let pageIds: string[] = [];
      try { pageIds = a ? JSON.parse(a.pageIds || '[]') : []; } catch { /* [] */ }
      return { id: u.id, email: u.email, displayName: u.displayName, status: u.status, role: a?.role || 'none', projectIds, pageIds };
    }),
  });
});

// Встановити доступ користувача (upsert; role='none' → прибрати доступ).
app.put('/admin/access', async (req: Request, res: Response) => {
  if (!requireAdmin(req, res)) return;
  const { userId, product = 'flows', role, projectIds, pageIds } = req.body || {};
  if (!userId || !['superadmin', 'user', 'none'].includes(role)) {
    return void res.status(422).json({ error: 'userId + role(superadmin|user|none)' });
  }
  if (role === 'none') {
    await prisma.access.deleteMany({ where: { userId, product: String(product) } });
    return void res.json({ ok: true, removed: true });
  }
  const pj = JSON.stringify(Array.isArray(projectIds) ? projectIds : []);
  const pgj = JSON.stringify(Array.isArray(pageIds) ? pageIds : []);
  const acc = await prisma.access.upsert({
    where: { userId_product: { userId, product: String(product) } },
    update: { role, projectIds: pj, pageIds: pgj },
    create: { userId, product: String(product), role, projectIds: pj, pageIds: pgj },
  });
  res.json({ ok: true, access: { userId, product, role: acc.role, projectIds: JSON.parse(acc.projectIds), pageIds: JSON.parse(acc.pageIds) } });
});

// ── «Компанії»: керування доступами flows (сесійна авторизація SSO-суперадміна) ──
const FLOWS_URL = process.env.FLOWS_URL || 'https://flows.fineko.space';
const OWNER_EMAILS = (process.env.OWNER_EMAILS || 'olexandrmatsuk@gmail.com').split(',').map((s) => s.trim().toLowerCase());

async function flowsSuperadmin(req: Request) {
  const user = await currentUser(req);
  if (!user || user.status !== 'active') return null;
  if (OWNER_EMAILS.includes((user.email || '').toLowerCase())) return user; // bootstrap-власник
  const acc = await prisma.access.findUnique({ where: { userId_product: { userId: user.id, product: 'flows' } } });
  return acc && acc.role === 'superadmin' ? user : null;
}

async function fetchFlowsProjects(): Promise<Array<{ id: string; name: string }>> {
  const client = await prisma.oAuthClient.findFirst({ where: { name: 'flows' } });
  if (!client) return [];
  try {
    const r = await fetch(`${FLOWS_URL}/api/auth/sso/projects`, { headers: { 'x-sso-secret': client.clientSecret } });
    const j: any = await r.json();
    return Array.isArray(j.projects) ? j.projects : [];
  } catch { return []; }
}

// Сторінки (пункти меню) flows, для яких можна давати доступ по одній конкретному
// користувачу з роллю 'user' — окремо від project-обмежень. Список читаємо з flows
// (джерело правди — Sidebar.jsx), щоб не тримати дублікат тут вручну.
async function fetchFlowsPages(): Promise<Array<{ id: string; label: string }>> {
  const client = await prisma.oAuthClient.findFirst({ where: { name: 'flows' } });
  if (!client) return [];
  try {
    const r = await fetch(`${FLOWS_URL}/api/auth/sso/pages`, { headers: { 'x-sso-secret': client.clientSecret } });
    const j: any = await r.json();
    return Array.isArray(j.pages) ? j.pages : [];
  } catch { return []; }
}

// ── Реєстр продуктів екосистеми ─────────────────────────────
// Ключ = значення Access.product І назва OAuthClient. Каталог (проєкти/сторінки)
// читаємо з самого продукту тим самим контрактом, що вже працює для flows:
//   GET <url>/api/auth/sso/projects  → { projects: [{id,name}] }
//   GET <url>/api/auth/sso/pages     → { pages:    [{id,label}] }
// Продукт, який ще не має цих ендпоінтів, не ламає панель — показуємо його
// з роллю без деталізації і поміткою, що каталог недоступний.
interface ProductDef { key: string; label: string; url: string }

const PRODUCTS: ProductDef[] = [
  { key: 'flows', label: 'Воронки', url: FLOWS_URL },
  { key: 'org', label: 'Орг.структура', url: process.env.ORG_URL || 'https://org.fineko.space' },
  { key: 'content2', label: 'Контент', url: process.env.CONTENT_URL || 'https://content2.fineko.space' },
  { key: 'tracker', label: 'Трекер', url: process.env.TRACKER_URL || 'https://tasks2.fineko.space' },
];

interface Catalog {
  projects: Array<{ id: string; name: string }>;
  pages: Array<{ id: string; label: string }>;
  ok: boolean;
  note: string | null;
}

async function fetchCatalog(prod: ProductDef): Promise<Catalog> {
  const empty = (note: string): Catalog => ({ projects: [], pages: [], ok: false, note });
  const client = await prisma.oAuthClient.findFirst({ where: { name: prod.key } });
  if (!client) return empty('OAuth-клієнт не зареєстрований у SSO');

  const get = async (path: string) => {
    const r = await fetch(`${prod.url}/api/auth/sso/${path}`, {
      headers: { 'x-sso-secret': client.clientSecret },
      signal: AbortSignal.timeout(6000),
    });
    if (!r.ok) throw new Error(`HTTP ${r.status}`);
    return r.json() as any;
  };

  let projects: Array<{ id: string; name: string }> = [];
  let pages: Array<{ id: string; label: string }> = [];
  let note: string | null = null;
  try {
    const j = await get('projects');
    projects = Array.isArray(j.projects) ? j.projects : [];
  } catch (e: any) {
    note = `проєкти недоступні (${e.message})`;
  }
  try {
    const j = await get('pages');
    pages = Array.isArray(j.pages) ? j.pages : [];
  } catch (e: any) {
    note = note ? `${note}; сторінки недоступні` : `сторінки недоступні (${e.message})`;
  }
  return { projects, pages, ok: note === null, note };
}

/** Панель доступів: власник або суперадмін БУДЬ-ЯКОГО продукту. */
async function requireOwnerUI(req: Request) {
  const user = await currentUser(req);
  if (!user || user.status !== 'active') return null;
  if (OWNER_EMAILS.includes((user.email || '').toLowerCase())) return user;
  const any = await prisma.access.findFirst({ where: { userId: user.id, role: 'superadmin' } });
  return any ? user : null;
}

// Уся картина доступів: користувачі × продукти + каталоги. Одним запитом,
// щоб панель не робила N викликів і не мигала.
app.get('/admin/overview', async (req: Request, res: Response) => {
  const me = await requireAdminSession(req);
  if (!me) return void res.status(401).json({ error: 'unauthorized' });

  const [users, accesses, catalogs] = await Promise.all([
    prisma.user.findMany({ orderBy: { createdAt: 'desc' }, include: { identities: { select: { provider: true } } } }),
    prisma.access.findMany(),
    Promise.all(PRODUCTS.map((p) => fetchCatalog(p))),
  ]);

  const byUserProduct = new Map(accesses.map((a) => [`${a.userId}::${a.product}`, a]));
  const parse = (v: string | null | undefined): string[] => {
    try { return JSON.parse(v || '[]'); } catch { return []; }
  };

  res.json({
    me: { email: me.email },
    products: PRODUCTS.map((p, i) => ({ key: p.key, label: p.label, url: p.url, catalog: catalogs[i] })),
    users: users.map((u) => ({
      id: u.id,
      email: u.email,
      displayName: u.displayName,
      status: u.status,
      providers: u.identities.map((i) => i.provider),
      createdAt: u.createdAt,
      access: Object.fromEntries(PRODUCTS.map((p) => {
        const a = byUserProduct.get(`${u.id}::${p.key}`);
        return [p.key, {
          role: a?.role || 'none',
          projectIds: parse(a?.projectIds),
          pageIds: parse(a?.pageIds),
        }];
      })),
    })),
  });
});

// Зміна доступу з панелі. Окремо від /admin/access (той під x-admin-key для скриптів),
// бо тут авторизація кукою живої людини.
app.put('/admin/overview/access', async (req: Request, res: Response) => {
  const me = await requireAdminSession(req);
  if (!me) return void res.status(401).json({ error: 'unauthorized' });

  const { userId, product, role, projectIds, pageIds } = req.body || {};
  if (!userId || !PRODUCTS.some((p) => p.key === product)) {
    return void res.status(422).json({ error: 'userId + відомий product обовʼязкові' });
  }
  if (!['superadmin', 'user', 'none'].includes(role)) {
    return void res.status(422).json({ error: 'role: superadmin | user | none' });
  }

  // Захист від самоблокування: власник не має відібрати доступ сам у себе випадково.
  if (userId === me.id && role === 'none') {
    return void res.status(409).json({ error: 'Не можна прибрати доступ самому собі' });
  }

  if (role === 'none') {
    await prisma.access.deleteMany({ where: { userId, product } });
    return void res.json({ ok: true, removed: true });
  }

  const pj = JSON.stringify(Array.isArray(projectIds) ? projectIds : []);
  const pg = JSON.stringify(Array.isArray(pageIds) ? pageIds : []);
  await prisma.access.upsert({
    where: { userId_product: { userId, product } },
    update: { role, projectIds: pj, pageIds: pg },
    create: { userId, product, role, projectIds: pj, pageIds: pg },
  });
  res.json({ ok: true });
});

app.get('/companies/data', async (req: Request, res: Response) => {
  const admin = await flowsSuperadmin(req);
  if (!admin) return void res.status(401).json({ error: 'unauthorized' });
  const [users, accesses, projects, pages] = await Promise.all([
    prisma.user.findMany({ orderBy: { createdAt: 'desc' } }),
    prisma.access.findMany({ where: { product: 'flows' } }),
    fetchFlowsProjects(),
    fetchFlowsPages(),
  ]);
  const byUser = new Map(accesses.map((a) => [a.userId, a]));
  res.json({
    projects,
    pages,
    users: users.map((u) => {
      const a = byUser.get(u.id);
      let projectIds: string[] = [];
      try { projectIds = a ? JSON.parse(a.projectIds || '[]') : []; } catch { /* [] */ }
      let pageIds: string[] = [];
      try { pageIds = a ? JSON.parse(a.pageIds || '[]') : []; } catch { /* [] */ }
      return { id: u.id, email: u.email, displayName: u.displayName, status: u.status, role: a?.role || 'none', projectIds, pageIds };
    }),
  });
});

app.put('/companies/access', async (req: Request, res: Response) => {
  const admin = await flowsSuperadmin(req);
  if (!admin) return void res.status(401).json({ error: 'unauthorized' });
  const { userId, role, projectIds, pageIds } = req.body || {};
  if (!userId || !['superadmin', 'user', 'none'].includes(role)) return void res.status(422).json({ error: 'bad_input' });
  if (role === 'none') { await prisma.access.deleteMany({ where: { userId, product: 'flows' } }); return void res.json({ ok: true }); }
  const pj = JSON.stringify(Array.isArray(projectIds) ? projectIds : []);
  const pgj = JSON.stringify(Array.isArray(pageIds) ? pageIds : []);
  await prisma.access.upsert({
    where: { userId_product: { userId, product: 'flows' } },
    update: { role, projectIds: pj, pageIds: pgj },
    create: { userId, product: 'flows', role, projectIds: pj, pageIds: pgj },
  });
  res.json({ ok: true });
});

// Видача одноразового посилання в панель. Доступна власнику/суперадміну
// за звичайною сесією — саме тут відбувається перехід «я залогінений» → «я в адмінці».
app.post('/admin/ticket', async (req: Request, res: Response) => {
  const me = await requireOwnerUI(req);
  if (!me) return void res.status(401).json({ error: 'unauthorized' });
  res.json({ url: `${BASE_URL}/admin/enter?t=${issueAdminTicket(me.id)}`, ttlSeconds: ADMIN_TICKET_TTL });
});

// Обмін квитка на коротку адмін-сесію. Токен гаситься, і ми одразу редіректимо
// на чистий /admin — щоб він не лишився в історії браузера.
app.get('/admin/enter', async (req: Request, res: Response) => {
  const userId = consumeAdminTicket(String(req.query.t || ''));
  if (!userId) return void res.status(410).type('html').send(ssoPage('Посилання недійсне',
    '<h1>Посилання вже використане або протухло</h1><p>Поверніться на <a href="/" style="color:#e0364f">головну SSO</a> і отримайте нове.</p>'));

  const user = await prisma.user.findUnique({ where: { id: userId } });
  if (!user || user.status !== 'active') return void res.status(403).send('Доступ закрито');
  const isOwner = OWNER_EMAILS.includes((user.email || '').toLowerCase());
  const sup = isOwner ? true : !!(await prisma.access.findFirst({ where: { userId, role: 'superadmin' } }));
  if (!sup) return void res.status(403).send('Потрібні права адміністратора');

  res.cookie('admin_session', issueAdminSession(userId), {
    httpOnly: true, sameSite: 'strict', secure: SECURE_COOKIES, maxAge: ADMIN_SESSION_TTL * 1000, path: '/admin',
  });
  res.redirect('/admin');
});

// Саму сторінку теж ховаємо: без адмін-сесії її наче й немає.
app.get('/admin', async (req: Request, res: Response) => {
  const me = await requireAdminSession(req);
  if (!me) return void res.status(404).send('Cannot GET /admin');
  res.type('html').send(adminPage());
});

app.post('/admin/exit', (_req: Request, res: Response) => {
  res.cookie('admin_session', '', { httpOnly: true, maxAge: 0, path: '/admin' });
  res.json({ ok: true });
});
app.get('/companies', (_req: Request, res: Response) => void res.type('html').send(companiesPage()));

function loginPage(clientId: string, redirectUri: string, state: string, error: string): string {
  const esc = (s: string) => s.replace(/"/g, '&quot;').replace(/</g, '&lt;');
  return `<!doctype html><html lang="uk"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>FINEKO — вхід</title><link rel="icon" type="image/svg+xml" href="/favicon.svg">
<style>body{font-family:system-ui;background:linear-gradient(rgba(13,17,23,.5),rgba(13,17,23,.82)),url('/login-bg.png') center/cover fixed,#0d1117;color:#e6edf3;display:flex;min-height:100vh;align-items:center;justify-content:center}
.card{background:rgba(22,27,34,.82);backdrop-filter:blur(12px);-webkit-backdrop-filter:blur(12px);border:1px solid rgba(255,255,255,.1);border-radius:14px;padding:32px;width:340px;box-shadow:0 24px 70px rgba(0,0,0,.5)}
h1{font-size:18px;margin:0 0 4px}p{color:#8b949e;font-size:13px;margin:0 0 20px}
input{width:100%;box-sizing:border-box;padding:10px;margin-bottom:12px;background:#0d1117;border:1px solid #30363d;border-radius:8px;color:#e6edf3}
button{width:100%;padding:11px;background:#238636;color:#fff;border:0;border-radius:8px;font-weight:600;cursor:pointer}
.err{color:#f85149;font-size:13px;margin-bottom:12px}</style></head>
<body><div class="card"><h1>🔐 FINEKO</h1><p>Єдиний вхід у продукти FINEKO</p>
${error ? `<div class="err">${esc(error)}</div>` : ''}
<form method="POST" action="/authorize">
<input type="hidden" name="client_id" value="${esc(clientId)}"><input type="hidden" name="redirect_uri" value="${esc(redirectUri)}"><input type="hidden" name="state" value="${esc(state)}">
<input name="email" type="email" placeholder="email" required autofocus autocomplete="username">
<input name="password" type="password" placeholder="пароль" required autocomplete="current-password">
<button type="submit">Увійти</button></form>
<div style="text-align:center;margin-top:14px"><a href="/forgot-password" style="color:#8b949e;font-size:13px;text-decoration:underline">Забули пароль?</a></div>
</div></body></html>`;
}

// Обгортка сторінки SSO (спільний стиль)
function ssoPage(title: string, inner: string): string {
  return `<!doctype html><html lang="uk"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${title}</title><link rel="icon" type="image/svg+xml" href="/favicon.svg">
<style>body{font-family:system-ui;background:linear-gradient(rgba(13,17,23,.5),rgba(13,17,23,.82)),url('/login-bg.png') center/cover fixed,#0d1117;color:#e6edf3;display:flex;min-height:100vh;align-items:center;justify-content:center}
.card{background:rgba(22,27,34,.82);backdrop-filter:blur(12px);-webkit-backdrop-filter:blur(12px);border:1px solid rgba(255,255,255,.1);border-radius:14px;padding:32px;width:340px;box-shadow:0 24px 70px rgba(0,0,0,.5)}
h1{font-size:18px;margin:0 0 4px}p{color:#8b949e;font-size:13px;margin:0 0 20px}
input{width:100%;box-sizing:border-box;padding:10px;margin-bottom:12px;background:#0d1117;border:1px solid #30363d;border-radius:8px;color:#e6edf3}
button{width:100%;padding:11px;background:#238636;color:#fff;border:0;border-radius:8px;font-weight:600;cursor:pointer}
.msg{font-size:13px;margin:12px 0}.ok{color:#3fb950}.err{color:#f85149}a{color:#58a6ff}</style></head>
<body><div class="card">${inner}</div></body></html>`;
}

// Сторінка «Забули пароль?» — вводимо email, шлемо на POST /forgot-password.
function forgotPage(): string {
  return ssoPage('FINEKO — відновлення пароля', `<h1>🔐 Відновлення пароля</h1><p>Введіть email — надішлемо посилання для скидання.</p>
<input id="email" type="email" placeholder="email" autocomplete="username" autofocus>
<button onclick="go()">Надіслати посилання</button>
<div id="msg" class="msg"></div>
<div style="text-align:center;margin-top:10px"><a href="javascript:history.back()">← Назад до входу</a></div>
<script>
async function go(){var e=document.getElementById('email').value.trim();var m=document.getElementById('msg');
if(!e){m.className='msg err';m.textContent='Введіть email';return;}
m.className='msg';m.textContent='Надсилаю…';
try{var r=await fetch('/forgot-password',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({email:e})});var d=await r.json();
m.className='msg ok';m.innerHTML=(d.message||'Якщо акаунт існує, ми надіслали посилання.')+(d.devLink?'<br><br>Локальне посилання:<br><a href="'+d.devLink+'">'+d.devLink+'</a>':'');
}catch(_){m.className='msg err';m.textContent='Помилка. Спробуйте пізніше.';}}
</script>`);
}

// Сторінка скидання пароля за токеном.
function resetPage(token: string): string {
  const t = token.replace(/[^a-f0-9]/gi, '');
  return ssoPage('FINEKO — новий пароль', `<h1>🔐 Новий пароль</h1><p>Введіть новий пароль до акаунта FINEKO.</p>
<input id="pw" type="password" placeholder="новий пароль (мін. 6)" autocomplete="new-password" autofocus>
<button onclick="go()">Зберегти пароль</button>
<div id="msg" class="msg"></div>
<script>
async function go(){var p=document.getElementById('pw').value;var m=document.getElementById('msg');
if(!p||p.length<6){m.className='msg err';m.textContent='Пароль мінімум 6 символів';return;}
m.className='msg';m.textContent='Зберігаю…';
try{var r=await fetch('/reset-password',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({token:'${t}',password:p})});var d=await r.json();
if(r.ok){m.className='msg ok';m.innerHTML='✅ '+(d.message||'Пароль оновлено.')+'<br><br><a href="/">Повернутись</a>';}
else{m.className='msg err';m.textContent=d.error||'Не вдалося оновити.';}
}catch(_){m.className='msg err';m.textContent='Помилка. Спробуйте пізніше.';}}
</script>`);
}

// Сторінка «Компанії» — керування доступами користувачів до Воронок.
function companiesPage(): string {
  return `<!doctype html><html lang="uk"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>FINEKO — Компанії</title><link rel="icon" type="image/svg+xml" href="/favicon.svg">
<style>
body{font-family:system-ui;margin:0;background:linear-gradient(rgba(13,17,23,.6),rgba(13,17,23,.9)),url('/login-bg.png') center/cover fixed,#0b0f1a;color:#e6edf3;min-height:100vh}
.wrap{max-width:920px;margin:0 auto;padding:24px 16px}
h1{font-size:22px;margin:0 0 4px}.sub{color:#8b949e;font-size:13px;margin:0 0 20px}
.card{background:rgba(22,27,34,.85);border:1px solid rgba(255,255,255,.1);border-radius:12px;padding:16px;margin-bottom:12px}
.row{display:flex;align-items:center;gap:12px;flex-wrap:wrap}
.email{font-weight:600;min-width:200px;flex:1}
select,input{background:#0d1117;border:1px solid #30363d;border-radius:8px;color:#e6edf3;padding:8px}
button{background:#238636;color:#fff;border:0;border-radius:8px;padding:8px 14px;font-weight:600;cursor:pointer}
.proj{display:flex;flex-wrap:wrap;gap:8px;margin-top:10px}
.proj label{display:flex;align-items:center;gap:6px;background:#0d1117;border:1px solid #30363d;border-radius:8px;padding:6px 10px;font-size:13px;cursor:pointer}
.muted{color:#8b949e;font-size:12px}#msg{font-size:13px;margin:8px 0;min-height:18px}
.login{max-width:340px;margin:60px auto}
</style></head>
<body><div class="wrap">
<h1>🏢 Компанії — доступи до Воронок</h1>
<p class="sub">Признач роль і проєкти кожному користувачу. Доступи одразу читаються Воронками при вході.</p>
<div id="app">Завантаження…</div><div id="msg"></div>
</div>
<script>
var PROJECTS=[];var PAGES=[];
function esc(s){return String(s==null?'':s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/"/g,'&quot;');}
async function load(){
  var r=await fetch('/companies/data',{credentials:'include'});
  if(r.status===401){renderLogin();return;}
  var d=await r.json();PROJECTS=d.projects||[];PAGES=d.pages||[];renderUsers(d.users||[]);
}
function renderLogin(){
  document.getElementById('app').innerHTML='<div class="card login"><div style="font-size:18px;font-weight:600;margin-bottom:6px">🔐 Вхід</div><p class="sub">Увійдіть як суперадмін FINEKO.</p><input id="e" type="email" placeholder="email" style="width:100%;box-sizing:border-box;margin-bottom:10px"><input id="p" type="password" placeholder="пароль" style="width:100%;box-sizing:border-box;margin-bottom:10px"><button id="loginBtn" style="width:100%">Увійти</button><div id="le" class="muted" style="margin-top:8px"></div></div>';
}
function projChecks(u){
  return PROJECTS.map(function(pr){var on=(u.projectIds||[]).indexOf(pr.id)>=0;return '<label><input type="checkbox" class="projchk" data-uid="'+esc(u.id)+'" value="'+esc(pr.id)+'" '+(on?'checked':'')+'>'+esc(pr.name)+'</label>';}).join('');
}
function pageChecks(u){
  if(!PAGES.length) return '<span class="muted">Список сторінок недоступний (flows не відповідає).</span>';
  return PAGES.map(function(pg){var on=(u.pageIds||[]).indexOf(pg.id)>=0;return '<label><input type="checkbox" class="pagechk" data-uid="'+esc(u.id)+'" value="'+esc(pg.id)+'" '+(on?'checked':'')+'>'+esc(pg.label)+'</label>';}).join('');
}
function roleOpt(v,cur,t){return '<option value="'+v+'"'+(cur===v?' selected':'')+'>'+t+'</option>';}
function renderUsers(users){
  var html=users.map(function(u){
    return '<div class="card"><div class="row">'+
      '<span class="email">'+esc(u.displayName||u.email)+'<div class="muted">'+esc(u.email)+' · '+esc(u.status)+'</div></span>'+
      '<select class="role" data-uid="'+esc(u.id)+'">'+roleOpt('none',u.role,'Немає доступу')+roleOpt('user',u.role,'Користувач (обрані проєкти)')+roleOpt('superadmin',u.role,'Суперадмін (усе)')+'</select>'+
      '<button class="save-btn" data-uid="'+esc(u.id)+'">Зберегти</button></div>'+
      '<div class="proj" id="proj-'+esc(u.id)+'" style="'+(u.role==='user'?'':'display:none')+'">'+projChecks(u)+'</div>'+
      '<div class="muted" id="pagelbl-'+esc(u.id)+'" style="'+(u.role==='user'?'':'display:none')+';margin-top:10px">Додаткові сторінки (крім базових — Воронки/Аналітика/Сесії/Підписники, вони завжди доступні):</div>'+
      '<div class="proj" id="page-'+esc(u.id)+'" style="'+(u.role==='user'?'':'display:none')+'">'+pageChecks(u)+'</div></div>';
  }).join('');
  document.getElementById('app').innerHTML=html||'<div class="muted">Немає користувачів.</div>';
}
document.addEventListener('change',function(ev){
  var t=ev.target;if(t&&t.classList&&t.classList.contains('role')){var uid=t.getAttribute('data-uid');
    var el=document.getElementById('proj-'+uid);if(el)el.style.display=(t.value==='user')?'flex':'none';
    var pl=document.getElementById('pagelbl-'+uid);if(pl)pl.style.display=(t.value==='user')?'block':'none';
    var pg=document.getElementById('page-'+uid);if(pg)pg.style.display=(t.value==='user')?'flex':'none';
  }
});
document.addEventListener('click',async function(ev){
  var t=ev.target;if(!t)return;
  if(t.id==='loginBtn'){
    var e=document.getElementById('e').value.trim(),p=document.getElementById('p').value;
    var r=await fetch('/login',{method:'POST',headers:{'Content-Type':'application/json'},credentials:'include',body:JSON.stringify({email:e,password:p})});
    if(r.ok){location.reload();}else{document.getElementById('le').textContent='Невірний email або пароль';}
  }
  if(t.classList&&t.classList.contains('save-btn')){
    var uid=t.getAttribute('data-uid');
    var role=document.querySelector('.role[data-uid="'+uid+'"]').value;
    var ids=[];document.querySelectorAll('.projchk[data-uid="'+uid+'"]:checked').forEach(function(c){ids.push(c.value);});
    var pids=[];document.querySelectorAll('.pagechk[data-uid="'+uid+'"]:checked').forEach(function(c){pids.push(c.value);});
    var rr=await fetch('/companies/access',{method:'PUT',headers:{'Content-Type':'application/json'},credentials:'include',body:JSON.stringify({userId:uid,role:role,projectIds:ids,pageIds:pids})});
    var m=document.getElementById('msg');
    if(rr.ok){m.style.color='#3fb950';m.textContent='✅ Збережено о '+new Date().toLocaleTimeString();}else{m.style.color='#f85149';m.textContent='Помилка збереження';}
  }
});
load();
</script></body></html>`;
}

// Захист: жоден необроблений reject/exception не має класти сервіс
process.on('unhandledRejection', (reason) => {
  // eslint-disable-next-line no-console
  console.error('[fineko-sso] unhandledRejection:', reason);
});
process.on('uncaughtException', (err) => {
  // eslint-disable-next-line no-console
  console.error('[fineko-sso] uncaughtException:', err);
});

app.listen(PORT, () => {
  // eslint-disable-next-line no-console
  console.log(`[fineko-sso] listening on ${BASE_URL}`);
});

// ── Панель доступів (усі продукти) ──────────────────────────
// Свідомо без фреймворків і збірки: SSO — маленький сервіс, і його панель
// має відкриватись навіть тоді, коли решта екосистеми лежить.
function adminPage(): string {
  return `<!doctype html><html lang="uk"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>FINEKO — Доступи</title><link rel="icon" type="image/svg+xml" href="/favicon.svg">
<style>
body{font-family:system-ui;margin:0;background:linear-gradient(rgba(13,17,23,.6),rgba(13,17,23,.9)),url('/login-bg.png') center/cover fixed,#0b0f1a;color:#e6edf3;min-height:100vh}
.wrap{max-width:1180px;margin:0 auto;padding:24px 16px}
h1{font-size:22px;margin:0 0 4px}.sub{color:#8b949e;font-size:13px;margin:0 0 18px}
.card{background:rgba(22,27,34,.85);border:1px solid rgba(255,255,255,.1);border-radius:12px;padding:16px;margin-bottom:12px}
.top{display:flex;gap:10px;flex-wrap:wrap;align-items:center;margin-bottom:14px}
.pill{background:rgba(22,27,34,.85);border:1px solid rgba(255,255,255,.12);border-radius:999px;padding:6px 12px;font-size:12px}
.pill b{color:#e6edf3}.pill.off{opacity:.55}
.uhead{display:flex;align-items:center;gap:12px;flex-wrap:wrap;margin-bottom:10px}
.email{font-weight:600}.muted{color:#8b949e;font-size:12px}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:10px}
.prod{background:#0d1117;border:1px solid #30363d;border-radius:10px;padding:10px}
.prod h4{margin:0 0 8px;font-size:13px;display:flex;justify-content:space-between;align-items:center;gap:8px}
.warn{color:#d29922;font-size:11px;font-weight:400;cursor:help}
select,input{background:#0d1117;border:1px solid #30363d;border-radius:8px;color:#e6edf3;padding:7px;font-size:13px}
select{width:100%}
button{background:#238636;color:#fff;border:0;border-radius:8px;padding:8px 14px;font-weight:600;cursor:pointer}
.chk{display:flex;flex-wrap:wrap;gap:6px;margin-top:8px}
.chk label{display:flex;align-items:center;gap:5px;background:#161b22;border:1px solid #30363d;border-radius:7px;padding:4px 8px;font-size:12px;cursor:pointer}
.ent{border:1px solid #21262d;border-radius:8px;padding:8px;margin-top:8px;background:rgba(0,0,0,.18)}
.ent-h{display:flex;justify-content:space-between;align-items:center;gap:8px;font-size:11px;color:#8b949e;margin-bottom:6px}
.ent-h b{color:#c9d1d9;font-weight:600}
.ent-a{font-size:11px;color:#58a6ff;cursor:pointer;text-decoration:underline}
.ent-empty{font-size:11px;color:#6e7681;font-style:italic}
.sect{font-size:11px;color:#8b949e;margin-top:8px}
.exit{background:none;border:1px solid #30363d;color:#8b949e;border-radius:8px;padding:7px 12px;font-size:12px;cursor:pointer}
#msg{font-size:13px;margin:8px 0;min-height:18px}
.login{max-width:340px;margin:60px auto}
.badge{font-size:11px;border-radius:6px;padding:2px 7px;border:1px solid #30363d}
.b-none{color:#8b949e}.b-user{color:#58a6ff;border-color:#1f6feb}.b-super{color:#f0883e;border-color:#9e6a03}
</style></head>
<body><div class="wrap">
<h1>Доступи до продуктів FINEKO</h1>
<p class="sub">Усі користувачі й усі продукти в одному місці. Проєкти та сторінки читаються з самих сервісів, тож список не треба підтримувати вручну.</p>
<div class="top" id="top"></div>
<div style="display:flex;justify-content:space-between;align-items:center;gap:10px;margin-bottom:10px"><span class="muted">Сесія панелі коротка — коли протухне, візьміть нове разове посилання на головній SSO.</span><button class="exit" id="exitBtn">Вийти з панелі</button></div>
<input id="q" placeholder="пошук за email або імʼям" style="width:100%;box-sizing:border-box;margin-bottom:12px">
<div id="app">Завантаження…</div><div id="msg"></div>
</div>
<script>
var DATA=null;
function esc(s){return String(s==null?'':s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/"/g,'&quot;');}

async function load(){
  var r=await fetch('/admin/overview',{credentials:'include'});
  if(r.status===401){location.href='/';return;}
  DATA=await r.json();
  renderTop();render();
}
function renderLogin(){
  document.getElementById('top').innerHTML='';
  document.getElementById('app').innerHTML='<div class="card login"><div style="font-size:18px;font-weight:600;margin-bottom:6px">Вхід</div><p class="sub">Потрібні права власника або суперадміна.</p><input id="e" type="email" placeholder="email" style="width:100%;box-sizing:border-box;margin-bottom:10px"><input id="p" type="password" placeholder="пароль" style="width:100%;box-sizing:border-box;margin-bottom:10px"><button id="loginBtn" style="width:100%">Увійти</button><div id="le" class="muted" style="margin-top:8px"></div></div>';
}
function renderTop(){
  var html=DATA.products.map(function(p){
    var n=DATA.users.filter(function(u){return u.access[p.key] && u.access[p.key].role!=='none';}).length;
    var cat=p.catalog.ok?(p.catalog.projects.length+' проєктів, '+p.catalog.pages.length+' сторінок'):'каталог недоступний';
    return '<span class="pill'+(p.catalog.ok?'':' off')+'"><b>'+esc(p.label)+'</b> — '+n+' з доступом, '+esc(cat)+'</span>';
  }).join('');
  document.getElementById('top').innerHTML=html+'<span class="pill">ви: <b>'+esc(DATA.me.email)+'</b></span>';
}
function badge(role){
  if(role==='superadmin')return '<span class="badge b-super">суперадмін</span>';
  if(role==='user')return '<span class="badge b-user">користувач</span>';
  return '<span class="badge b-none">немає</span>';
}
function opt(v,cur,t){return '<option value="'+v+'"'+(cur===v?' selected':'')+'>'+t+'</option>';}

// Кожна сутність — окремий блок із заголовком, лічильником і швидким вибором.
// Так видно, що саме відкрито: проєкти і пункти меню це різні речі.
function entity(id,title,cls,list,checked,labelField,emptyText){
  if(!list.length) return '<div class="ent"><div class="ent-h"><b>'+esc(title)+'</b></div><div class="ent-empty">'+esc(emptyText)+'</div></div>';
  var boxes=list.map(function(x){
    var on=checked.indexOf(x.id)>=0;
    return '<label><input type="checkbox" class="'+cls+'" data-k="'+esc(id)+'" value="'+esc(x.id)+'"'+(on?' checked':'')+'>'+esc(x[labelField])+'</label>';
  }).join('');
  var n=list.filter(function(x){return checked.indexOf(x.id)>=0;}).length;
  return '<div class="ent"><div class="ent-h"><b>'+esc(title)+'</b>'+
    '<span>'+n+' з '+list.length+' &nbsp;'+
    '<span class="ent-a bulk" data-c="'+cls+'" data-k="'+esc(id)+'" data-v="1">усі</span> / '+
    '<span class="ent-a bulk" data-c="'+cls+'" data-k="'+esc(id)+'" data-v="0">жодного</span></span></div>'+
    '<div class="chk">'+boxes+'</div></div>';
}

function prodBlock(u,p){
  var a=u.access[p.key]||{role:'none',projectIds:[],pageIds:[]};
  var id=u.id+'--'+p.key;
  var warn=p.catalog.ok?'':'<span class="warn" title="'+esc(p.catalog.note||'')+'">каталог н/д</span>';
  var body='';
  if(p.catalog.ok){
    body='<div class="detail" id="d-'+esc(id)+'" style="'+(a.role==='user'?'':'display:none')+'">'+
      entity(id,'Проєкти','pchk',p.catalog.projects,a.projectIds,'name','Проєктів у цьому сервісі немає')+
      entity(id,'Сторінки меню','gchk',p.catalog.pages,a.pageIds,'label','Сторінки не оголошені сервісом')+
      '</div>';
  }
  return '<div class="prod"><h4><span>'+esc(p.label)+' '+badge(a.role)+'</span>'+warn+'</h4>'+
    '<select class="role" data-k="'+esc(id)+'">'+opt('none',a.role,'Немає доступу')+opt('user',a.role,'Користувач')+opt('superadmin',a.role,'Суперадмін')+'</select>'+
    body+'</div>';
}

function render(){
  var q=(document.getElementById('q').value||'').trim().toLowerCase();
  var users=DATA.users.filter(function(u){
    if(!q)return true;
    return (u.email||'').toLowerCase().indexOf(q)>=0||(u.displayName||'').toLowerCase().indexOf(q)>=0;
  });
  var html=users.map(function(u){
    return '<div class="card"><div class="uhead">'+
      '<span class="email">'+esc(u.displayName||u.email)+'</span>'+
      '<span class="muted">'+esc(u.email)+' · '+esc(u.status)+' · '+esc((u.providers||[]).join(', ')||'без провайдера')+'</span>'+
      '<span style="flex:1"></span>'+
      '<button class="save" data-uid="'+esc(u.id)+'">Зберегти</button></div>'+
      '<div class="grid">'+DATA.products.map(function(p){return prodBlock(u,p);}).join('')+'</div></div>';
  }).join('');
  document.getElementById('app').innerHTML=html||'<div class="card muted">Нікого не знайдено.</div>';
}

document.addEventListener('input',function(ev){if(ev.target&&ev.target.id==='q'&&DATA)render();});
document.addEventListener('change',function(ev){
  var t=ev.target;
  if(t&&t.classList&&t.classList.contains('role')){
    var d=document.getElementById('d-'+t.getAttribute('data-k'));
    if(d)d.style.display=(t.value==='user')?'block':'none';
  }
});
document.addEventListener('click',async function(ev){
  var t=ev.target;if(!t)return;
  if(t.classList&&t.classList.contains('bulk')){
    var want=t.getAttribute('data-v')==='1';
    document.querySelectorAll('.'+t.getAttribute('data-c')+'[data-k="'+t.getAttribute('data-k')+'"]').forEach(function(c){c.checked=want;});
    return;
  }
  if(t.id==='exitBtn'){
    await fetch('/admin/exit',{method:'POST',credentials:'include'});
    location.href='/';
    return;
  }
  if(t.classList&&t.classList.contains('save')){
    var uid=t.getAttribute('data-uid');
    var m=document.getElementById('msg');
    var okAll=true,errText='';
    for(var i=0;i<DATA.products.length;i++){
      var pk=DATA.products[i].key,k=uid+'--'+pk;
      var sel=document.querySelector('.role[data-k="'+k+'"]');if(!sel)continue;
      var ids=[];document.querySelectorAll('.pchk[data-k="'+k+'"]:checked').forEach(function(c){ids.push(c.value);});
      var gids=[];document.querySelectorAll('.gchk[data-k="'+k+'"]:checked').forEach(function(c){gids.push(c.value);});
      var rr=await fetch('/admin/overview/access',{method:'PUT',headers:{'Content-Type':'application/json'},credentials:'include',
        body:JSON.stringify({userId:uid,product:pk,role:sel.value,projectIds:ids,pageIds:gids})});
      if(!rr.ok){okAll=false;var j=await rr.json().catch(function(){return {};});errText=j.error||('HTTP '+rr.status);}
    }
    if(okAll){m.style.color='#3fb950';m.textContent='Збережено о '+new Date().toLocaleTimeString();await load();}
    else{m.style.color='#f85149';m.textContent='Помилка: '+errText;}
  }
});
load();
</script></body></html>`;
}

// ── Головна SSO: вхід і перелік систем ──────────────────────
// Посилання в продукти ведуть через /authorize: сесія вже є, тому SSO одразу
// видає код і кидає всередину — окремий пароль ніде вводити не треба.
app.get('/hub/data', async (req: Request, res: Response) => {
  const user = await currentUser(req);
  if (!user || user.status !== 'active') return void res.status(401).json({ error: 'unauthorized' });

  const clients = await prisma.oAuthClient.findMany();
  const byName = new Map(clients.map((c) => [c.name, c]));

  const links = PRODUCTS.map((p) => {
    const c = byName.get(p.key);
    let redirect = '';
    try { redirect = (JSON.parse(c?.redirectUris || '[]') as string[])[0] || ''; } catch { /* порожньо */ }
    const ready = Boolean(c && redirect);
    return {
      key: p.key,
      label: p.label,
      ready,
      url: ready ? `${BASE_URL}/authorize?client_id=${encodeURIComponent(c!.clientId)}&redirect_uri=${encodeURIComponent(redirect)}` : '',
      note: !c ? 'не підключений до SSO' : (!redirect ? 'не заданий redirect_uri' : ''),
    };
  });

  const isOwner = OWNER_EMAILS.includes((user.email || '').toLowerCase());
  const sup = isOwner ? true : !!(await prisma.access.findFirst({ where: { userId: user.id, role: 'superadmin' } }));

  res.json({ user: { email: user.email, displayName: user.displayName }, links, isAdmin: sup });
});

app.get('/', (_req: Request, res: Response) => void res.type('html').send(hubPage()));

function hubPage(): string {
  return `<!doctype html><html lang="uk"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>FINEKO — Єдиний вхід</title><link rel="icon" type="image/svg+xml" href="/favicon.svg">
<style>
body{font-family:system-ui;margin:0;background:linear-gradient(rgba(13,17,23,.6),rgba(13,17,23,.9)),url('/login-bg.png') center/cover fixed,#0b0f1a;color:#e6edf3;min-height:100vh}
.wrap{max-width:520px;margin:0 auto;padding:48px 16px}
h1{font-size:22px;margin:0 0 4px}.sub{color:#8b949e;font-size:13px;margin:0 0 20px}
.card{background:rgba(22,27,34,.85);border:1px solid rgba(255,255,255,.1);border-radius:12px;padding:16px;margin-bottom:12px}
a.item,button.item{display:flex;align-items:center;justify-content:space-between;gap:10px;width:100%;box-sizing:border-box;
  background:#0d1117;border:1px solid #30363d;border-radius:10px;padding:12px 14px;margin-bottom:8px;
  color:#e6edf3;text-decoration:none;font-size:14px;font-weight:600;cursor:pointer;text-align:left}
a.item:hover,button.item:hover{border-color:#58a6ff}
a.item.off{opacity:.45;pointer-events:none}
button.admin{background:linear-gradient(90deg,rgba(224,54,79,.18),rgba(224,54,79,.06));border-color:#e0364f;color:#ffd9df}
button.admin:hover{border-color:#ff5470}
.tag{font-size:11px;font-weight:500;color:#8b949e}
.tag.hot{color:#ff9db0}
input{background:#0d1117;border:1px solid #30363d;border-radius:8px;color:#e6edf3;padding:10px;width:100%;box-sizing:border-box;margin-bottom:10px}
button.go{background:#238636;color:#fff;border:0;border-radius:8px;padding:10px 14px;font-weight:600;cursor:pointer;width:100%}
.muted{color:#8b949e;font-size:12px}.err{color:#f85149;font-size:13px;margin-top:8px}
.who{display:flex;justify-content:space-between;align-items:center;gap:10px;margin-bottom:14px}
.out{background:none;border:1px solid #30363d;color:#8b949e;border-radius:8px;padding:6px 10px;font-size:12px;cursor:pointer}
</style></head>
<body><div class="wrap">
<h1>FINEKO</h1>
<p class="sub">Єдиний вхід у продукти екосистеми.</p>
<div id="app" class="card">Завантаження…</div>
</div>
<script>
function esc(s){return String(s==null?'':s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/"/g,'&quot;');}

async function load(){
  var r=await fetch('/hub/data',{credentials:'include'});
  if(r.status===401){renderLogin('');return;}
  var d=await r.json();renderHub(d);
}

function renderLogin(err){
  document.getElementById('app').innerHTML=
    '<div style="font-size:16px;font-weight:600;margin-bottom:10px">Вхід</div>'+
    '<input id="e" type="email" placeholder="email" autocomplete="username">'+
    '<input id="p" type="password" placeholder="пароль" autocomplete="current-password">'+
    '<button class="go" id="loginBtn">Увійти</button>'+
    '<div class="err" id="le">'+esc(err)+'</div>'+
    '<div style="text-align:center;margin-top:12px"><a href="/forgot-password" class="muted">Забули пароль?</a></div>';
}

function renderHub(d){
  var items=d.links.map(function(l){
    if(!l.ready) return '<a class="item off"><span>'+esc(l.label)+'</span><span class="tag">'+esc(l.note)+'</span></a>';
    return '<a class="item" href="'+esc(l.url)+'"><span>'+esc(l.label)+'</span><span class="tag">увійти</span></a>';
  }).join('');

  var admin=d.isAdmin
    ? '<button class="item admin" id="adminBtn"><span>Панель доступів</span><span class="tag hot">разове посилання, 3 хв</span></button>'
    : '';

  document.getElementById('app').innerHTML=
    '<div class="who"><span class="muted">'+esc(d.user.displayName||d.user.email)+'</span>'+
    '<button class="out" id="outBtn">Вийти</button></div>'+
    items+
    (admin?'<div style="height:6px"></div>'+admin:'')+
    '<div id="ae" class="err"></div>';
}

document.addEventListener('click',async function(ev){
  var t=ev.target.closest? ev.target.closest('button'):null;
  if(!t)return;

  if(t.id==='loginBtn'){
    var e=document.getElementById('e').value.trim(),p=document.getElementById('p').value;
    var r=await fetch('/login',{method:'POST',headers:{'Content-Type':'application/json'},credentials:'include',body:JSON.stringify({email:e,password:p})});
    if(r.ok){load();}else{document.getElementById('le').textContent='Невірний email або пароль';}
    return;
  }
  if(t.id==='outBtn'){
    await fetch('/logout',{method:'POST',credentials:'include'});
    location.reload();return;
  }
  if(t.id==='adminBtn'){
    // Квиток беремо в момент кліку: він живе хвилини й спрацьовує один раз,
    // тому не має сенсу тримати його в сторінці заздалегідь.
    t.disabled=true;
    var rr=await fetch('/admin/ticket',{method:'POST',credentials:'include'});
    if(rr.ok){var j=await rr.json();location.href=j.url;}
    else{t.disabled=false;document.getElementById('ae').textContent='Не вдалося отримати доступ до панелі';}
  }
});
load();
</script></body></html>`;
}
