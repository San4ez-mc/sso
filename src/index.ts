// SSO FINEKO (#284) — єдиний вхід. Ідентичність (ХТО); доступи дає орг.структура.
import express, { type Request, type Response } from 'express';
import cookieParser from 'cookie-parser';
import cors from 'cors';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { randomBytes, randomUUID } from 'node:crypto';
import { PrismaClient } from '@prisma/client';

const prisma = new PrismaClient();
const app = express();
app.use(express.json());
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

// ── Health ──────────────────────────────────────────────────
app.get('/health', async (_req, res) => {
  const users = await prisma.user.count().catch(() => -1);
  res.json({ ok: true, service: 'fineko-sso', users });
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
    res.cookie('sso_token', token, { httpOnly: true, sameSite: 'lax', maxAge: TOKEN_TTL * 1000 });
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
    res.cookie('sso_token', token, { httpOnly: true, sameSite: 'lax', maxAge: TOKEN_TTL * 1000 });
    res.json({ user: { id: user.id, email: user.email, displayName: user.displayName }, token });
  } catch (err) {
    res.status(500).json({ error: String(err) });
  }
});

app.post('/logout', (_req, res) => {
  res.cookie('sso_token', '', { httpOnly: true, maxAge: 0 });
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
      if (!process.env.SMTP_HOST) devLink = link; // без SMTP — віддаємо лінк
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

// ── OAuth authorization_code flow (для підключення продуктів) ──
// Продукт: redirect на /authorize?client_id&redirect_uri&state
// Після входу SSO віддає ?code; продукт міняє code→token на /oauth/token.
app.get('/authorize', async (req: Request, res: Response) => {
  const clientId = String(req.query.client_id || '');
  const redirectUri = String(req.query.redirect_uri || '');
  const state = String(req.query.state || '');
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
});

app.post('/authorize', async (req: Request, res: Response) => {
  const { client_id: clientId, redirect_uri: redirectUri, state = '', email, password } = req.body || {};
  const client = await prisma.oAuthClient.findUnique({ where: { clientId } });
  if (!client) return void res.status(400).send('Unknown client_id');
  const user = await prisma.user.findUnique({ where: { email: String(email || '').trim().toLowerCase() } });
  if (!user || !user.passwordHash || !(await bcrypt.compare(String(password || ''), user.passwordHash)) || user.status !== 'active') {
    return void res.type('html').send(loginPage(clientId, redirectUri, state, 'Невірний email або пароль'));
  }
  const token = issueToken(user);
  res.cookie('sso_token', token, { httpOnly: true, sameSite: 'lax', maxAge: TOKEN_TTL * 1000 });
  const code = randomBytes(24).toString('hex');
  await prisma.authCode.create({ data: { code, clientId, userId: user.id, redirectUri, expiresAt: new Date(Date.now() + 300_000) } });
  const sep = redirectUri.includes('?') ? '&' : '?';
  res.redirect(`${redirectUri}${sep}code=${code}${state ? `&state=${encodeURIComponent(state)}` : ''}`);
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

function loginPage(clientId: string, redirectUri: string, state: string, error: string): string {
  const esc = (s: string) => s.replace(/"/g, '&quot;').replace(/</g, '&lt;');
  return `<!doctype html><html lang="uk"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>FINEKO — вхід</title>
<style>body{font-family:system-ui;background:#0d1117;color:#e6edf3;display:flex;min-height:100vh;align-items:center;justify-content:center}
.card{background:#161b22;border:1px solid #30363d;border-radius:12px;padding:32px;width:340px}
h1{font-size:18px;margin:0 0 4px}p{color:#8b949e;font-size:13px;margin:0 0 20px}
input{width:100%;box-sizing:border-box;padding:10px;margin-bottom:12px;background:#0d1117;border:1px solid #30363d;border-radius:8px;color:#e6edf3}
button{width:100%;padding:11px;background:#238636;color:#fff;border:0;border-radius:8px;font-weight:600;cursor:pointer}
.err{color:#f85149;font-size:13px;margin-bottom:12px}</style></head>
<body><div class="card"><h1>🔐 FINEKO</h1><p>Єдиний вхід у продукти FINEKO</p>
${error ? `<div class="err">${esc(error)}</div>` : ''}
<form method="POST" action="/authorize">
<input type="hidden" name="client_id" value="${esc(clientId)}"><input type="hidden" name="redirect_uri" value="${esc(redirectUri)}"><input type="hidden" name="state" value="${esc(state)}">
<input name="email" type="email" placeholder="email" required autofocus>
<input name="password" type="password" placeholder="пароль" required>
<button type="submit">Увійти</button></form></div></body></html>`;
}

app.listen(PORT, () => {
  // eslint-disable-next-line no-console
  console.log(`[fineko-sso] listening on ${BASE_URL}`);
});
