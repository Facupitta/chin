import express from 'express';
import helmet from 'helmet';
import cors from 'cors';
import { rateLimit } from 'express-rate-limit';
import jwt from 'jsonwebtoken';
import { z } from 'zod';
import { randomBytes } from 'node:crypto';
import { hashPassword, verifyPassword } from './password.js';

const credentials = z.object({
  username: z.string().trim().min(3).max(32).regex(/^[a-zA-Z0-9_]+$/).transform(v => v.toLowerCase()),
  password: z.string().min(12).max(128),
}).strict();
const publicColumns = 'id, username, tokens, creation_date, last_login_date';
const issuer = 'super-tournament-api';
const audience = 'super-tournament-client';
const expiresIn = 900;
const maxTokens = 2_147_483_647;
const tokenIncrement = z.object({ amount: z.number().int().positive().max(maxTokens) }).strict();

export async function createApp({ db, secret, origins = [], authLimit = 10 }) {
  // El usuario inexistente también ejecuta scrypt para reducir diferencias de tiempo.
  const dummyHash = await hashPassword(randomBytes(32).toString('hex'));
  const app = express();
  app.disable('x-powered-by');
  app.use(helmet());
  app.use((req, res, next) => { res.set('Cache-Control', 'no-store'); next(); });
  app.use(cors({ origin: origins, methods: ['GET', 'POST'], allowedHeaders: ['Content-Type', 'Authorization'] }));
  app.use(rateLimit({ windowMs: 60_000, limit: 100, standardHeaders: 'draft-8', legacyHeaders: false,
    message: { error: 'Demasiadas solicitudes. Intentá nuevamente más tarde.' } }));
  app.use(express.json({ limit: '8kb' }));

  const authLimiter = rateLimit({ windowMs: 15 * 60_000, limit: authLimit,
    standardHeaders: 'draft-8', legacyHeaders: false,
    message: { error: 'Demasiados intentos. Intentá nuevamente más tarde.' } });

  function validate(req, res, next) {
    const parsed = credentials.safeParse(req.body);
    if (!parsed.success) return res.status(400).json({ error: 'Datos inválidos', details: parsed.error.issues.map(i => ({ field: i.path.join('.'), message: i.message })) });
    req.credentials = parsed.data;
    next();
  }

  app.post('/api/auth/register', authLimiter, validate, async (req, res) => {
    const { username, password } = req.credentials;
    const hash = await hashPassword(password);
    const result = await db.query(`INSERT INTO "User" (username, password) VALUES ($1, $2) ON CONFLICT(username) DO NOTHING RETURNING ${publicColumns}`, [username, hash]);
    if (!result.rowCount) return res.status(409).json({ error: 'El username ya está en uso' });
    const user = result.rows[0];
    res.status(201).json({ user });
  });

  app.post('/api/auth/login', authLimiter, validate, async (req, res) => {
    const { username, password } = req.credentials;
    const { rows: [user] } = await db.query('SELECT * FROM "User" WHERE username = $1', [username]);
    const valid = await verifyPassword(password, user?.password ?? dummyHash);
    if (!user || !valid) return res.status(401).json({ error: 'Credenciales inválidas' });
    const accessToken = jwt.sign({}, secret, { algorithm: 'HS256', subject: String(user.id), issuer, audience, expiresIn });
    const { rows: [updatedUser] } = await db.query(`UPDATE "User" SET last_login_date = CURRENT_TIMESTAMP WHERE id = $1 RETURNING ${publicColumns}`, [user.id]);
    res.json({ access_token: accessToken, token_type: 'Bearer', expires_in: expiresIn, user: updatedUser });
  });

  async function authenticate(req, res, next) {
    const match = /^Bearer ([^\s]+)$/i.exec(req.get('authorization') ?? '');
    if (!match) return res.status(401).json({ error: 'JWT requerido' });
    let payload;
    try {
      payload = jwt.verify(match[1], secret, { algorithms: ['HS256'], issuer, audience });
      if (typeof payload !== 'object' || !/^\d+$/.test(payload.sub ?? '') || !Number.isSafeInteger(Number(payload.sub)) || Number(payload.sub) < 1 || Number(payload.sub) > maxTokens) throw new Error('Invalid subject');
    } catch {
      return res.status(401).json({ error: 'JWT inválido o expirado' });
    }
    const { rows: [user] } = await db.query(`SELECT ${publicColumns} FROM "User" WHERE id = $1`, [Number(payload.sub)]);
    if (!user) return res.status(401).json({ error: 'JWT inválido o expirado' });
    req.user = user;
    next();
  }

  app.get('/api/users/me', authenticate, (req, res) => {
    res.json({ user: req.user });
  });

  app.post('/api/users/me/tokens', authenticate, async (req, res) => {
    const parsed = tokenIncrement.safeParse(req.body);
    if (!parsed.success) return res.status(400).json({ error: 'amount debe ser un entero positivo de hasta 2147483647, sin campos adicionales' });
    const { amount } = parsed.data;
    // Suma y control de desbordamiento en una sola operación, incluso con solicitudes simultáneas.
    const { rows: [user] } = await db.query(
      `UPDATE "User" SET tokens = tokens + $1 WHERE id = $2 AND tokens <= $3 RETURNING ${publicColumns}`,
      [amount, req.user.id, maxTokens - amount],
    );
    if (!user) return res.status(409).json({ error: 'No se pudo sumar: el saldo máximo es 2147483647 tokens' });
    res.json({ user });
  });

  app.use((req, res) => res.status(404).json({ error: 'Ruta no encontrada' }));
  app.use((err, req, res, next) => {
    if (err.type === 'entity.too.large') return res.status(413).json({ error: 'Solicitud demasiado grande' });
    if (err.type === 'entity.parse.failed') return res.status(400).json({ error: 'JSON inválido' });
    console.error('Error interno:', err.code ?? err.name);
    res.status(500).json({ error: 'Error interno del servidor' });
  });
  return app;
}
