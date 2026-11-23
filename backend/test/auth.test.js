import { test } from 'node:test';
import assert from 'node:assert/strict';
import request from 'supertest';
import jwt from 'jsonwebtoken';
import { openDatabase } from '../src/database.js';
import { createApp } from '../src/app.js';
import { readConfig } from '../src/config.js';

const secret = 'test-only-secret-'.repeat(5);
const credentials = { username: 'facu', password: 'Una-clave-segura-123' };
async function fixture(t, options = {}) {
  const pool = await openDatabase(readConfig());
  const db = await pool.connect();
  t.after(async () => {
    try { await db.query('ROLLBACK'); } finally { db.release(); await pool.end(); }
  });
  await db.query('BEGIN');
  // Tabla temporal privada por prueba; no modifica usuarios reales.
  await db.query('CREATE TEMP TABLE "User" (LIKE public."User" INCLUDING ALL) ON COMMIT DROP');
  return { db, api: request(await createApp({ db, secret, authLimit: 100, ...options })) };
}

test('registro, hash, login, JWT y aislamiento del usuario', async t => {
  const { api, db } = await fixture(t);
  const registered = await api.post('/api/auth/register').send(credentials).expect(201);
  assert.deepEqual(Object.keys(registered.body.user).sort(), ['id', 'username', 'tokens', 'creation_date', 'last_login_date'].sort());
  assert.equal(registered.body.user.tokens, 0);
  assert.equal(registered.body.user.last_login_date, null);
  assert.ok(Number.isFinite(Date.parse(registered.body.user.creation_date)));
  const { rows: [stored] } = await db.query('SELECT * FROM "User"');
  assert.notEqual(stored.password, credentials.password);
  assert.match(stored.password, /^scrypt\$/);
  const second = await api.post('/api/auth/register').send({ ...credentials, username: 'otro' }).expect(201);
  assert.ok(second.body.user.id > stored.id);
  await api.post('/api/auth/register').send({ ...credentials, username: 'FACU' }).expect(409);
  const login = await api.post('/api/auth/login').send(credentials).expect(200);
  assert.ok(login.body.user.last_login_date);
  const me = await api.get('/api/users/me').set('Authorization', `Bearer ${login.body.access_token}`).expect(200);
  assert.equal(me.body.user.id, stored.id);
  assert.equal(me.body.user.password, undefined);
  assert.equal(me.headers['cache-control'], 'no-store');
  assert.equal(me.headers['x-content-type-options'], 'nosniff');
  assert.equal(me.headers['x-powered-by'], undefined);
});

test('rechaza credenciales, JWT alterados, expirados y de otro emisor', async t => {
  const { api, db } = await fixture(t);
  await api.post('/api/auth/register').send(credentials).expect(201);
  const failed = await api.post('/api/auth/login').send({ ...credentials, password: 'incorrecta-123456' }).expect(401);
  const missing = await api.post('/api/auth/login').send({ ...credentials, username: 'inexistente' }).expect(401);
  assert.deepEqual(failed.body, missing.body);
  assert.equal((await db.query('SELECT last_login_date FROM "User"')).rows[0].last_login_date, null);
  await api.get('/api/users/me').expect(401);
  await api.get('/api/users/me').set('Authorization', 'Bearer invalid').expect(401);
  for (const overrides of [{ expiresIn: -1 }, { issuer: 'otro' }, { audience: 'otro' }, { algorithm: 'HS384' }, { subject: '999' }]) {
    const token = jwt.sign({}, secret, { algorithm: 'HS256', subject: '1', issuer: 'super-tournament-api', audience: 'super-tournament-client', expiresIn: 900, ...overrides });
    await api.get('/api/users/me').set('Authorization', `Bearer ${token}`).expect(401);
  }
  const token = jwt.sign({}, 'otra-clave', { subject: '1' });
  await api.get('/api/users/me').set('Authorization', `Bearer ${token}`).expect(401);
});

test('validación, asignación masiva, JSON inválido y límite de cuerpo', async t => {
  const { api, db } = await fixture(t);
  for (const body of [null, {}, { ...credentials, password: 'corta' }, { ...credentials, username: "' OR 1=1 --" }, { ...credentials, tokens: 100 }, { ...credentials, id: 9 }]) {
    await api.post('/api/auth/register').send(body ?? {}).expect(400);
  }
  await api.post('/api/auth/register').set('Content-Type', 'application/json').send('{').expect(400);
  await api.post('/api/auth/register').send({ ...credentials, password: 'x'.repeat(9000) }).expect(413);
  assert.equal(Number((await db.query('SELECT count(*) AS count FROM "User"')).rows[0].count), 0);
  await api.get('/missing').expect(404);
});

test('rate limit de autenticación y CORS por origen explícito', async t => {
  const { api } = await fixture(t, { authLimit: 2, origins: ['http://localhost:5173'] });
  await api.post('/api/auth/login').send(credentials).expect(401);
  await api.post('/api/auth/login').send(credentials).expect(401);
  await api.post('/api/auth/login').send(credentials).expect(429);
  const allowed = await api.get('/api/users/me').set('Origin', 'http://localhost:5173');
  assert.equal(allowed.headers['access-control-allow-origin'], 'http://localhost:5173');
  const denied = await api.get('/api/users/me').set('Origin', 'https://otro.example');
  assert.equal(denied.headers['access-control-allow-origin'], undefined);
});

test('configuración exige secreto y puerto válidos', () => {
  assert.throws(() => readConfig({}), /JWT_SECRET/);
  assert.throws(() => readConfig({ JWT_SECRET: 'short' }), /JWT_SECRET/);
  assert.throws(() => readConfig({ JWT_SECRET: secret, PORT: 'invalid' }), /PORT/);
  assert.equal(readConfig({ JWT_SECRET: secret, PGPASSWORD: 'test' }).PORT, 3000);
  assert.throws(() => readConfig({ JWT_SECRET: secret }), /PGPASSWORD/);
  assert.throws(() => readConfig({ JWT_SECRET: secret, PGPASSWORD: 'test', PGPORT: 'invalid' }), /PGPORT/);
});

test('suma tokens al usuario del JWT y conserva los saldos de otros usuarios', async t => {
  const { api, db } = await fixture(t);
  const { rows: [owner] } = await db.query('INSERT INTO "User" (username, password, tokens) VALUES ($1, $2, $3) RETURNING id', ['owner', 'unused', 5]);
  await db.query('INSERT INTO "User" (username, password, tokens) VALUES ($1, $2, $3)', ['other', 'unused', 70]);
  const token = jwt.sign({}, secret, { subject: String(owner.id), issuer: 'super-tournament-api', audience: 'super-tournament-client', expiresIn: 900 });
  const added = await api.post('/api/users/me/tokens').set('Authorization', `Bearer ${token}`).send({ amount: 10 }).expect(200);
  assert.equal(added.body.user.id, owner.id);
  assert.equal(added.body.user.tokens, 15);
  assert.equal(added.body.user.password, undefined);
  for (const amount of [2, 3, 4]) {
    await api.post('/api/users/me/tokens').set('Authorization', `Bearer ${token}`).send({ amount }).expect(200);
  }
  const me = await api.get('/api/users/me').set('Authorization', `Bearer ${token}`).expect(200);
  assert.equal(me.body.user.tokens, 24);
  assert.equal((await db.query('SELECT tokens FROM "User" WHERE username = $1', ['other'])).rows[0].tokens, 70);
});

test('tokens rechaza body inválido, acceso no autenticado y desbordamiento', async t => {
  const { api, db } = await fixture(t);
  const { rows: [owner] } = await db.query('INSERT INTO "User" (username, password, tokens) VALUES ($1, $2, $3) RETURNING id', ['owner', 'unused', 2147483646]);
  const options = { subject: String(owner.id), issuer: 'super-tournament-api', audience: 'super-tournament-client', expiresIn: 900 };
  const token = jwt.sign({}, secret, options);
  await api.post('/api/users/me/tokens').send({ amount: 1 }).expect(401);
  for (const invalid of ['invalid', jwt.sign({}, secret, { ...options, expiresIn: -1 }), jwt.sign({}, secret, { ...options, subject: '999' })]) {
    await api.post('/api/users/me/tokens').set('Authorization', `Bearer ${invalid}`).send({ amount: 1 }).expect(401);
  }
  for (const body of [{}, { amount: 0 }, { amount: -1 }, { amount: 1.5 }, { amount: '10' }, { amount: null }, { amount: 2147483648 }, { amount: 1, user_id: 2 }]) {
    await api.post('/api/users/me/tokens').set('Authorization', `Bearer ${token}`).send(body).expect(400);
  }
  await api.post('/api/users/me/tokens').set('Authorization', `Bearer ${token}`).send({ amount: 2 }).expect(409);
  assert.equal((await db.query('SELECT tokens FROM "User" WHERE id = $1', [owner.id])).rows[0].tokens, 2147483646);
  const limit = await api.post('/api/users/me/tokens').set('Authorization', `Bearer ${token}`).send({ amount: 1 }).expect(200);
  assert.equal(limit.body.user.tokens, 2147483647);
  await api.post('/api/users/me/tokens').set('Authorization', `Bearer ${token}`).send({ amount: 1 }).expect(409);
});
