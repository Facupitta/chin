import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readConfig } from '../src/config.js';

const JWT_SECRET = 'test-secret-'.repeat(8);
test('acepta DATABASE_URL PostgreSQL sin PGPASSWORD y conserva SSL', () => {
  const DATABASE_URL = 'postgres://user:password@db.example:5432/postgres?sslmode=require';
  assert.equal(readConfig({ JWT_SECRET, DATABASE_URL }).DATABASE_URL, DATABASE_URL);
});
test('rechaza URLs incompatibles con pg', () => {
  for (const DATABASE_URL of ['prisma://db.example/?api_key=test', 'https://db.example', 'invalid']) {
    assert.throws(() => readConfig({ JWT_SECRET, DATABASE_URL }), /DATABASE_URL/);
  }
});
test('acepta TLS explicito para PG y rechaza modos invalidos', () => {
  for (const PGSSLMODE of ['require', 'verify-full', 'disable']) {
    assert.equal(readConfig({ JWT_SECRET, PGPASSWORD: 'test', PGSSLMODE }).PGSSLMODE, PGSSLMODE);
  }
  assert.throws(() => readConfig({ JWT_SECRET, PGPASSWORD: 'test', PGSSLMODE: 'invalid' }), /PGSSLMODE/);
  assert.throws(() => readConfig({ JWT_SECRET }), /PGPASSWORD/);
});
