import pg from 'pg';

export async function openDatabase(config) {
  const db = new pg.Pool({
    host: config.PGHOST, port: config.PGPORT,
    database: config.PGDATABASE, user: config.PGUSER, password: config.PGPASSWORD,
    max: 10, connectionTimeoutMillis: 5000, idleTimeoutMillis: 30000,
  });
  db.on('error', error => console.error('Error de conexión PostgreSQL:', error.code));
  try {
    await db.query(`
    CREATE TABLE IF NOT EXISTS public."User" (
      id INTEGER GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
      username TEXT NOT NULL UNIQUE CHECK(length(username) BETWEEN 3 AND 32 AND username = lower(username)),
      password TEXT NOT NULL,
      tokens INTEGER NOT NULL DEFAULT 0 CHECK(tokens >= 0),
      creation_date TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
      last_login_date TIMESTAMPTZ
    );
  `);
    return db;
  } catch (error) {
    await db.end();
    if (error.code === '42501') {
      throw new Error('El usuario PostgreSQL no tiene permisos suficientes. En la base configurada, un administrador debe conceder USAGE y CREATE sobre el esquema public al usuario de la API.', { cause: error });
    }
    throw error;
  }
}
