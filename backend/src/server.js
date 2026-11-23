import { readConfig } from './config.js';
import { openDatabase } from './database.js';
import { createApp } from './app.js';

const config = readConfig();
const db = await openDatabase(config);
const app = await createApp({ db, secret: config.JWT_SECRET,
  origins: config.CORS_ORIGINS.split(',').map(v => v.trim()).filter(Boolean) });
const server = app.listen(config.PORT, config.HOST, () => {
  console.log(`API disponible en http://${config.HOST}:${config.PORT}`);
});
server.on('error', async error => { console.error('No se pudo iniciar la API:', error.code); await db.end(); process.exitCode = 1; });
let stopping = false;
function shutdown() {
  if (stopping) return;
  stopping = true;
  server.close(async () => { await db.end(); });
  setTimeout(() => process.exit(1), 10_000).unref();
}
process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);
