import { z } from 'zod';

export function readConfig(env = process.env) {
  const config = z.object({
    PORT: z.coerce.number().int().min(1).max(65535).default(3000),
    HOST: z.string().min(1).default('127.0.0.1'),
    PGHOST: z.string().min(1).default('127.0.0.1'),
    PGPORT: z.coerce.number().int().min(1).max(65535).default(5432),
    PGDATABASE: z.string().min(1).default('chin_lcl'),
    PGUSER: z.string().min(1).default('chin_lcl'),
    PGPASSWORD: z.string().min(1),
    JWT_SECRET: z.string().min(64),
    CORS_ORIGINS: z.string().default(''),
  }).safeParse(env);
  if (!config.success) {
    throw new Error(`Configuración inválida: ${config.error.issues.map(i => `${i.path.join('.')}: ${i.message}`).join('; ')}`);
  }
  return config.data;
}
