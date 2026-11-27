-- Esquema PostgreSQL del backend Super Tournament.
-- Ejecutar conectado a la base de datos de destino con permisos CREATE en public.
-- Crea las entidades faltantes sin eliminar datos.
-- IF NOT EXISTS no actualiza la estructura de una tabla existente.

BEGIN;

CREATE TABLE IF NOT EXISTS public."User" (
    id INTEGER GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    username TEXT NOT NULL UNIQUE
        CHECK (length(username) BETWEEN 3 AND 32 AND username = lower(username)),
    password TEXT NOT NULL,
    tokens INTEGER NOT NULL DEFAULT 0 CHECK (tokens >= 0),
    creation_date TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_login_date TIMESTAMPTZ
);

-- PostgreSQL crea automaticamente la secuencia del ID y los indices
-- de la clave primaria y de la restriccion UNIQUE de username.
-- password almacena el hash scrypt generado por el backend, nunca texto plano.
-- No hay otras entidades ni claves foraneas en el backend actual.

COMMIT;
