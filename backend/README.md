# Super Tournament API

API REST con Node.js + Express, JWT y PostgreSQL. Requiere Node.js 22.13 o posterior y PostgreSQL local activo.

## Inicio (PowerShell)

```powershell
npm ci
Copy-Item .env.example .env
node -e "console.log(require('node:crypto').randomBytes(48).toString('base64url'))"
# Pegar el resultado en JWT_SECRET dentro de .env.
# Completar PGPASSWORD con la contraseña del usuario PostgreSQL local.
npm run dev
```

Para ejecución normal: `npm start`. Para pruebas: `npm test`.
La API escucha por defecto en `http://127.0.0.1:3000`. La conexión usa `PGHOST=127.0.0.1`, `PGPORT=5432`, `PGDATABASE=chin_lcl`, `PGUSER=chin_lcl` y la contraseña `PGPASSWORD` del `.env`. No subir `.env` al repositorio.

La base y el usuario deben existir previamente; el usuario necesita permisos para crear tablas en el esquema `public`. Al iniciar, el servidor conecta y crea `public."User"` si no existe, antes de aceptar solicitudes. Los datos anteriores de SQLite no se migran automáticamente.

Si aparece `permiso denegado al esquema public`, ejecutar como administrador conectado a **chin_lcl**:

```sql
GRANT USAGE, CREATE ON SCHEMA public TO chin_lcl;
```

Las pruebas requieren la conexión PostgreSQL del `.env` y usan una tabla temporal privada por prueba, descartada al finalizar, sin modificar los usuarios de la tabla real.

## Modelo

La única tabla de aplicación es `public."User"`. PostgreSQL administra la secuencia de identidad para el id incremental.

| Campo | Tipo | Comportamiento |
| --- | --- | --- |
| id | INTEGER | Clave primaria autoincremental |
| username | TEXT | Único; se normaliza a minúsculas; 3–32 letras ASCII, números o guiones bajos |
| password | TEXT | Hash scrypt con salt aleatoria, nunca se devuelve por API |
| tokens | INTEGER | No negativo, comienza en 0; independiente del JWT |
| creation_date | TIMESTAMPTZ | Fecha automática; se devuelve como ISO 8601 UTC |
| last_login_date | TIMESTAMPTZ nullable | NULL hasta el primer login exitoso; fecha UTC |

## Endpoints

| Método | Ruta | Uso |
| --- | --- | --- |
| POST | `/api/auth/register` | Registro público; devuelve 201 con `{ user }` |
| POST | `/api/auth/login` | Devuelve JWT y usuario; actualiza last_login_date |
| GET | `/api/users/me` | Usuario autenticado; requiere Authorization: Bearer JWT |
| POST | `/api/users/me/tokens` | Suma `amount` al usuario del JWT; devuelve 200 con `{ user }` actualizado |

Registro y login reciben solamente:

```json
{ "username": "facu", "password": "Una-clave-segura-123" }
```

Contraseña de 12–128 caracteres, sin recortarla ni transformarla. Los campos adicionales se rechazan. El registro no permite definir `tokens`, fechas ni id. No hay endpoints para listar otros usuarios.

Para sumar tokens: `POST /api/users/me/tokens`, con `Authorization: Bearer <JWT>` y `Content-Type: application/json`:

```json
{ "amount": 10 }
```

Solo acepta un entero positivo, sin campos adicionales. El usuario se obtiene del JWT, no del body. La suma es atómica; si el saldo superaría 2147483647, devuelve 409 sin modificarlo. Una cantidad inválida devuelve 400 y un JWT ausente, inválido o expirado devuelve 401. Cada solicitud exitosa vuelve a sumar: no es idempotente, por lo que no se debe reintentar automáticamente tras una respuesta perdida.

Este endpoint permite que cualquier usuario autenticado se acredite la cantidad solicitada. El JWT identifica al usuario, pero no demuestra que haya ganado una recompensa; para una economía de juego real, las acreditaciones deben validarse en el servidor.

Ejemplo completo en PowerShell:

```powershell
$body = @{ username = 'facu'; password = 'Una-clave-segura-123' } | ConvertTo-Json
Invoke-RestMethod http://127.0.0.1:3000/api/auth/register -Method Post -ContentType application/json -Body $body
$login = Invoke-RestMethod http://127.0.0.1:3000/api/auth/login -Method Post -ContentType application/json -Body $body
Invoke-RestMethod http://127.0.0.1:3000/api/users/me -Headers @{ Authorization = "Bearer $($login.access_token)" }
```

Login devuelve `access_token`, `token_type: "Bearer"`, `expires_in: 900` (15 minutos) y `user`. No hay refresh token ni revocación individual: al cerrar sesión el cliente descarta el JWT; un JWT emitido sigue siendo válido hasta su vencimiento. El registro no inicia sesión automáticamente.

Errores: 400 datos inválidos, 401 autenticación inválida, 404 ruta inexistente, 409 username ocupado, 413 cuerpo demasiado grande, 429 límite de solicitudes y 500 error interno sin detalles sensibles.

## Seguridad y despliegue

- Hash scrypt con salt individual, N=32768, r=8, p=3, comparación en tiempo constante y hash señuelo para usuarios inexistentes.
- JWT HS256 con expiración, algoritmo, emisor y audiencia verificados. Se exige un secreto de al menos 64 caracteres; generarlo aleatoriamente como se indica arriba.
- Consultas parametrizadas, validación estricta, Helmet, respuestas no cacheables y JSON limitado a 8 KB.
- CORS permite exclusivamente los orígenes de `CORS_ORIGINS`. CORS controla acceso desde navegadores, no reemplaza autenticación.
- Límite por IP: 100 solicitudes/minuto y 10 intentos de registro/login combinados cada 15 minutos, incluyendo éxitos. Los contadores están en memoria y se reinician con el proceso.
- Para producción, colocar detrás de HTTPS, configurar credenciales y backups de PostgreSQL y los orígenes reales. `HOST=0.0.0.0` permite escuchar fuera de localhost, por ejemplo en contenedores.
- `trust proxy` permanece deshabilitado. Si se despliega detrás de un proxy, configurarlo según la topología confiable antes de usar límites por IP; no habilitarlo indiscriminadamente. Para múltiples instancias se necesita almacenamiento compartido de límites.

Referencia: [prácticas de seguridad de Express](https://expressjs.com/en/advanced/best-practice-security/).
