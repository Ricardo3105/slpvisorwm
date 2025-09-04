// server.js — Backend con auth + fotos + ratings
require('dotenv').config();

const express = require('express');
const cors = require('cors');
const path = require('path');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const app = express();

/* ------------------------ Middlewares base ------------------------ */
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

/* --------------------------- PostgreSQL --------------------------- */
const pool = new Pool({
  host: process.env.DB_HOST || '127.0.0.1',
  port: Number(process.env.DB_PORT || 5432),
  user: process.env.DB_USER || 'postgres',
  password: process.env.DB_PASS || '',
  database: process.env.DB_NAME || 'visorwm',
});

async function q(sql, params = []) {
  // console.log('[SQL]', sql, params);
  try { return await pool.query(sql, params); }
  catch (e) { console.error('❌ DB:', e.message); throw e; }
}

/* ---------- Crear tablas mínimas si no existen (auto-bootstrap) ---------- */
async function ensureTables() {
  await q(`CREATE EXTENSION IF NOT EXISTS "pgcrypto";`);

  await q(`
    CREATE TABLE IF NOT EXISTS public.users (
      id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      email         TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      display_name  TEXT,
      role          TEXT DEFAULT 'user',
      created_at    TIMESTAMP DEFAULT NOW()
    );
  `);

  // No forzamos FK a photos.id por si tu esquema no usa UUID
  await q(`
    CREATE TABLE IF NOT EXISTS public.ratings (
      photo_id TEXT NOT NULL,
      user_id  TEXT NOT NULL,
      value    VARCHAR(2) CHECK (value IN ('Sí','No')),
      "user"   TEXT,
      ts       BIGINT NOT NULL,
      PRIMARY KEY (photo_id, user_id)
    );
  `);
}

/* -------------------- Utilidades de Auth / Tokens ----------------- */
const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret';
const JWT_EXPIRES = process.env.JWT_EXPIRES || '2d';
const BCRYPT_ROUNDS = parseInt(process.env.BCRYPT_ROUNDS || '10', 10);

function signToken(user) {
  return jwt.sign(
    { id: user.id, email: user.email, role: user.role || 'user' },
    JWT_SECRET,
    { expiresIn: JWT_EXPIRES }
  );
}

function authRequired(req, res, next) {
  const h = req.headers.authorization || '';
  const m = h.match(/^Bearer (.+)$/i);
  if (!m) return res.status(401).json({ error: 'No autorizado (falta token)' });
  try {
    const payload = jwt.verify(m[1], JWT_SECRET);
    req.user = payload; // { id, email, role }
    next();
  } catch (e) {
    return res.status(401).json({ error: 'Token inválido o expirado' });
  }
}

/* ----------------------------- Rutas AUTH ----------------------------- */
// Registro (dev: abierto; en prod restringe a admin/invitación)
app.post('/auth/register', async (req, res) => {
  const { email, password, displayName } = req.body || {};
  if (!email || !password) return res.status(400).json({ error: 'email y password son requeridos' });

  try {
    const hash = await bcrypt.hash(password, BCRYPT_ROUNDS);
    const { rows } = await q(
      `INSERT INTO public.users (email, password_hash, display_name)
       VALUES ($1,$2,$3)
       ON CONFLICT (email) DO NOTHING
       RETURNING id, email, role`,
      [email.trim().toLowerCase(), hash, displayName || null]
    );

    let user;
    if (!rows.length) {
      // ya existe → permite login directo
      const r2 = await q(`SELECT id, email, role FROM public.users WHERE email=$1`, [email.trim().toLowerCase()]);
      user = r2.rows[0];
    } else {
      user = rows[0];
    }
    const token = signToken(user);
    res.json({ ok: true, user, token });
  } catch (e) {
    console.error('❌ /auth/register:', e.message);
    res.status(500).json({ error: 'No se pudo registrar' });
  }
});

// Login
app.post('/auth/login', async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) return res.status(400).json({ error: 'email y password son requeridos' });
  try {
    const { rows } = await q(
      `SELECT id, email, password_hash, role FROM public.users WHERE email=$1`,
      [email.trim().toLowerCase()]
    );
    if (!rows.length) return res.status(401).json({ error: 'Usuario no encontrado' });

    const user = rows[0];
    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok) return res.status(401).json({ error: 'Contraseña incorrecta' });

    const token = signToken(user);
    res.json({ ok: true, user: { id: user.id, email: user.email, role: user.role }, token });
  } catch (e) {
    console.error('❌ /auth/login:', e.message);
    res.status(500).json({ error: 'Error en login' });
  }
});

// Perfil (valida token)
app.get('/auth/me', authRequired, (req, res) => {
  res.json({ ok: true, user: req.user });
});

/* --------------------------- Salud / util --------------------------- */
app.get('/health', async (req, res) => {
  try {
    const { rows } = await q('SELECT NOW() as now, current_database() as db');
    res.json({ ok: true, ...rows[0] });
  } catch (e) {
    res.status(500).json({ ok: false, error: e.message });
  }
});

/* --------------------------- Helpers de datos --------------------------- */
const normNic = v => String(v ?? '').trim().replace(/\s+/g, '');

/* ----------------------------- /photos ----------------------------- */
/**
 * GET /photos?nic=...&limit=100
 * Devuelve filas para el NIC. Protegido.
 * Si tu tabla tiene columnas específicas, ajústalas en el SELECT.
 */
app.get('/photos', authRequired, async (req, res) => {
  const nic = normNic(req.query.nic || '');
  const limit = Math.min(parseInt(req.query.limit || '100', 10), 200);
  if (!nic) return res.status(400).json({ error: 'Falta parámetro nic' });

  try {
    // Intento 1: columnas curadas (ajusta a tu esquema si las tienes)
    const curatedSql = `
      SELECT
        id,
        nic,
        direccion,
        -- si tu fecha es timestamp en otra columna, ajústala:
        COALESCE(fecha_gestion_ts::text, fecha_gestion::text) AS fecha_gestion,
        medidor,
        lectura,
        lectura_anterior,
        tipo_magnitud,
        anomalia,
        nombre_suscriptor,
        gestionada_por,
        contratista,
        barrio,
        municipio,
        nota_ultimo_intento,
        evidencia,
        url,
        latitud,
        longitud
      FROM public.photos
      WHERE REPLACE(TRIM(nic::text),' ','') = $1
      ORDER BY id DESC
      LIMIT $2
    `;
    try {
      const { rows } = await q(curatedSql, [nic, limit]);
      return res.json(rows);
    } catch (e1) {
      // Fallback genérico si el SELECT anterior no aplica a tu esquema
      console.warn('⚠️ /photos usando fallback SELECT *:', e1.message);
      const { rows } = await q(
        `SELECT * FROM public.photos
         WHERE REPLACE(TRIM(nic::text),' ','') = $1
         ORDER BY 1 DESC
         LIMIT $2`,
        [nic, limit]
      );
      return res.json(rows);
    }
  } catch (e) {
    console.error('❌ /photos:', e.message);
    res.status(500).json({ error: e.message });
  }
});

/* ----------------------------- /ratings ---------------------------- */
/**
 * GET /ratings/:photoId/:userId
 * Devuelve la calificación del usuario para esa foto. Protegido.
 */
app.get('/ratings/:photoId/:userId', authRequired, async (req, res) => {
  const { photoId, userId } = req.params;
  // seguridad básica: solo ver la suya o ser admin
  if (req.user.email !== userId && req.user.role !== 'admin') {
    return res.status(403).json({ error: 'No puedes consultar la calificación de otro usuario' });
  }
  try {
    const { rows } = await q(
      `SELECT value, "user", ts
       FROM public.ratings
       WHERE photo_id=$1 AND user_id=$2`,
      [photoId, userId]
    );
    if (!rows.length) return res.status(204).send();
    res.json(rows[0]);
  } catch (e) {
    console.error('❌ /ratings GET:', e.message);
    res.status(500).json({ error: e.message });
  }
});

/**
 * PUT /ratings/:photoId/:userId   body: { value: "Sí"|"No", user: "correo/alias" }
 * Guarda/actualiza (UPSERT). Protegido.
 */
app.put('/ratings/:photoId/:userId', authRequired, async (req, res) => {
  const { photoId, userId } = req.params;
  const { value, user } = req.body || {};
  if (!['Sí', 'No'].includes(value)) return res.status(400).json({ error: 'value debe ser "Sí" o "No"' });

  // seguridad: solo puede escribir su propio userId (o ser admin)
  if (req.user.email !== userId && req.user.role !== 'admin') {
    return res.status(403).json({ error: 'No puedes calificar como otro usuario' });
  }

  try {
    const ts = Date.now();
    await q(
      `INSERT INTO public.ratings (photo_id, user_id, value, "user", ts)
       VALUES ($1,$2,$3,$4,$5)
       ON CONFLICT (photo_id, user_id) DO UPDATE
         SET value = EXCLUDED.value,
             "user" = EXCLUDED."user",
             ts    = EXCLUDED.ts`,
      [photoId, userId, value, user || req.user.email, ts]
    );
    res.json({ ok: true, ts });
  } catch (e) {
    console.error('❌ /ratings PUT:', e.message);
    res.status(500).json({ error: e.message });
  }
});

/* ------------------------- Rutas estáticas/SPA ------------------------- */
app.get('/', (_, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

/* --------------------------- 404 / Errores --------------------------- */
app.use((req, res) => res.status(404).json({ error: 'Not found' }));
app.use((err, req, res, next) => {
  console.error('❌ Unhandled:', err);
  res.status(500).json({ error: 'Internal Server Error' });
});

/* ----------------------------- Start ----------------------------- */
(async () => {
  try {
    await ensureTables();
    const PORT = Number(process.env.PORT || 3000);
    app.listen(PORT, () => {
      console.log(`✅ Backend activo en http://localhost:${PORT}`);
      console.log(`   DB → ${process.env.DB_USER}@${process.env.DB_HOST}:${process.env.DB_PORT}/${process.env.DB_NAME}`);
    });
  } catch (e) {
    console.error('❌ Falló el arranque:', e);
    process.exit(1);
  }
})();
