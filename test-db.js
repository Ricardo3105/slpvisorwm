// test-db.js
require('dotenv').config();
const { Pool } = require('pg');

const pool = new Pool({
  host: process.env.DB_HOST || '127.0.0.1',
  port: process.env.DB_PORT || 5432,
  user: process.env.DB_USER || 'postgres',
  password: process.env.DB_PASS || '',
  database: process.env.DB_NAME || 'visorwm',
});

(async () => {
  try {
    const client = await pool.connect();
    console.log("✅ Conexión exitosa a PostgreSQL");

    // Probamos con una consulta sencilla
    const result = await client.query('SELECT NOW() as fecha, current_database() as db, user');
    console.log("📊 Respuesta:", result.rows[0]);

    client.release();
    process.exit(0);
  } catch (err) {
    console.error("❌ Error conectando a PostgreSQL:", err.message);
    process.exit(1);
  }
})();
