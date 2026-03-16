#!/usr/bin/env node
const { Pool } = require('pg');
const pool = new Pool({ connectionString: process.env.DATABASE_URL, ssl: { rejectUnauthorized: false } });

async function migrate() {
  console.log('Running migrations...');
  const client = await pool.connect();
  try {
    await client.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY, name TEXT NOT NULL, email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL, role TEXT DEFAULT 'coach', created_at TIMESTAMPTZ DEFAULT NOW()
      );
      CREATE TABLE IF NOT EXISTS members (
        id TEXT PRIMARY KEY, name TEXT NOT NULL, email TEXT, phone TEXT,
        status TEXT DEFAULT 'Active', membership TEXT, last_visit DATE,
        visits_7d INT DEFAULT 0, total_visits INT DEFAULT 0, needs TEXT DEFAULT 'Low',
        coach TEXT, goals JSONB DEFAULT '[]', habits JSONB DEFAULT '[]',
        notes TEXT DEFAULT '', flagged BOOLEAN DEFAULT FALSE, contacted BOOLEAN DEFAULT FALSE,
        join_date DATE, timeline JSONB DEFAULT '[]', momence_id BIGINT, updated_at TIMESTAMPTZ DEFAULT NOW()
      );
      CREATE TABLE IF NOT EXISTS leads (
        id TEXT PRIMARY KEY, name TEXT NOT NULL, email TEXT, phone TEXT,
        status TEXT DEFAULT 'New Lead', source TEXT, coach TEXT, consult_date DATE,
        notes TEXT DEFAULT '', timeline JSONB DEFAULT '[]',
        added TIMESTAMPTZ DEFAULT NOW(), updated_at TIMESTAMPTZ DEFAULT NOW()
      );
      CREATE TABLE IF NOT EXISTS activity_log (
        id SERIAL PRIMARY KEY, user_name TEXT NOT NULL, action TEXT NOT NULL,
        entity_type TEXT, entity_id TEXT, entity_name TEXT, detail TEXT,
        created_at TIMESTAMPTZ DEFAULT NOW()
      );
      CREATE INDEX IF NOT EXISTS idx_members_coach ON members(coach);
      CREATE INDEX IF NOT EXISTS idx_members_status ON members(status);
      CREATE INDEX IF NOT EXISTS idx_members_flagged ON members(flagged);
      CREATE INDEX IF NOT EXISTS idx_members_momence ON members(momence_id);
      CREATE INDEX IF NOT EXISTS idx_leads_status ON leads(status);
      CREATE INDEX IF NOT EXISTS idx_activity_created ON activity_log(created_at DESC);
    `);
    const bcrypt = require('bcryptjs');
    const users = [
      { name: 'Xuan',   email: 'xuan@andwellfitness.ca',   password: 'andwell2026' },
      { name: 'Linda',  email: 'linda@andwellfitness.ca',  password: 'andwell2026' },
      { name: 'Alvin',  email: 'alvin@andwellfitness.ca',  password: 'andwell2026' },
      { name: 'Andrew', email: 'andrew@andwellfitness.ca', password: 'andwell2026' },
    ];
    for (const u of users) {
      const hash = await bcrypt.hash(u.password, 10);
      await client.query(
        'INSERT INTO users (name, email, password) VALUES ($1,$2,$3) ON CONFLICT (email) DO NOTHING',
        [u.name, u.email, hash]
      );
    }
    console.log('Tables created. Users seeded (password: andwell2026)');
    users.forEach(u => console.log(' ', u.name, u.email));
  } finally { client.release(); await pool.end(); }
}
migrate().catch(e => { console.error(e.message); process.exit(1); });
