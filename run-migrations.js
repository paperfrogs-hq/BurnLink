#!/usr/bin/env node
/**
 * Migration runner - Execute SQL migrations in Supabase
 * Usage: node run-migrations.js
 */

const fs = require('fs');
const path = require('path');
const https = require('https');
require('dotenv').config();

const SUPABASE_URL = process.env.SUPABASE_URL;
const SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;

if (!SUPABASE_URL || !SERVICE_ROLE_KEY) {
  console.error('ERROR: Missing SUPABASE_URL or SUPABASE_SERVICE_ROLE_KEY in .env');
  process.exit(1);
}

async function executeSQL(sql) {
  return new Promise((resolve, reject) => {
    const url = new URL(`${SUPABASE_URL}/rest/v1/rpc/exec_sql`, SUPABASE_URL);
    
    const options = {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${SERVICE_ROLE_KEY}`,
        'apikey': SERVICE_ROLE_KEY,
      },
      hostname: new URL(SUPABASE_URL).hostname,
      path: '/rest/v1/rpc/exec_sql',
    };

    const req = https.request(options, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        if (res.statusCode >= 400) {
          reject(new Error(`SQL execution failed (${res.statusCode}): ${data}`));
        } else {
          resolve(data);
        }
      });
    });

    req.on('error', reject);
    req.write(JSON.stringify({ query: sql }));
    req.end();
  });
}

async function executeSQLDirect() {
  // Alternative: Use direct PostgreSQL wire protocol via Supabase's API
  const { createClient } = require('@supabase/supabase-js');
  
  const supabase = createClient(SUPABASE_URL, SERVICE_ROLE_KEY, {
    auth: { persistSession: false }
  });

  // Discover all migration files in alphabetical order (e.g. 001_…, 002_…)
  const migrationsDir = path.join(__dirname, 'migrations');
  const migrationFiles = fs
    .readdirSync(migrationsDir)
    .filter((f) => f.endsWith('.sql'))
    .sort();

  if (migrationFiles.length === 0) {
    console.error('No .sql files found in migrations/');
    process.exit(1);
  }

  console.log(
    `Found ${migrationFiles.length} migration file(s): ${migrationFiles.join(', ')}`
  );

  for (const file of migrationFiles) {
    await runMigrationFile(supabase, path.join(migrationsDir, file));
  }

  console.log('\nMigrations complete!');
}

async function runMigrationFile(supabase, filePath) {
  const sql = fs.readFileSync(filePath, 'utf8');

  // Split SQL into individual statements (basic splitting)
  const statements = sql
    .split(';')
    .map((s) => s.trim())
    .filter((s) => s.length > 0 && !s.startsWith('--'));

  console.log(`\n--- ${path.basename(filePath)} ---`);
  console.log(`Found ${statements.length} SQL statements to execute...`);

  for (let i = 0; i < statements.length; i++) {
    const stmt = statements[i] + ';';
    console.log(`\n[${i + 1}/${statements.length}] Executing: ${stmt.substring(0, 50)}...`);
    
    try {
      const { data, error } = await supabase.rpc('exec_sql', {
        query: stmt,
      });
      
      if (error) {
        console.error(`ERROR: ${error.message}`);
        // Continue on error in case table already exists
      } else {
        console.log(`✅ Success`);
      }
    } catch (err) {
      console.error(`ERROR: ${err.message}`);
      // Continue on error
    }
  }
}

// Run the migration
executeSQLDirect().catch(err => {
  console.error('Migration failed:', err);
  process.exit(1);
});
