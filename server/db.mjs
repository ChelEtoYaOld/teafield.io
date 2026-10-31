import { DatabaseSync } from 'node:sqlite';
import { mkdirSync } from 'node:fs';
import { resolve } from 'node:path';
import { profile,products } from './catalog.mjs';
export function openDatabase(dir=process.env.DATA_DIR||'./data'){
 mkdirSync(dir,{recursive:true});const db=new DatabaseSync(resolve(dir,'tea-field.sqlite'));
 db.exec(`PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;
 CREATE TABLE IF NOT EXISTS photos (id TEXT PRIMARY KEY, mime TEXT NOT NULL, bytes BLOB NOT NULL);
 CREATE TABLE IF NOT EXISTS settings (id INTEGER PRIMARY KEY CHECK(id=1), value TEXT NOT NULL);
 CREATE TABLE IF NOT EXISTS products (id TEXT PRIMARY KEY, value TEXT NOT NULL);
 CREATE TABLE IF NOT EXISTS admins (username TEXT PRIMARY KEY, salt TEXT NOT NULL, hash TEXT NOT NULL);
 CREATE TABLE IF NOT EXISTS sessions (token TEXT PRIMARY KEY, username TEXT NOT NULL REFERENCES admins(username), expires INTEGER NOT NULL);
 CREATE TABLE IF NOT EXISTS orders (id TEXT PRIMARY KEY,value TEXT NOT NULL);
 CREATE TABLE IF NOT EXISTS inventory (id TEXT PRIMARY KEY,value TEXT NOT NULL);
 CREATE TABLE IF NOT EXISTS audit (id INTEGER PRIMARY KEY,at TEXT NOT NULL,actor TEXT NOT NULL,action TEXT NOT NULL,entity TEXT NOT NULL);
 `);
 const first=!db.prepare('SELECT id FROM settings WHERE id=1').get();
 if(first){db.exec('BEGIN');try{db.prepare('INSERT INTO settings VALUES(1,?)').run(JSON.stringify(profile));const insert=db.prepare('INSERT INTO products VALUES(?,?)');for(const p of products)insert.run(p.id,JSON.stringify(p));db.exec('COMMIT')}catch(e){db.exec('ROLLBACK');throw e}}
 // Upgrade the legacy delivery field without touching products or operational data.
 const stored=JSON.parse(db.prepare('SELECT value FROM settings WHERE id=1').get().value);
 if(!stored.orderUrl || Object.hasOwn(stored,'wolt')){
  stored.orderUrl ||= profile.orderUrl;
  delete stored.wolt;
  db.prepare('UPDATE settings SET value=? WHERE id=1').run(JSON.stringify(stored));
 }
 return db;
}
