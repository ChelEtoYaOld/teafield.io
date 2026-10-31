import { randomBytes,scryptSync } from 'node:crypto';
import { openDatabase } from './db.mjs';
const username=process.env.ADMIN_USERNAME?.trim(),password=process.env.ADMIN_PASSWORD;
if(!username||!password||password.length<12){console.error('CZ: Nastavte ADMIN_USERNAME a ADMIN_PASSWORD (alespoň 12 znaků).\nEN: Set ADMIN_USERNAME and ADMIN_PASSWORD (at least 12 characters).');process.exit(1)}
const db=openDatabase();const salt=randomBytes(32).toString('hex'),hash=scryptSync(password,salt,64).toString('hex');
try{db.prepare('INSERT INTO admins VALUES(?,?,?)').run(username,salt,hash);console.log('CZ: Administrátor vytvořen. EN: Administrator created.')}finally{db.close()}
