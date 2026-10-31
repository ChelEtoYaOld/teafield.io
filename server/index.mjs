import http from 'node:http';
import { randomBytes,randomUUID,scryptSync,timingSafeEqual,createHash } from 'node:crypto';
import { readFile,stat } from 'node:fs/promises';
import { resolve,extname,sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { openDatabase } from './db.mjs';
const publicDir=fileURLToPath(new URL('../public/',import.meta.url));
const sha=s=>createHash('sha256').update(s).digest('hex');
const messages={unauthorized:['Přihlaste se prosím.','Please sign in.'],invalid:['Zkontrolujte zadané údaje.','Please check the entered values.'],credentials:['Neplatné přihlašovací údaje.','Invalid credentials.'],rate:['Příliš mnoho pokusů. Zkuste to za 15 minut.','Too many attempts. Try again in 15 minutes.'],missing:['Záznam nebyl nalezen.','Record not found.'],internal:['Požadavek se nepodařilo dokončit.','Could not complete the request.'],origin:['Požadavek není povolen.','Request not allowed.']};
function check(v){if(!v){const e=Error('invalid');e.status=400;throw e}}
function str(x,max=500){check(typeof x==='string'&&x.trim().length<=max);return x.trim()}
function num(x,max=1e6){check(typeof x==='number'&&Number.isFinite(x)&&x>=0&&x<=max);return x}
function safeUrl(v,hosts){const url=new URL(str(v));check(url.protocol==='https:'&&hosts.includes(url.hostname));return url.href}
export function validateProduct(p,id){check(p&&typeof p==='object');check(['matcha','cloud','tea'].includes(p.category));check(['active','sold-out','hidden'].includes(p.status));const name=str(p.name,100);check(name);return{id,name,category:p.category,descriptionCs:str(p.descriptionCs,500),descriptionEn:str(p.descriptionEn,500),price:num(p.price,10000),image:p.image,status:p.status}}
export function createApp({dataDir,secure=process.env.NODE_ENV==='production'}={}){
 const db=openDatabase(dataDir);const attempts=new Map();
 const rows=table=>db.prepare(`SELECT value FROM ${table} ORDER BY rowid`).all().map(r=>JSON.parse(r.value));
 const audit=(actor,action,id)=>db.prepare('INSERT INTO audit(at,actor,action,entity) VALUES(?,?,?,?)').run(new Date().toISOString(),actor,action,id);
 const server=http.createServer(async(req,res)=>{
  const lang=req.headers['accept-language']?.startsWith('cs')?'cs':'en';
  const send=(code,value,headers={})=>{res.writeHead(code,{'Content-Type':'application/json; charset=utf-8','Cache-Control':'no-store',...headers});res.end(JSON.stringify(value))};
  res.setHeader('X-Content-Type-Options','nosniff');res.setHeader('Referrer-Policy','strict-origin-when-cross-origin');res.setHeader('X-Frame-Options','DENY');res.setHeader('Permissions-Policy','camera=(), microphone=(), geolocation=()');
  res.setHeader('Content-Security-Policy',"default-src 'self'; img-src 'self'; font-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'");
  if(secure)res.setHeader('Strict-Transport-Security','max-age=31536000');
  try{
   const url=new URL(req.url,'http://localhost');const path=url.pathname;
   const write=['POST','PUT','DELETE','PATCH'].includes(req.method);
   if(path.startsWith('/api/')&&write){const origin=req.headers.origin;const expected=process.env.PUBLIC_ORIGIN||`${secure?'https':'http'}://${req.headers.host}`;if(origin!==expected||req.headers['sec-fetch-site']==='cross-site'){send(403,{error:messages.origin[lang==='cs'?0:1]});return}if(path!=='/api/admin/photos'&&req.method!=='DELETE'&&!req.headers['content-type']?.startsWith('application/json')){send(415,{error:messages.invalid[lang==='cs'?0:1]});return}}
   async function body(){let chunks=[],size=0;for await(const chunk of req){size+=chunk.length;if(size>32768){const e=Error('invalid');e.status=413;throw e}chunks.push(chunk)}try{return JSON.parse(Buffer.concat(chunks).toString())}catch{check(false)}}
   function checkedPhoto(path) {
    if (/^\/assets\/(drink-[1-6]|tea-field-counter|tea-field-seating)\.jpg$/.test(path)) return path;
    const match = typeof path === 'string' && path.match(/^\/media\/([a-f0-9]{64})$/);
    check(match && db.prepare('SELECT 1 FROM photos WHERE id=?').get(match[1]));
    return path;
   }
   const photoRoute = path.match(/^\/media\/([a-f0-9]{64})$/);
   if (photoRoute && ['GET','HEAD'].includes(req.method)) {
    const photo = db.prepare('SELECT mime, bytes FROM photos WHERE id=?').get(photoRoute[1]);
    if (!photo) return send(404, {error: messages.missing[lang==='cs'?0:1]});
    res.writeHead(200, {'Content-Type':photo.mime, 'Cache-Control':'public, max-age=31536000, immutable'});
    res.end(req.method === 'HEAD' ? undefined : Buffer.from(photo.bytes));
    return;
   }
   const cookie=req.headers.cookie?.split(';').map(x=>x.trim()).find(x=>x.startsWith('tf_session='))?.slice(11)||'';
   const session=cookie?db.prepare('SELECT username FROM sessions WHERE token=? AND expires>?').get(sha(cookie),Date.now()):null;
   if(path==='/api/storefront'&&req.method==='GET'){send(200,{profile:JSON.parse(db.prepare('SELECT value FROM settings WHERE id=1').get().value),products:rows('products').filter(p=>p.status!=='hidden')});return}
   if(path==='/api/login'&&req.method==='POST'){
    const ip=req.socket.remoteAddress;const now=Date.now();for(const [k,v]of attempts)if(v.reset<now)attempts.delete(k);
    const limit=attempts.get(ip)||{count:0,reset:now+900000};if(limit.count>=8){send(429,{error:messages.rate[lang==='cs'?0:1]},{'Retry-After':'900'});return}
    const b=await body();const username=str(b.username,100);check(typeof b.password==='string'&&b.password.length<=1024);const password=b.password;const user=db.prepare('SELECT * FROM admins WHERE username=?').get(username);
    const candidate=scryptSync(password,user?.salt||'invalid-login-salt',64);const expected=Buffer.from(user?.hash||'00'.repeat(64),'hex');
    if(!timingSafeEqual(candidate,expected)||!user){limit.count++;attempts.set(ip,limit);send(401,{error:messages.credentials[lang==='cs'?0:1]});return}
    attempts.delete(ip);db.prepare('DELETE FROM sessions WHERE expires<?').run(now);const token=randomBytes(32).toString('hex');db.prepare('INSERT INTO sessions VALUES(?,?,?)').run(sha(token),user.username,now+8*3600000);
    send(200,{username:user.username},{'Set-Cookie':`tf_session=${token}; HttpOnly; SameSite=Strict; Path=/; Max-Age=28800${secure?'; Secure':''}`});return;
   }
   if(path.startsWith('/api/admin')||path==='/api/logout'){
    if(!session){send(401,{error:messages.unauthorized[lang==='cs'?0:1]});return}
    if (path === '/api/admin/photos' && req.method === 'POST') {
     const chunks = [];
     let size = 0;
     for await (const chunk of req) {
      size += chunk.length;
      if (size > 5 * 1024 * 1024) return send(413, {error:lang==='cs'?'Maximální velikost je 5 MB.':'Maximum file size is 5 MB.'});
      chunks.push(chunk);
     }
     const bytes = Buffer.concat(chunks);
     let mime;
     if (bytes.subarray(0,3).equals(Buffer.from([255,216,255])) && bytes.subarray(-2).equals(Buffer.from([255,217]))) mime='image/jpeg';
     if (bytes.subarray(0,8).equals(Buffer.from('89504e470d0a1a0a','hex')) && bytes.subarray(12,16).toString()==='IHDR') mime='image/png';
     if (bytes.subarray(0,4).toString()==='RIFF' && bytes.subarray(8,12).toString()==='WEBP') mime='image/webp';
     check(mime && req.headers['content-type']===mime);
     const id = sha(bytes);
     db.prepare('INSERT OR IGNORE INTO photos VALUES(?,?,?)').run(id, mime, bytes);
     return send(201, {image:'/media/'+id});
    }
    if(path==='/api/logout'&&req.method==='POST'){db.prepare('DELETE FROM sessions WHERE token=?').run(sha(cookie));send(200,{ok:true},{'Set-Cookie':`tf_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0${secure?'; Secure':''}`});return}
    if(path==='/api/admin'&&req.method==='GET'){send(200,{username:session.username,profile:JSON.parse(db.prepare('SELECT value FROM settings WHERE id=1').get().value),products:rows('products'),orders:rows('orders'),inventory:rows('inventory'),audit:db.prepare('SELECT * FROM audit ORDER BY id DESC LIMIT 50').all()});return}
    if(path==='/api/admin/profile'&&req.method==='PUT'){
     const p=await body();const value={heroImage:checkedPhoto(p.heroImage || '/assets/tea-field-counter.jpg'),aboutImage:checkedPhoto(p.aboutImage || '/assets/tea-field-seating.jpg'),name:str(p.name,100),address:str(p.address,200),city:str(p.city,200),hoursCs:str(p.hoursCs),hoursEn:str(p.hoursEn),instagram:safeUrl(p.instagram,['www.instagram.com','instagram.com']),maps:safeUrl(p.maps,['www.google.com','maps.google.com','maps.app.goo.gl']),orderUrl:safeUrl(p.orderUrl,['www.google.com','google.com']),checked:str(p.checked,20)};check(value.name&&value.address);db.prepare('UPDATE settings SET value=? WHERE id=1').run(JSON.stringify(value));audit(session.username,'profile.update','profile');send(200,{ok:true});return;
    }
    const match=path.match(/^\/api\/admin\/(products|orders|inventory)\/([a-zA-Z0-9_-]+)$/);
    if (match && req.method === 'DELETE') {
     const [,table,id] = match;
     db.exec('BEGIN');
     try {
      const result = db.prepare(`DELETE FROM ${table} WHERE id=?`).run(id);
      if (result.changes) audit(session.username, table+'.delete', id);
      db.exec('COMMIT');
      return result.changes ? send(200,{ok:true}) : send(404,{error:messages.missing[lang==='cs'?0:1]});
     } catch (error) {
      db.exec('ROLLBACK');
      throw error;
     }
    }
    const createDrink = match?.[1] === 'products' && req.method === 'POST';
    if(match && (req.method === 'PUT' || createDrink)){
     const [,table,id]=match;let value;const b=await body();
     if (table === 'products') {
      const exists = db.prepare('SELECT 1 FROM products WHERE id=?').get(id);
      if (createDrink && exists) return send(409,{error:lang==='cs'?'Nápoj již existuje.':'This drink already exists.'});
      if (!createDrink && !exists) return send(404,{error:messages.missing[lang==='cs'?0:1]});
      checkedPhoto(b.image);
      value = validateProduct(b,id);
     }
     if(table==='orders'){check(['received','preparing','completed','cancelled'].includes(b.status));const customer=str(b.customer,100),items=str(b.items,1000);check(customer&&items);value={id,customer,items,total:num(b.total),status:b.status,createdAt:db.prepare('SELECT value FROM orders WHERE id=?').get(id)?JSON.parse(db.prepare('SELECT value FROM orders WHERE id=?').get(id).value).createdAt:new Date().toISOString()}}
     if(table==='inventory'){const name=str(b.name,100),unit=str(b.unit,20);check(name&&unit);value={id,name,unit,quantity:num(b.quantity),threshold:num(b.threshold)}}
     db.exec('BEGIN');try{db.prepare(`INSERT INTO ${table}(id,value) VALUES(?,?) ON CONFLICT(id) DO UPDATE SET value=excluded.value`).run(id,JSON.stringify(value));audit(session.username,`${table}.save`,id);db.exec('COMMIT')}catch(e){db.exec('ROLLBACK');throw e}send(createDrink ? 201 : 200,{ok:true});return;
    }
    send(404,{error:messages.missing[lang==='cs'?0:1]});return;
   }
   if(path.startsWith('/api/')){send(404,{error:messages.missing[lang==='cs'?0:1]});return}
   if(!['GET','HEAD'].includes(req.method)){send(405,{error:'Method not allowed'});return}
   const route=path==='/'?'index.html':/^\/(admin|adminlogin|admindashboard|adminmenucatalog|adminorders|admininventory|adminanalytics|adminregister)\/?$/.test(path)?'admin.html':decodeURIComponent(path).replace(/^\//,'');
   const file=resolve(publicDir,route);if(!file.startsWith(resolve(publicDir)+sep)){send(404,{error:'Not found'});return}
   let content;try{check((await stat(file)).isFile());content=await readFile(file)}catch{send(404,{error:'Not found'});return}
   const mime={'.html':'text/html; charset=utf-8','.js':'text/javascript; charset=utf-8','.css':'text/css; charset=utf-8','.svg':'image/svg+xml','.png':'image/png','.jpg':'image/jpeg','.ico':'image/x-icon','.ttf':'font/ttf','.json':'application/json'};
   res.writeHead(200,{'Content-Type':mime[extname(file)]||'application/octet-stream','Cache-Control':extname(file)==='.html'?'no-cache':'public, max-age=3600'});res.end(req.method==='HEAD'?undefined:content);
  }catch(e){const status=e.status||400;if(status>=500)console.error('Request failed:',e.message);send(status,{error:(messages[e.message]||messages.invalid)[lang==='cs'?0:1]})}
 });
 server.on('close',()=>db.close());return {server,db};
}
if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url)){const {server}=createApp();server.listen(Number(process.env.PORT||3000),process.env.HOST||'127.0.0.1',()=>console.log(`Tea Field: http://${process.env.HOST||'127.0.0.1'}:${process.env.PORT||3000}`))}
