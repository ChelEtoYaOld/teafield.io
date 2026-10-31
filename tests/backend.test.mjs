import {test} from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,rm,readFile} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {scryptSync} from 'node:crypto';
import {createApp} from '../server/index.mjs';

test('backend: authentication, validation, persistence and bilingual errors',async t=>{
 const dir=await mkdtemp(join(tmpdir(),'tea-test-'));const {server,db}=createApp({dataDir:dir});db.prepare('INSERT INTO admins VALUES(?,?,?)').run('test','salt',scryptSync('test-password-only','salt',64).toString('hex'));
 await new Promise(r=>server.listen(0,'127.0.0.1',r));const base=`http://127.0.0.1:${server.address().port}`;let cookie='';
 const request=(path,method='GET',body,extra={})=>fetch(base+path,{method,headers:{Origin:base,'Content-Type':'application/json',Cookie:cookie,...extra},...(body?{body:JSON.stringify(body)}:{})});
 try{
  await t.test('public catalogue contains only six verified favourites',async()=>{const r=await request('/api/storefront');assert.equal(r.status,200);const j=await r.json();assert.equal(j.products.length,6);assert.equal(j.profile.address,'Thámova 136/8');assert.equal(j.products[0].name,'Mango Matcha')});
  await t.test('anonymous writes and reads are blocked',async()=>{assert.equal((await request('/api/admin')).status,401);assert.equal((await request('/api/admin/products/mango-matcha','PUT',{})).status,401)});
  await t.test('rejects cross-origin writes',async()=>{assert.equal((await request('/api/login','POST',{username:'test',password:'test-password-only'},{Origin:'https://other.example'})).status,403)});
  await t.test('localized login error and valid httpOnly cookie',async()=>{let r=await request('/api/login','POST',{username:'test',password:'wrong'},{'Accept-Language':'cs'});assert.equal(r.status,401);assert.equal((await r.json()).error,'Neplatné přihlašovací údaje.');r=await request('/api/login','POST',{username:'test',password:'test-password-only'});assert.equal(r.status,200);assert.match(r.headers.get('set-cookie'),/HttpOnly; SameSite=Strict/);cookie=r.headers.get('set-cookie').split(';')[0]});
  const product=(await(await request('/api/admin')).json()).products[0];
  await t.test('rejects negative price and unsafe image',async()=>{assert.equal((await request('/api/admin/products/'+product.id,'PUT',{...product,price:-2})).status,400);assert.equal((await request('/api/admin/products/'+product.id,'PUT',{...product,image:'https://evil.example/a.jpg'})).status,400)});
  await t.test('catalogue edits persist and hidden items disappear publicly',async()=>{assert.equal((await request('/api/admin/products/'+product.id,'PUT',{...product,price:160,status:'hidden'})).status,200);let j=await(await request('/api/storefront')).json();assert.equal(j.products.length,5);assert.equal(JSON.parse(db.prepare('SELECT value FROM products WHERE id=?').get(product.id).value).price,160)});
  await t.test('orders, inventory and audit are saved',async()=>{assert.equal((await request('/api/admin/orders/test-order','PUT',{customer:'Test',items:'Matcha',total:155,status:'received'})).status,200);assert.equal((await request('/api/admin/inventory/test-stock','PUT',{name:'Matcha',unit:'g',quantity:10,threshold:20})).status,200);const j=await(await request('/api/admin')).json();assert.equal(j.orders.length,1);assert.equal(j.inventory.length,1);assert.equal(j.audit.length,3)});
  await t.test('malicious profile links rejected',async()=>{const j=await(await request('/api/admin')).json();assert.equal((await request('/api/admin/profile','PUT',{...j.profile,orderUrl:'javascript:alert(1)'})).status,400)});
  await t.test('static files and security headers',async()=>{const r=await request('/');assert.equal(r.status,200);assert.match(r.headers.get('content-security-policy'),/frame-ancestors 'none'/);assert.equal((await request('/.env')).status,404);assert.equal((await request('/admin')).status,200)});
  await t.test('staff can upload a photo and use it for a drink and the homepage', async () => {
   const photo = await readFile(new URL('../public/assets/tea-field-counter.jpg',import.meta.url));
   const upload = (bytes, token) => fetch(base+'/api/admin/photos', {method:'POST',headers:{Origin:base,Cookie:token,'Content-Type':'image/jpeg'},body:bytes});
   assert.equal((await upload(photo,'')).status,401);
   assert.equal((await upload(Buffer.from('<svg/>'),cookie)).status,400);
   const response = await upload(photo,cookie);
   assert.equal(response.status,201);
   const {image} = await response.json();
   const current = await (await request('/api/admin')).json();
   assert.equal((await request('/api/admin/profile','PUT',{...current.profile,heroImage:image,aboutImage:image})).status,200);
   assert.equal((await request('/api/admin/products/'+product.id,'PUT',{...product,image})).status,200);
   const publicData = await (await request('/api/storefront')).json();
   assert.equal(publicData.profile.heroImage,image);
   assert.equal(publicData.profile.aboutImage,image);
   assert.equal(publicData.products.find(row=>row.id===product.id).image,image);
   assert.deepEqual(Buffer.from(await (await request(image)).arrayBuffer()),photo);
  });
  await t.test('delete is protected and removes only the selected records', async () => {
   for (const [table,id] of [['orders','test-order'],['inventory','test-stock'],['products',product.id]]) {
    const endpoint = '/api/admin/'+table+'/'+id;
    assert.equal((await request(endpoint,'DELETE',null,{Cookie:''})).status,401);
    assert.equal((await request(endpoint,'DELETE',null,{Origin:'https://other.example'})).status,403);
    assert.equal((await request(endpoint,'DELETE')).status,200);
    assert.equal((await request(endpoint,'DELETE')).status,404);
   }
   const admin = await (await request('/api/admin')).json();
   assert.equal(admin.orders.length,0);
   assert.equal(admin.inventory.length,0);
   assert.equal(admin.products.length,5);
   assert.equal(admin.audit.filter(row=>row.action.endsWith('.delete')).length,3);
  });
  await t.test('create a visible favourite from an empty catalogue', async () => {
   const menu = await (await request('/api/storefront')).json();
   for (const row of menu.products) {
    assert.equal((await request('/api/admin/products/'+row.id,'DELETE')).status,200);
   }
   assert.deepEqual((await (await request('/api/storefront')).json()).products,[]);
   const endpoint = '/api/admin/products/new-drink';
   const drink = {...product, name:'New drink',image:menu.profile.heroImage,status:'active'};
   assert.equal((await request(endpoint,'POST',drink,{Cookie:''})).status,401);
   assert.equal((await request(endpoint,'POST',drink)).status,201);
   assert.equal((await request(endpoint,'POST',drink)).status,409);
   const result = await (await request('/api/storefront')).json();
   assert.deepEqual(result.products,[{...drink,id:'new-drink'}]);
  });
  await t.test('logout revokes session',async()=>{assert.equal((await request('/api/logout','POST',{})).status,200);assert.equal((await request('/api/admin')).status,401)});
 }finally{await new Promise(r=>server.close(r));await rm(dir,{recursive:true,force:true})}
});
