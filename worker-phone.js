// Cloudflare Worker + D1. The server only ever stores ciphertext; encryption happens in the browser.
// Single-file build for the Cloudflare dashboard. Version comes from the APP_VERSION variable.
const HTML = "<!doctype html>\n<html lang=\"en\"><head><meta charset=\"utf-8\">\n<meta name=\"viewport\" content=\"width=device-width,initial-scale=1,viewport-fit=cover\">\n<meta name=\"theme-color\" content=\"#14161f\"><title>Ping Ur Friends</title>\n<style>\n:root{--bg:#14161f;--panel:#1e2231;--line:#2c3247;--text:#e8eaf2;--mute:#8f96b0;--me:#3b4a8f;--ok:#5fd4b0;--bad:#ff8a7a}\n*{box-sizing:border-box}\nhtml,body{height:100%;margin:0}\nbody{background:var(--bg);color:var(--text);font:16px/1.4 ui-rounded,\"Segoe UI\",system-ui,sans-serif;display:flex;flex-direction:column;padding:env(safe-area-inset-top) 0 env(safe-area-inset-bottom)}\nheader{display:flex;align-items:center;gap:8px;padding:12px 16px;border-bottom:1px solid var(--line)}\nheader h1{font-size:18px;margin:0;flex:1}\nmain{flex:1;overflow:auto;padding:12px 16px;display:flex;flex-direction:column;gap:8px}\n[hidden]{display:none!important}\nbutton,input,select{font:inherit;color:var(--text);background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:10px 12px}\nbutton{cursor:pointer}button:focus-visible,input:focus-visible,select:focus-visible{outline:2px solid var(--ok)}\nbutton.go{background:var(--me);border-color:var(--me)}\n.row{background:var(--panel);border-radius:10px;padding:12px;display:flex;justify-content:space-between;align-items:center;gap:8px}\n.bar{display:flex;gap:8px}.bar input{flex:1;min-width:0}\n.b{max-width:80%;padding:8px 12px;border-radius:16px;overflow-wrap:anywhere;cursor:pointer;background:var(--panel)}\n.b.me{align-self:flex-end;background:var(--me)}\n.ver{margin-top:auto;padding-top:24px;text-align:center;font-size:12px;color:var(--mute)}.bal{font-size:18px;padding:8px 0}.chk{display:flex;align-items:center;gap:10px;padding:6px 0}.chk input{width:auto}h2{font-size:16px;margin:16px 0 4px}.err{color:var(--bad);min-height:1.4em}\n</style></head><body>\n<header><h1 id=\"ttl\">Ping Ur Friends</h1><button id=\"back\" hidden>Back</button><button id=\"tab\" hidden>Tally</button></header>\n\n<main id=\"v-auth\"><input id=\"un\" placeholder=\"Username\" autocomplete=\"username\"><input id=\"pw\" type=\"password\" placeholder=\"Password (8+ characters)\" autocomplete=\"current-password\">\n<div class=\"bar\"><button class=\"go\" id=\"li\">Sign in</button><button id=\"re\">Create account</button></div><div class=\"err\" id=\"err\"></div>\n<p style=\"color:var(--mute)\">Your private key is created and kept on this device. Messages are encrypted before they leave it.</p>\n<div class=\"ver\" id=\"ver\" aria-label=\"App version\"></div></main>\n\n<main id=\"v-list\" hidden><div class=\"bar\"><input id=\"q\" placeholder=\"Username to connect with\"><button class=\"go\" id=\"hs\">Send request</button></div><div class=\"err\" id=\"err2\"></div><div id=\"list\"></div><div class=\"bar\"><button class=\"go\" id=\"tl\">Open Tally</button><button id=\"out\">Sign out</button></div></main>\n\n<main id=\"v-chat\" hidden><div id=\"log\" style=\"flex:1;display:flex;flex-direction:column;gap:6px;overflow:auto\"></div>\n<div class=\"bar\"><input id=\"msg\" placeholder=\"Message\" autocomplete=\"off\"><button class=\"go\" id=\"snd\">Send</button></div>\n<small style=\"color:var(--mute)\">Tap a message to inspect its ciphertext.</small></main>\n\n<main id=\"v-tally\" hidden><div class=\"bal\" id=\"sum\"></div><div id=\"bals\"></div>\n<h2>New expense</h2><div class=\"bar\"><input id=\"amt\" type=\"number\" inputmode=\"decimal\" min=\"0\" step=\"0.01\" placeholder=\"Total amount\"><input id=\"note\" placeholder=\"What for?\"></div>\n<div>Split evenly with you and:</div><div id=\"who\"></div>\n<div class=\"bar\"><select id=\"payer\" aria-label=\"Paid by\"></select><button class=\"go\" id=\"split\">Split evenly</button></div><div class=\"err\" id=\"err3\"></div>\n<h2>History</h2><div id=\"exp\"></div></main>\n\n<script>\nconst $=s=>document.querySelector(s),E=new TextEncoder(),D=new TextDecoder(),EC={name:'ECDH',namedCurve:'P-256'};\nconst b64=b=>btoa(String.fromCharCode(...new Uint8Array(b))),ub=s=>Uint8Array.from(atob(s),c=>c.charCodeAt(0));\nlet tok=localStorage.tok,me=JSON.parse(localStorage.me||'null'),cur=null,last=0,timer,keys={},bal=0,view='v-auth';\nconst money=c=>'$'+(c/100).toFixed(2);\nasync function api(p,body){\n  const r=await fetch('/api/'+p,{method:body?'POST':'GET',headers:{authorization:'Bearer '+tok,'content-type':'application/json'},body:body&&JSON.stringify(body)});\n  const j=await r.json();if(!r.ok)throw new Error(j.error||'Request failed');return j}\nfunction show(v){view=v;for(const m of document.querySelectorAll('main'))m.hidden=m.id!==v;\n  $('#back').hidden=v!=='v-chat'&&v!=='v-tally';$('#tab').hidden=v!=='v-chat';\n  $('#ttl').textContent=v==='v-chat'?cur.name:v==='v-tally'?'Tally':'Ping Ur Friends'}\n\nasync function auth(reg){\n  const name=$('#un').value.trim(),pw=$('#pw').value;let pub,pk;\n  try{\n    if(reg){const k=await crypto.subtle.generateKey(EC,true,['deriveKey']);\n      pk=JSON.stringify(await crypto.subtle.exportKey('jwk',k.privateKey));pub=JSON.stringify(await crypto.subtle.exportKey('jwk',k.publicKey))}\n    else if(!localStorage['pk_'+name])throw Error('This device has no key for that account. Sign in on the device where you created it.');\n    const j=await api(reg?'register':'login',{name,pw,pub});\n    if(reg)localStorage['pk_'+name]=pk;\n    tok=localStorage.tok=j.token;me=j.me;localStorage.me=JSON.stringify(me);start();\n  }catch(e){$('#err').textContent=e.message}}\n\nasync function key(f){ // ECDH shared secret -> AES-GCM key, cached per friend\n  if(keys[f.id])return keys[f.id];\n  const pr=await crypto.subtle.importKey('jwk',JSON.parse(localStorage['pk_'+me.name]),EC,false,['deriveKey']);\n  const pu=await crypto.subtle.importKey('jwk',JSON.parse(f.pub),EC,false,[]);\n  return keys[f.id]=await crypto.subtle.deriveKey({name:'ECDH',public:pu},pr,{name:'AES-GCM',length:256},false,['encrypt','decrypt'])}\n\nasync function friends(){\n  const j=await api('friends'),l=$('#list');l.innerHTML='';\n  if(!j.length)l.textContent='No friends yet. Enter a username above to send a handshake request.';\n  for(const f of j){const d=document.createElement('div');d.className='row';\n    const s=document.createElement('span');s.textContent=f.name+(f.status==='pending'?(f.incoming?' wants to connect':' (request sent)'):'');d.append(s);\n    if(f.status==='pending'&&f.incoming){const b=document.createElement('button');b.className='go';b.textContent='Accept';\n      b.onclick=async()=>{await api('accept',{from:f.id});friends()};d.append(b)}\n    else if(f.status==='accepted'){d.style.cursor='pointer';d.onclick=()=>openChat(f)}\n    l.append(d)}}\n\nfunction add(m,t){const d=document.createElement('div');d.className='b '+(m.frm===me.id?'me':'');d.textContent=t;\n  d.onclick=()=>{const on=d.dataset.c;d.textContent=on?t:'\ud83d\udd10 '+m.ct.slice(0,140)+'\u2026';d.dataset.c=on?'':1};\n  $('#log').append(d);$('#log').scrollTop=1e9}\nasync function poll(){\n  if(!cur||view!=='v-chat')return;\n  try{for(const m of await api(`msgs?with=${cur.id}&after=${last}`)){last=m.id;let t;\n    try{t=D.decode(await crypto.subtle.decrypt({name:'AES-GCM',iv:ub(m.iv)},await key(cur),ub(m.ct)))}catch{t='Cannot decrypt this message'}add(m,t)}}catch{}}\nfunction openChat(f){cur=f;last=0;$('#log').innerHTML='';show('v-chat');poll();clearInterval(timer);timer=setInterval(poll,3000)}\nasync function send(){\n  const t=$('#msg').value.trim();if(!t)return;$('#msg').value='';\n  const iv=crypto.getRandomValues(new Uint8Array(12)),ct=await crypto.subtle.encrypt({name:'AES-GCM',iv},await key(cur),E.encode(t));\n  await api('send',{to:cur.id,iv:b64(iv),ct:b64(ct)});poll()}\n\nlet fr=[];\nfunction payers(){ // \"Paid by\" can be you or anyone ticked\n  const s=$('#payer'),p=s.value;s.innerHTML='';\n  s.add(new Option('Paid by you',me.id));\n  for(const c of document.querySelectorAll('#who input:checked'))s.add(new Option('Paid by '+c.parentNode.textContent,c.value));\n  if([...s.options].some(o=>o.value===p))s.value=p}\nasync function tally(){\n  show('v-tally');\n  const [rows,fl]=await Promise.all([api('tally'),api('friends')]);\n  fr=fl.filter(f=>f.status==='accepted');\n  const name={},bal={},seen=new Map();for(const f of fr){name[f.id]=f.name;bal[f.id]=0}\n  const nm=id=>id===me.id?'You':name[id]||'Someone';\n  for(const x of rows){const mine=x.payer===me.id,o=mine?x.other:x.payer;bal[o]=(bal[o]||0)+(mine?x.owed:-x.owed);\n    const g=seen.get(x.grp)||seen.set(x.grp,{x,sum:0}).get(x.grp);g.sum+=x.owed}\n  let get=0,owe=0;const B=$('#bals');B.innerHTML='';\n  if(!fr.length)B.textContent='Connect with a friend first, then you can split expenses here.';\n  for(const f of fr){const v=bal[f.id],d=document.createElement('div'),s=document.createElement('span');d.className='row';\n    s.textContent=v>0?`${f.name} owes you ${money(v)}`:v<0?`You owe ${f.name} ${money(-v)}`:`${f.name}: settled`;\n    s.style.color=v>0?'var(--ok)':v<0?'var(--bad)':'';d.append(s);\n    if(v){const b=document.createElement('button');b.textContent='Settle up';b.onclick=()=>settle(f.id,v);d.append(b)}\n    B.append(d);v>0?get+=v:owe-=v}\n  $('#sum').textContent=`You're owed ${money(get)}. You owe ${money(owe)}.`;\n  const W=$('#who');W.innerHTML='';\n  for(const f of fr){const l=document.createElement('label'),c=document.createElement('input');l.className='chk';c.type='checkbox';c.value=f.id;c.onchange=payers;l.append(c,f.name);W.append(l)}\n  payers();\n  const H=$('#exp');H.innerHTML='';\n  if(!seen.size)H.textContent='No expenses yet.';\n  for(const {x,sum} of seen.values()){const d=document.createElement('div');d.className='row';\n    d.textContent=x.note==='Settlement'?`${nm(x.payer)} paid ${x.other===me.id?'you':nm(x.other)} ${money(x.owed)} to settle up`\n      :`${nm(x.payer)} paid ${money(x.total)} for ${x.note||'an expense'}. Your share: ${money(x.payer===me.id?x.total-sum:x.owed)}`;H.append(d)}}\nasync function split(){\n  try{const a=Math.round(parseFloat($('#amt').value)*100),ids=[me.id,...[...document.querySelectorAll('#who input:checked')].map(c=>+c.value)];\n    if(!(a>0))throw Error('Enter the total amount');if(ids.length<2)throw Error('Tick at least one friend to split with');\n    await api('expense',{payer:+$('#payer').value,people:ids,total:a,note:$('#note').value.trim()});\n    $('#amt').value=$('#note').value='';$('#err3').textContent='';tally()\n  }catch(e){$('#err3').textContent=e.message}}\nasync function settle(id,v){ // friend owes you (v>0): they pay you; otherwise you pay them\n  try{await api('expense',{settle:1,payer:v>0?id:me.id,people:[me.id,id],total:Math.abs(v)});tally()}catch(e){$('#err3').textContent=e.message}}\n\nfunction start(){if(tok&&me){cur=null;show('v-list');friends().catch(()=>{tok=null;show('v-auth')})}else show('v-auth')}\n$('#li').onclick=()=>auth(0);$('#re').onclick=()=>auth(1);$('#snd').onclick=send;$('#msg').onkeydown=e=>e.key==='Enter'&&send();\n$('#hs').onclick=async()=>{try{await api('handshake',{name:$('#q').value.trim()});$('#q').value='';$('#err2').textContent='Request sent';friends()}catch(e){$('#err2').textContent=e.message}};\n$('#back').onclick=()=>{clearInterval(timer);start()};$('#tab').onclick=tally;$('#tl').onclick=()=>tally().catch(()=>{});\n$('#split').onclick=split;\n$('#out').onclick=()=>{localStorage.removeItem('tok');tok=me=null;show('v-auth')};\nfetch('/api/version').then(r=>r.json()).then(j=>{$('#ver').textContent='v'+j.version}).catch(()=>{});\nstart();\n</script></body></html>\n";
const J = (d, s = 200) => Response.json(d, { status: s });
const enc = new TextEncoder();
const b64 = (b) => btoa(String.fromCharCode(...new Uint8Array(b)));

async function hash(pw, salt, iter) {
  const k = await crypto.subtle.importKey('raw', enc.encode(pw), 'PBKDF2', false, ['deriveBits']);
  return b64(await crypto.subtle.deriveBits(
    { name: 'PBKDF2', hash: 'SHA-256', salt: enc.encode(salt), iterations: iter }, k, 256));
}
async function session(db, id, name) {
  const token = crypto.randomUUID() + crypto.randomUUID();
  await db.prepare('INSERT INTO sessions VALUES(?,?,?)').bind(token, id, Date.now()).run();
  return J({ token, me: { id, name } });
}

export default {
  async fetch(req, env) {
    const url = new URL(req.url), db = env.DB, q = url.searchParams;
    if (!url.pathname.startsWith('/api/')) return new Response(HTML, { headers: { 'content-type': 'text/html;charset=utf-8' } });
    const p = url.pathname.slice(5);
    const b = req.method === 'POST' ? await req.json().catch(() => ({})) : {};
    try {
      if (p === 'version') return J({ version: env.APP_VERSION || 'dev' });
      if (p === 'register') {
        const { name, pw, pub } = b;
        if (!/^\w{3,20}$/.test(name || '') || (pw || '').length < 8 || !pub)
          return J({ error: 'Use a 3-20 character username and a password of 8+ characters' }, 400);
        // Iterations are stored with each hash. Workers allow at most 100000; on the free plan (10 ms CPU) set PBKDF2_ITER=50000.
        const it = Math.min(Math.max(+env.PBKDF2_ITER || 100000, 10000), 100000);
        const salt = crypto.randomUUID();
        const r = await db.prepare('INSERT INTO users(name,salt,hash,pub) VALUES(?,?,?,?)')
          .bind(name, salt, `${it}$${await hash(pw, salt, it)}`, pub).run().catch(() => null);
        return r ? session(db, r.meta.last_row_id, name) : J({ error: 'Username is taken' }, 409);
      }
      if (p === 'login') {
        const u = await db.prepare('SELECT * FROM users WHERE name=?').bind(b.name || '').first();
        const [it, h] = u ? u.hash.split('$') : [];
        if (!u || (await hash(b.pw || '', u.salt, +it)) !== h) return J({ error: 'Wrong username or password' }, 401);
        return session(db, u.id, u.name);
      }

      const s = await db.prepare('SELECT uid FROM sessions WHERE token=? AND ts>?')
        .bind((req.headers.get('authorization') || '').slice(7), Date.now() - 6048e5).first();
      if (!s) return J({ error: 'Please sign in again' }, 401);
      const me = s.uid;
      const linked = async (o) => !!(await db.prepare(
        "SELECT 1 FROM links WHERE status='accepted' AND ((a=?1 AND b=?2) OR (a=?2 AND b=?1))").bind(me, o).first());
      const o = +q.get('with') || 0;

      if (p === 'handshake') {
        const t = await db.prepare('SELECT id FROM users WHERE name=?').bind(b.name || '').first();
        if (!t || t.id === me) return J({ error: 'No user with that name' }, 404);
        await db.prepare("INSERT OR IGNORE INTO links VALUES(?,?,'pending')").bind(me, t.id).run();
        return J({ ok: 1 });
      }
      if (p === 'accept') {
        await db.prepare("UPDATE links SET status='accepted' WHERE a=? AND b=?").bind(b.from, me).run();
        return J({ ok: 1 });
      }
      if (p === 'friends')
        return J((await db.prepare(
          `SELECT u.id,u.name,u.pub,l.status,(l.b=?1) AS incoming FROM links l
           JOIN users u ON u.id=CASE WHEN l.a=?1 THEN l.b ELSE l.a END WHERE l.a=?1 OR l.b=?1`).bind(me).all()).results);

      if (p === 'msgs') {
        if (!(await linked(o))) return J({ error: 'Not connected' }, 403);
        return J((await db.prepare(
          `SELECT id,frm,iv,ct,ts FROM msgs WHERE id>?3 AND ((frm=?1 AND dst=?2) OR (frm=?2 AND dst=?1))
           ORDER BY id LIMIT 100`).bind(me, o, +q.get('after') || 0).all()).results);
      }
      if (p === 'send') {
        if (!(await linked(b.to))) return J({ error: 'Not connected' }, 403);
        await db.prepare('INSERT INTO msgs(frm,dst,iv,ct,ts) VALUES(?,?,?,?,?)')
          .bind(me, b.to, String(b.iv), String(b.ct), Date.now()).run();
        return J({ ok: 1 });
      }

      if (p === 'tally')
        return J((await db.prepare(
          `SELECT grp,payer,other,owed,total,note,ts FROM expenses WHERE payer=?1 OR other=?1
           ORDER BY id DESC LIMIT 500`).bind(me).all()).results);

      if (p === 'expense') {
        // {payer, people:[ids incl. payer and you], total (cents), note}. {settle:1} records a full repayment.
        const ids = [...new Set(Array.isArray(b.people) ? b.people : [])], pay = b.payer, tot = b.total;
        if (!ids.every(Number.isInteger) || !Number.isInteger(tot) || tot <= 0 || ids.length < 2 ||
            !ids.includes(pay) || !ids.includes(me) || (b.settle && ids.length !== 2))
          return J({ error: 'Pick at least two people, including yourself' }, 400);
        // One query per side (not per person), so group size doesn't add database calls.
        const friendsOf = async (u) => new Set((await db.prepare(
          "SELECT CASE WHEN a=?1 THEN b ELSE a END AS f FROM links WHERE status='accepted' AND (a=?1 OR b=?1)")
          .bind(u).all()).results.map((r) => r.f));
        const mine = await friendsOf(me), theirs = pay === me ? mine : await friendsOf(pay);
        if (!ids.every((x) => x === me || mine.has(x)) || !ids.every((x) => x === pay || theirs.has(x)))
          return J({ error: 'Everyone must be connected with you and with the payer' }, 400);
        const n = ids.length, base = Math.floor(tot / n), grp = crypto.randomUUID();
        const note = b.settle ? 'Settlement' : String(b.note || '').slice(0, 80);
        let rem = tot - base * n;
        const rows = [];
        for (const x of ids) {
          const sh = b.settle ? tot : base + (rem-- > 0 ? 1 : 0); // spare cents go to the first people listed
          if (x !== pay && sh > 0) rows.push([x, sh]);
        }
        if (!rows.length) return J({ error: 'Amount is too small to split' }, 400);
        const ins = db.prepare('INSERT INTO expenses(grp,payer,other,owed,total,note,ts) VALUES(?,?,?,?,?,?,?)');
        const ts = Date.now(), st = rows.map(([x, sh]) => ins.bind(grp, pay, x, sh, tot, note, ts));
        for (let i = 0; i < st.length; i += 50) await db.batch(st.slice(i, i + 50));
        return J({ ok: 1 });
      }
      return J({ error: 'Not found' }, 404);
    } catch (e) {
      return J({ error: 'Server error' }, 500);
    }
  },
};
