/* ===================================================================
   Balls! game server (Cloudflare Worker + Durable Objects)
   One Table object per 4-letter code runs the whole game: it shuffles,
   deals, checks every move and sends each player only their own cards.
   The rules engine above this block is copied from index.html by build.mjs,
   so the browser (bot games) and the server always play by the same rules.
   =================================================================== */
const CORS={'Access-Control-Allow-Origin':'*','Access-Control-Allow-Methods':'GET,POST,OPTIONS','Access-Control-Allow-Headers':'content-type'};
const json=(o,status=200)=>new Response(JSON.stringify(o),{status,headers:{'content-type':'application/json',...CORS}});
const AWAY_PLAY_MS=30000, AWAY_LOBBY_MS=60000, EMPTY_CLOSE_MS=10*60000, CHAT_KEEP=40;
const ID_RE=/^[A-Za-z0-9_-]{4,40}$/;
const sid=()=>Math.random().toString(36).slice(2,10);
const clean=(t,n)=>String(t==null?'':t).replace(/[\u0000-\u001f]/g,'').trim().slice(0,n);

export default {
  async fetch(req, env){
    const url=new URL(req.url);
    if(req.method==='OPTIONS') return new Response(null,{status:204,headers:CORS});
    const acc=url.pathname.match(/^\/api\/account\/(register|login|me|logout|delete|password)$/);
    if(acc){
      if(req.method!=='POST') return json({error:'Use POST.'},405);
      const r=await env.ACCOUNTS.get(env.ACCOUNTS.idFromName('accounts')).fetch('https://acct/'+acc[1],{method:'POST',body:await req.text()});
      return new Response(await r.text(),{status:r.status,headers:{'content-type':'application/json',...CORS}});
    }
    if(url.pathname==='/api/lobby'){
      const stub=env.LOBBY.get(env.LOBBY.idFromName('lobby'));
      const r=await stub.fetch('https://lobby/list');
      return new Response(await r.text(),{headers:{'content-type':'application/json',...CORS}});
    }
    const m=url.pathname.match(/^\/api\/table\/([A-Z]{4})$/);
    if(m){
      if(req.headers.get('Upgrade')!=='websocket') return json({error:'Use a WebSocket to join a table.'},426);
      return env.TABLE.get(env.TABLE.idFromName(m[1])).fetch(req);
    }
    if(url.pathname==='/'||url.pathname==='/api/health') return json({ok:true,game:'balls',version:VERSION});
    return json({error:'not found'},404);
  }
};

/* ---------- accounts: name + scrambled password + win/loss record, nothing else ----------
   Passwords are stored as PBKDF2 hashes; sessions as hashes of a random token. */
const enc=new TextEncoder();
const b64u=buf=>{ let t=''; for(const x of new Uint8Array(buf)) t+=String.fromCharCode(x); return btoa(t).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,''); };
const sha256=async t=>b64u(await crypto.subtle.digest('SHA-256',enc.encode(t)));
async function pwHash(pw,salt){ const k=await crypto.subtle.importKey('raw',enc.encode(pw),'PBKDF2',false,['deriveBits']); return b64u(await crypto.subtle.deriveBits({name:'PBKDF2',hash:'SHA-256',salt:enc.encode(salt),iterations:100000},k,256)); }
const NAME_RE=/^[A-Za-z0-9_-]{3,14}$/, SESSION_MS=180*864e5;
const ACH_IDS=['a69','a69x2','a100','w0','w1','w2','w3','w4','j1','j2','j4','t3j','t4','tj','tjj','t2j','flawless',
  'win1','balls1','quick','gotcha','oops','comeback','survivor','m10','m50'];
/* the developer account: created on first use, before anyone else can take the name.
   Only a salted PBKDF2 hash is stored here, never the password. */
const DEV_SEED={key:'u:giel',user:{uid:'dev-giel',name:'giel',role:'dev',salt:'WMnmARFKRbPGMB2dE04Iow',hash:'GN8sQ2k_-Ob78uQMogpmAI-cnRdmCvIRjBog4zz956g',wins:0,losses:0,played:0}};
/* compare two hashes without leaking how many characters matched */
const same=(a,b)=>{ if(typeof a!=='string'||typeof b!=='string'||a.length!==b.length) return false; let x=0; for(let i=0;i<a.length;i++) x|=a.charCodeAt(i)^b.charCodeAt(i); return x===0; };
export class Accounts {
  constructor(ctx){ this.ctx=ctx; }
  async fetch(req){
    const st=this.ctx.storage, path=new URL(req.url).pathname.slice(1);
    if(!this.seeded){ this.seeded=true; if(!(await st.get(DEV_SEED.key))) await st.put(DEV_SEED.key,{...DEV_SEED.user,created:Date.now()}); }
    let b={}; try{ b=await req.json()||{}; }catch(e){}
    const out=(o,status=200)=>new Response(JSON.stringify(o),{status,headers:{'content-type':'application/json'}});
    const no=(code,status=400)=>out({error:code},status);
    const pub=u=>({name:u.name,wins:u.wins||0,losses:u.losses||0,played:u.played||0,since:u.created,ach:u.ach||{},dev:u.role==='dev'});
    const keyOf=n=>'u:'+String(n||'').toLowerCase();
    const session=async tok=>{
      if(typeof tok!=='string'||tok.length<20||tok.length>100) return null;
      const se=await st.get('s:'+await sha256(tok)); if(!se||se.exp<Date.now()) return null;
      const u=await st.get(se.key); return u&&u.uid===se.uid?u:null;
    };
    const newSession=async u=>{ const tok=b64u(crypto.getRandomValues(new Uint8Array(32))); await st.put('s:'+await sha256(tok),{uid:u.uid,key:keyOf(u.name),exp:Date.now()+SESSION_MS}); return tok; };
    const pwOk=pw=>typeof pw==='string'&&pw.length>=8&&pw.length<=100;
    const pwRight=async(u,pw)=>typeof pw==='string'&&same(await pwHash(pw,u.salt),u.hash);
    switch(path){
      case 'register': {
        const name=String(b.name||'').trim();
        if(!NAME_RE.test(name)) return no('name');
        if(!pwOk(b.password)) return no('pw');
        if(await st.get(keyOf(name))) return no('taken',409);
        const salt=b64u(crypto.getRandomValues(new Uint8Array(16)));
        const u={uid:sid()+sid(),name,salt,hash:await pwHash(b.password,salt),created:Date.now(),wins:0,losses:0,played:0};
        await st.put(keyOf(name),u);
        return out({token:await newSession(u),user:pub(u)});
      }
      case 'login': {
        const u=await st.get(keyOf(String(b.name||'').trim()));
        if(!u||typeof b.password!=='string') return no('login',401);
        if(u.lockUntil&&u.lockUntil>Date.now()) return no('locked',429);
        if(!await pwRight(u,b.password)){
          u.fails=(u.fails||0)+1; if(u.fails>=8){ u.lockUntil=Date.now()+5*60e3; u.fails=0; }
          await st.put(keyOf(u.name),u); return no('login',401);
        }
        if(u.fails||u.lockUntil){ delete u.fails; delete u.lockUntil; await st.put(keyOf(u.name),u); }
        return out({token:await newSession(u),user:pub(u)});
      }
      case 'me': { const u=await session(b.token); return u?out({user:pub(u)}):no('auth',401); }
      case 'logout': { if(typeof b.token==='string') await st.delete('s:'+await sha256(b.token)); return out({ok:true}); }
      case 'delete': {
        const u=await session(b.token); if(!u) return no('auth',401);
        if(!await pwRight(u,b.password)) return no('login',401);
        await st.delete(keyOf(u.name)); await st.delete('s:'+await sha256(b.token));
        return out({ok:true});
      }
      /* only reachable from game tables, never from the internet */
      case 'password': {
        const u=await session(b.token); if(!u) return no('auth',401);
        if(!await pwRight(u,b.password)) return no('login',401);
        if(!pwOk(b.next)) return no('pw');
        u.salt=b64u(crypto.getRandomValues(new Uint8Array(16))); u.hash=await pwHash(b.next,u.salt);
        await st.put(keyOf(u.name),u); return out({ok:true});
      }
      case 'verify': { const u=await session(b.token); return u?out({uid:u.uid,name:u.name,dev:u.role==='dev'}):no('auth',401); }
      case 'achieve': {
        const u=await st.get(keyOf(b.name)); if(!u||u.uid!==b.uid) return out({fresh:[]});
        const fresh=[]; u.ach=u.ach||{};
        for(const a of (Array.isArray(b.ids)?b.ids:[])) if(ACH_IDS.includes(a)&&!u.ach[a]){ u.ach[a]=Date.now(); fresh.push(a); }
        if(fresh.length) await st.put(keyOf(u.name),u);
        return out({fresh,user:pub(u)});
      }
      case 'result': {
        const done={}, fresh={};
        for(const r of (Array.isArray(b.results)?b.results:[])){
          const u=await st.get(keyOf(r.name)); if(!u||u.uid!==r.uid||done[u.uid]) continue;
          u.played=(u.played||0)+1; if(r.win) u.wins=(u.wins||0)+1; else u.losses=(u.losses||0)+1;
          u.ach=u.ach||{}; const fr=[];
          for(const [n,a] of [[10,'m10'],[50,'m50']]) if(u.played>=n&&!u.ach[a]){ u.ach[a]=Date.now(); fr.push(a); }
          await st.put(keyOf(u.name),u); done[u.uid]=pub(u); fresh[u.uid]=fr;
        }
        return out({users:done,fresh});
      }
    }
    return no('nope',404);
  }
}

/* ---------- public table list ---------- */
export class Lobby {
  constructor(ctx){ this.ctx=ctx; }
  async fetch(req){
    let list=(await this.ctx.storage.get('list'))||{};
    const now=Date.now();
    for(const k of Object.keys(list)) if(now-(list[k].at||0)>2*3600e3) delete list[k];
    if(req.method==='POST'){
      const b=await req.json();
      if(b&&/^[A-Z]{4}$/.test(b.code)){ if(b.drop) delete list[b.code]; else list[b.code]={n:clean(b.info.n,14),p:b.info.p|0,m:b.info.m|0,s:clean(b.info.s,80),at:now}; }
      await this.ctx.storage.put('list',list);
      return new Response('ok');
    }
    return new Response(JSON.stringify(Object.entries(list).map(([code,x])=>({code,...x}))),{headers:{'content-type':'application/json'}});
  }
}

/* ---------- one game table ---------- */
export class Table {
  constructor(ctx, env){ this.ctx=ctx; this.env=env; this.loaded=false; }

  async load(){
    if(this.loaded) return;
    const got=await this.ctx.storage.get(['s','sec','chat','meta']);
    this.s=got.get('s')||null; this.sec=got.get('sec')||{}; this.chat=got.get('chat')||[]; this.meta=got.get('meta')||{away:{},listed:null,code:null};
    this.loaded=true;
  }
  async save(){ await this.ctx.storage.put({s:this.s,sec:this.sec,chat:this.chat,meta:this.meta}); }

  async fetch(req){
    const code=(new URL(req.url).pathname.match(/([A-Z]{4})$/)||[])[1];
    await this.load();
    if(code&&!this.meta.code){ this.meta.code=code; }
    const pair=new WebSocketPair(); const [client,server]=Object.values(pair);
    this.ctx.acceptWebSocket(server);
    return new Response(null,{status:101,webSocket:client});
  }

  /* ---- sockets ---- */
  sockets(){ return this.ctx.getWebSockets(); }
  att(ws){ try{ return ws.deserializeAttachment()||{}; }catch(e){ return {}; } }
  online(id,except){ return this.sockets().some(w=>w!==except&&this.att(w).id===id&&w.readyState===1); }
  sendTo(ws,o){ try{ ws.send(JSON.stringify(o)); }catch(e){} }
  err(ws,msg,code){ this.sendTo(ws,{t:'err',msg,code}); }
  view(id){
    const s=this.s, v=JSON.parse(JSON.stringify(s));
    v.hands={}; for(const [pid,h] of Object.entries(s.hands||{})) v.hands[pid]=pid===id?h.slice():h.map(()=> 'back');
    v.deck=(s.deck||[]).map(()=>0);
    v.now=Date.now();
    return v;
  }
  broadcast(){ for(const ws of this.sockets()){ const a=this.att(ws); if(a.id&&ws.readyState===1) this.sendTo(ws,{t:'state',s:this.view(a.id)}); } }
  humans(){ return this.s?this.s.players.filter(p=>!p.bot):[]; }

  async webSocketMessage(ws,raw){
    await this.load();
    let m; try{ m=JSON.parse(raw); }catch(e){ return; }
    if(!m||typeof m!=='object') return;
    lang=m.lang==='nl'||this.att(ws).lang==='nl'?'nl':'en';
    if(m.t==='hello') return this.hello(ws,m);
    const a=this.att(ws); if(!a.id||!this.s){ return this.err(ws,L('Join the table first.','Doe eerst mee aan de tafel.')); }
    if(m.t==='chat') return this.chatMsg(ws,a,m);
    if(m.t==='act') return this.action(ws,a,m);
  }

  async hello(ws,m){
    const id=String(m.id||''), secret=String(m.secret||'');
    let name=clean(m.name,14)||'Player';
    if(!ID_RE.test(id)||secret.length<8) return this.err(ws,'Bad hello.');
    let account=null;
    if(m.token){ try{ const r=await this.acctStub().fetch('https://acct/verify',{method:'POST',body:JSON.stringify({token:String(m.token)})}); if(r.ok) account=await r.json(); }catch(e){} }
    if(account) name=account.name;
    const code=this.meta.code;
    if(m.create){
      const live=this.s&&this.humans().some(p=>this.online(p.id,ws));
      if(live) return this.err(ws,'That code is taken.','exists');
      const rules=sanitizeRules(m.rules);
      this.s={v:1,phase:'lobby',host:id,code,players:[{id,name,score:0,out:false}],round:0,dealer:0,log:[],v_round:0,created:Date.now(),rules,stats:{},history:[]};
      this.sec={}; this.chat=[]; this.meta.away={}; this.meta.listed=null; this.meta.sum=clean(m.sum,80);
    }
    const s=this.s;
    if(!s) return this.err(ws,L(`No table with code ${code}.`,`Er is geen tafel met code ${code}.`),'notfound');
    if(this.sec[id]&&this.sec[id]!==secret) return this.err(ws,L('That seat belongs to someone else.','Die plek is van iemand anders.'),'secret');
    let p=s.players.find(x=>x.id===id);
    if(!p){
      if(s.phase!=='lobby') return this.err(ws,L('That game has already started.','Dat spel is al begonnen.'),'started');
      const mx=deriveRules(s.rules).maxPlayers;
      if(s.players.length>=mx) return this.err(ws,L(`That table is full (${mx} players).`,`Die tafel is vol (${mx} spelers).`),'full');
      p={id,name,score:0,out:false}; s.players.push(p); s.v++;
    }
    this.sec[id]=secret; delete this.meta.away[id]; if(p.left){ delete p.left; }
    this.meta.acct=this.meta.acct||{};
    if(account){ this.meta.acct[id]={uid:account.uid,name:account.name}; p.name=account.name; p.acct=true; if(account.dev) p.dev=true; else delete p.dev; }
    else if(s.phase==='lobby'){ delete this.meta.acct[id]; delete p.acct; delete p.dev; }
    ws.serializeAttachment({id,lang:m.lang==='nl'?'nl':'en'});
    await this.save();
    this.sendTo(ws,{t:'chatlog',list:this.chat});
    this.broadcast(); await this.listing(); await this.schedule();
  }

  async chatMsg(ws,a,m){
    const t=clean(m.text,140); if(!t) return;
    const k=m.k==='r'?'r':'m';
    const p=this.s.players.find(x=>x.id===a.id); if(!p) return;
    const now=Date.now();
    if(this.meta.lastChat&&this.meta.lastChat[a.id]&&now-this.meta.lastChat[a.id]<400) return;
    (this.meta.lastChat=this.meta.lastChat||{})[a.id]=now;
    const msg={k,id:a.id,n:p.name,t,at:now,key:now.toString(36)+sid()}; if(p.dev) msg.dev=true;
    if(k==='m'){ this.chat.push(msg); if(this.chat.length>CHAT_KEEP) this.chat=this.chat.slice(-CHAT_KEEP); await this.save(); }
    for(const w of this.sockets()) if(this.att(w).id&&w.readyState===1) this.sendTo(w,{t:'chat',m:msg});
  }

  async action(ws,a,m){
    const s=this.s, id=a.id, me=s.players.find(p=>p.id===id), host=s.host===id;
    useRules(s);
    const fail=msg=>{ this.err(ws,msg); return true; };
    let err=null;
    switch(m.a){
      case 'throw': { if(!Array.isArray(m.cards)) return; const cs=m.cards.map(String).slice(0,12); err=doThrow(s,id,cs); if(!err) this.achThrow(id,cs); break; }
      case 'draw': { err=doDraw(s,id,m.src==='avail'?'avail':'deck',String(m.card||'')); if(!err){ const h=s.hands[id]; this.achDraw(id,h[h.length-1]); } break; }
      case 'balls': err=doBalls(s,id); break;
      case 'start': {
        if(!host||s.phase!=='lobby') return;
        if(s.players.length<2) err=L('You need at least 2 players.','Je hebt minstens 2 spelers nodig.');
        else if(notReady(s).length) err=L('Waiting for '+notReady(s).map(p=>p.name).join(', ')+' to ready up.','Wachten tot '+notReady(s).map(p=>p.name).join(', ')+' klaar is.');
        else { const cn=cardsNeeded(s.rules,s.players.length); if(cn.need>cn.have) err=L('Not enough cards for this many players.','Niet genoeg kaarten voor zoveel spelers.'); else { s.stats={}; s.history=[]; s.dealer=Math.floor(Math.random()*s.players.length); s.v_round=1; startRound(s);
          /* win/loss only counts on Standard rules with at least 2 people at the table */
          s.ranked=rankedRules(s.rules)&&this.humans().length>=2; this.meta.recorded=null; this.meta.achT={}; this.meta.achRes=null; } }
        break; }
      case 'addBot': {
        if(!host||s.phase!=='lobby') return;
        if(s.players.length>=deriveRules(s.rules).maxPlayers) return;
        const used=new Set(s.players.map(p=>p.name)); const n=BOT_NAMES.find(x=>!used.has(x))||'Bot';
        s.players.push({id:'b'+sid(),name:n,score:0,out:false,bot:true,lvl:BOT_LEVELS.includes(m.lvl)?m.lvl:'normal'}); break; }
      case 'kick': {
        if(!host||s.phase!=='lobby'||m.id===id) return;
        s.players=s.players.filter(p=>p.id!==m.id);
        for(const w of this.sockets()) if(this.att(w).id===m.id){ this.sendTo(w,{t:'gone',msg:L('The host removed you from the table.','De host heeft je van de tafel gehaald.')}); try{ w.close(1000,'removed'); }catch(e){} }
        delete this.sec[m.id]; break; }
      case 'botLvl': { if(!host||s.phase!=='lobby'||!BOT_LEVELS.includes(m.lvl)) return; const b=s.players.find(p=>p.id===m.id&&p.bot); if(b) b.lvl=m.lvl; break; }
      case 'rules': {
        if(!host||s.phase!=='lobby') return;
        const r=sanitizeRules(m.rules);
        if(s.players.length>deriveRules(r).maxPlayers) err=L('There are already more players than that.','Er zitten al meer spelers aan tafel.');
        else { s.rules=r; this.meta.sum=clean(m.sum,80); s.players.forEach(p=>{ if(p.id!==s.host) p.ready=false; }); }
        break; }
      case 'ready': { if(s.phase!=='lobby'||!me||host) return; me.ready=!!m.on; break; }
      case 'next': { if(s.phase!=='reveal'||!host) return; s.v_round=(s.v_round||0)+1; startRound(s); break; }
      case 'toLobby': { if(s.phase!=='over'||!me) return; this.toLobby(); break; }
      case 'leave': {
        if(!me) return;
        if(host) this.passHost();
        if(s.phase==='lobby'){ s.players=s.players.filter(p=>p.id!==id); delete this.sec[id]; }
        else { me.left=true; this.meta.away[id]=Date.now()-AWAY_PLAY_MS; }
        break; }
      default: return;
    }
    if(err) return fail(err);
    s.v=(s.v||0)+1; s.lastActAt=Date.now();
    if(!this.s.players.some(p=>!p.bot)){ return this.close(); }
    await this.record();
    await this.save(); this.broadcast(); await this.listing(); await this.schedule();
  }

  /* match over on Standard rules: 1st place is a win, everyone else a loss (leaving counts as a loss) */
  acctStub(){ return this.env.ACCOUNTS.get(this.env.ACCOUNTS.idFromName('accounts')); }
  /* ---- achievements: Standard rules on a server table, players with an account, only their own moves ---- */
  achOn(id){ const s=this.s; return !!(s&&rankedRules(s.rules)&&(this.meta.acct||{})[id]); }
  achT(id){ const s=this.s, all=this.meta.achT=this.meta.achT||{}; const t=all[id]=all[id]||{h69:0,lost:false}; if(t.round!==s.round){ t.round=s.round; t.jok=0; t.jack=false; } return t; }
  achGive(id,a){ if(!this.achOn(id)) return; (this.pend=this.pend||{})[id]=this.pend[id]||new Set(); this.pend[id].add(a); }
  achThrow(id,cards){
    if(!this.achOn(id)) return;
    const t=this.achT(id), by={}; for(const c of cards){ const r=rank(c); by[r]=(by[r]||0)+1; }
    const jok=by.X||0, jacks=by.J||0;
    if(Object.values(by).some(n=>n>=4)) this.achGive(id,'t4');
    if(jok>=3) this.achGive(id,'t3j');
    if(jacks>=1) this.achGive(id,'tj');
    if(jacks>=2) this.achGive(id,'t2j');
    t.jack=jacks>=1;
  }
  achDraw(id,c){
    if(!this.achOn(id)) return;
    const t=this.achT(id);
    if(c&&rank(c)==='X'){ t.jok++; this.achGive(id,'j1'); if(t.jok>=2) this.achGive(id,'j2'); if(t.jok>=4) this.achGive(id,'j4'); if(t.jack) this.achGive(id,'tjj'); }
    t.jack=false;
  }
  achRound(){
    const s=this.s, res=s&&s.result;
    if(!res||this.meta.achRes===res.id||!rankedRules(s.rules)) return;
    this.meta.achRes=res.id;
    const place=placings(s), alive=s.players.filter(p=>!p.out), worst=Math.max(0,...Object.values(place));
    if(this.achOn(res.caller)){
      if(res.falseB) this.achGive(res.caller,'oops');
      else if(res.winner===res.caller){ this.achGive(res.caller,'balls1'); if((s.turnsTaken||{})[res.caller]===1) this.achGive(res.caller,'quick'); }
    }
    for(const b of res.beaters||[]) this.achGive(b,'gotcha');
    for(const row of res.rows){
      if(!this.achOn(row.id)) continue;
      const t=this.achT(row.id), pre=row.before+row.gain;
      if(s.phase!=='over'&&alive.length>=3&&place[row.id]===worst) t.last=true;
      if(pre===69){ t.h69++; this.achGive(row.id,'a69'); if(t.h69>=2) this.achGive(row.id,'a69x2'); }
      if(pre===100) this.achGive(row.id,'a100');
      if(res.winner!==row.id) t.lost=true;
      else if(row.v<=0&&row.v>=-4) this.achGive(row.id,'w'+(-row.v));
    }
    if(s.phase==='over') for(const p of s.players){
      if(place[p.id]!==1||!this.achOn(p.id)) continue;
      const t=this.achT(p.id);
      this.achGive(p.id,'win1');
      if(!t.lost) this.achGive(p.id,'flawless');
      if(t.last) this.achGive(p.id,'comeback');
      if(p.score>=90) this.achGive(p.id,'survivor');
    }
  }
  async achFlush(){
    const pend=this.pend; this.pend=null; if(!pend) return;
    for(const [pid,set] of Object.entries(pend)){
      const a=(this.meta.acct||{})[pid]; if(!a||!set.size) continue;
      try{
        const r=await this.acctStub().fetch('https://acct/achieve',{method:'POST',body:JSON.stringify({uid:a.uid,name:a.name,ids:[...set]})});
        const {fresh,user}=await r.json();
        if(fresh&&fresh.length) for(const w of this.sockets()) if(this.att(w).id===pid) this.sendTo(w,{t:'ach',ids:fresh,user});
      }catch(e){}
    }
  }

  async record(){
    this.achRound(); await this.achFlush();
    const s=this.s;
    if(!s||s.phase!=='over'||!s.ranked||!s.result||this.meta.recorded===s.result.id) return;
    this.meta.recorded=s.result.id;
    const place=placings(s), acct=this.meta.acct||{}, results=[], byUid={};
    for(const p of s.players){ const a=acct[p.id]; if(p.bot||!a) continue; results.push({uid:a.uid,name:a.name,win:place[p.id]===1}); byUid[a.uid]=p.id; }
    if(!results.length) return;
    try{
      const r=await this.acctStub().fetch('https://acct/result',{method:'POST',body:JSON.stringify({results})});
      const {users,fresh}=await r.json();
      for(const [uid,user] of Object.entries(users||{})){ const pid=byUid[uid]; const win=results.find(x=>x.uid===uid).win;
        for(const w of this.sockets()) if(this.att(w).id===pid) this.sendTo(w,{t:'record',win,user,fresh:(fresh||{})[uid]||[]}); }
    }catch(e){}
  }

  /* back to the lobby: players who left during the match lose their seat */
  toLobby(){
    const s=this.s; resetToLobby(s);
    const gone=s.players.filter(p=>!p.bot&&(p.left||!this.online(p.id)));
    if(gone.some(p=>p.id===s.host)) this.passHost();
    s.players=s.players.filter(p=>p.bot||!(p.left)||p.id===s.host);
    for(const p of s.players) delete p.left;
    for(const id of Object.keys(this.sec)) if(!s.players.some(p=>p.id===id)) delete this.sec[id];
  }
  /* next person in seat order after the host; someone who is connected comes first */
  passHost(){
    const s=this.s; if(!s) return;
    const n=s.players.length, i=s.players.findIndex(p=>p.id===s.host), order=[];
    for(let k=1;k<=n;k++){ const p=s.players[((i<0?-1:i)+k+n)%n]; if(p&&!p.bot&&!p.left&&p.id!==s.host) order.push(p); }
    const next=order.find(p=>this.online(p.id))||order[0];
    if(next){ s.host=next.id; next.ready=false; }
  }

  async webSocketClose(ws){ await this.gone(ws); }
  async webSocketError(ws){ await this.gone(ws); }
  async gone(ws){
    await this.load(); if(!this.s) return;
    const a=this.att(ws); if(!a.id) return;
    if(!this.online(a.id,ws)){ this.meta.away[a.id]=Date.now(); await this.save(); await this.schedule(); }
  }

  /* ---- what the table has to do next, and when ---- */
  dueList(){
    const s=this.s, now=Date.now(), out=[];
    if(!s) return out;
    const R=deriveRules(s.rules), humans=this.humans();
    const anyOnline=humans.some(p=>this.online(p.id));
    if(!anyOnline){ const since=Math.max(0,...humans.map(p=>this.meta.away[p.id]||0)); out.push({at:(since||now)+EMPTY_CLOSE_MS,run:()=>'close'}); }
    if(s.phase==='lobby'){
      for(const p of humans){ const t=this.meta.away[p.id]; if(t&&!this.online(p.id)) out.push({at:t+AWAY_LOBBY_MS,run:()=>{ if(p.id===s.host){ this.passHost(); if(s.host===p.id) return false; } s.players=s.players.filter(x=>x.id!==p.id); delete this.sec[p.id]; delete this.meta.away[p.id]; return true; }}); }
    }
    const hp=s.players.find(p=>p.id===s.host);
    if(s.phase!=='lobby'&&hp&&!hp.bot&&!this.online(hp.id)&&this.meta.away[hp.id]&&humans.some(p=>p.id!==hp.id&&this.online(p.id)))
      out.push({at:this.meta.away[hp.id]+AWAY_PLAY_MS,run:()=>{ const was=s.host; this.passHost(); return s.host!==was; }});
    if(s.phase==='play'){
      const cur=s.players[s.turn];
      if(cur){
        const start=s.startAt||0, last=s.lastActAt||0, sp=(SPEED[R.speed]||SPEED.normal).bot;
        const stepDelay=(s.step==='throw'?1000:750)*sp;
        const away=!cur.bot&&(cur.left||(this.meta.away[cur.id]&&!this.online(cur.id)));
        if(cur.bot) out.push({at:Math.max(start,last+stepDelay),run:()=>this.botStep(cur.id,lvlOf(s,cur))});
        else if(away) out.push({at:Math.max(start,last+stepDelay,(this.meta.away[cur.id]||0)+AWAY_PLAY_MS),run:()=>this.botStep(cur.id,'normal')});
        else if(R.turnTimer) out.push({at:Math.max(start,s.turnAt||start)+R.turnTimer*1000+400,run:()=>this.timeoutStep(cur.id)});
      }
    }
    if(s.phase==='reveal'&&R.autoNext&&s.revealAt) out.push({at:s.revealAt+NEXT_ROUND_MS,run:()=>{ s.v_round=(s.v_round||0)+1; startRound(s); return true; }});
    if(s.phase==='over'&&s.overAt) out.push({at:s.overAt+LOBBY_AFTER_MS,run:()=>{ this.toLobby(); return true; }});
    return out;
  }
  botStep(id,lvl){
    const s=this.s;
    if(s.step==='throw'){
      if(botWantsBalls(s,id,lvl)) return !doBalls(s,id);
      const h=s.hands[id]; const stuck=(s.turnsTaken[id]||0)>25&&Math.random()<.3;
      return !doThrow(s,id,stuck?[h[Math.floor(Math.random()*h.length)]]:botThrowFor(s,id,lvl));
    }
    const [src,card]=botDraw(s,id,lvl); return !doDraw(s,id,src,card);
  }
  timeoutStep(id){
    const s=this.s, nm=(s.players.find(p=>p.id===id)||{}).name;
    if(s.step==='throw'&&doThrow(s,id,botThrow(s.hands[id]))) return false;
    if(doDraw(s,id,'deck')) return false;
    addLog(s,{t:'timeout',n:nm}); return true;
  }
  async alarm(){
    await this.load(); if(!this.s) return;
    let changed=false;
    for(let i=0;i<8;i++){
      const now=Date.now();
      const due=this.dueList().filter(d=>d.at<=now).sort((a,b)=>a.at-b.at)[0];
      if(!due) break;
      useRules(this.s);
      const r=due.run();
      if(r==='close') return this.close();
      if(!r) break;
      this.s.v=(this.s.v||0)+1; this.s.lastActAt=Date.now(); changed=true;
    }
    if(changed){ await this.record(); await this.save(); this.broadcast(); await this.listing(); }
    await this.schedule();
  }
  async schedule(){
    const next=this.dueList().sort((a,b)=>a.at-b.at)[0];
    if(next) await this.ctx.storage.setAlarm(Math.max(Date.now()+50,next.at)); else await this.ctx.storage.deleteAlarm();
  }
  async close(){
    try{ await this.unlist(); }catch(e){}
    for(const w of this.sockets()){ try{ w.close(1000,'closed'); }catch(e){} }
    await this.ctx.storage.deleteAlarm(); await this.ctx.storage.deleteAll();
    this.s=null; this.sec={}; this.chat=[]; this.meta={away:{},listed:null,code:this.meta.code};
  }

  /* ---- public table list ---- */
  lobbyStub(){ return this.env.LOBBY.get(this.env.LOBBY.idFromName('lobby')); }
  async listing(){
    const s=this.s; if(!s) return;
    const R=deriveRules(s.rules);
    if(s.phase==='lobby'&&R.pub){
      const host=s.players.find(p=>p.id===s.host);
      const info={n:host?host.name:'Host',p:s.players.length,m:R.maxPlayers,s:this.meta.sum||''};
      const sig=JSON.stringify(info);
      if(sig!==this.meta.listed){ this.meta.listed=sig; await this.save(); await this.lobbyStub().fetch('https://lobby/',{method:'POST',body:JSON.stringify({code:s.code,info})}); }
    } else if(this.meta.listed){ await this.unlist(); }
  }
  async unlist(){ const code=(this.s&&this.s.code)||this.meta.code; this.meta.listed=null; if(code) await this.lobbyStub().fetch('https://lobby/',{method:'POST',body:JSON.stringify({code,drop:true})}); }
}

function sanitizeRules(r){
  const d=DEFAULT_RULES, x={...d}; r=r&&typeof r==='object'?r:{};
  const num=(k,lo,hi)=>{ const v=Number(r[k]); if(Number.isFinite(v)&&v>=lo&&v<=hi) x[k]=Math.round(v); };
  num('startHand',3,8); num('decks',1,3); num('jokers',0,4); num('maxPlayers',2,8); num('callMax',0,15); num('falsePenalty',0,100);
  num('elimAt',20,500); num('jokerVal',-10,60); num('jackVal',-10,20); num('turnTimer',0,120);
  if(['relaxed','normal','fast'].includes(r.speed)) x.speed=r.speed;
  if(BOT_LEVELS.includes(r.botLevel)) x.botLevel=r.botLevel;
  x.autoNext=r.autoNext!==false; x.pub=!!r.pub;
  for(const k of ['resetA','resetB']){ const v=r[k]; if(v&&typeof v==='object'){ const f=Number(v.from), t=Number(v.to); if(Number.isFinite(f)&&Number.isFinite(t)) x[k]={on:!!v.on,from:Math.round(f),to:Math.round(t)}; } }
  return x;
}
