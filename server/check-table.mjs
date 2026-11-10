// Opens a table on the live server, waits for the first state, then leaves. Used by the "Check game server" workflow.
const ws = new WebSocket('wss://balls-server.pelgrim32.workers.dev/api/table/QZXW');
const t = setTimeout(() => { console.log('TIMEOUT'); process.exit(1); }, 10000);
ws.onopen = () => { console.log('open'); ws.send(JSON.stringify({ t: 'hello', id: 'pCheck01', secret: 'checksecret1', name: 'Check', create: true, lang: 'en' })); };
ws.onmessage = e => {
  const m = JSON.parse(e.data);
  console.log('got', m.t, m.t === 'err' ? m.msg : (m.s ? m.s.phase : ''));
  if (m.t === 'state') { ws.send(JSON.stringify({ t: 'act', a: 'leave' })); clearTimeout(t); setTimeout(() => process.exit(0), 500); }
};
ws.onerror = e => console.log('error', e.message || e.type);
ws.onclose = e => console.log('closed', e.code, e.reason);
