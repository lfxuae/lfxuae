// LFX Academy — Secure DB proxy (Netlify Function)
// All privileged Supabase operations live here. The service key NEVER reaches the browser.
// Required environment variables (Netlify → Site settings → Environment variables):
//   SB_URL          = https://YOUR-PROJECT.supabase.co
//   SB_SERVICE_KEY  = (Supabase service_role key — ROTATE the old leaked one first!)
//   LFX_ADMIN_PASS  = (admin panel password)

const TABLES = ['subscribers', 'salespeople'];

const SUB_FIELDS = ['first_name','last_name','email','phone','ref_code','pay_method','status','date_str','proof_url'];
const SUB_STATUS = ['قيد التحقق','مدفوع'];

exports.handler = async (event) => {
  const json = (code, body) => ({
    statusCode: code,
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body)
  });

  if (event.httpMethod !== 'POST') return json(405, { error: 'POST only' });

  const SB_URL  = process.env.SB_URL;
  const SB_KEY  = process.env.SB_SERVICE_KEY;
  const ADMIN   = process.env.LFX_ADMIN_PASS;
  if (!SB_URL || !SB_KEY || !ADMIN) return json(500, { error: 'Server not configured' });

  let req;
  try { req = JSON.parse(event.body || '{}'); } catch { return json(400, { error: 'Bad JSON' }); }
  const { op } = req;

  const adminKey = event.headers['x-lfx-admin'] || event.headers['X-Lfx-Admin'] || '';
  const isAdmin  = !!adminKey && adminKey === ADMIN;

  // supports both new secret keys (sb_secret_...) and legacy JWT service_role keys
  const isNewKey = SB_KEY.startsWith('sb_secret');
  const H = isNewKey
    ? { 'apikey': SB_KEY, 'Content-Type': 'application/json' }
    : { 'apikey': SB_KEY, 'Authorization': 'Bearer ' + SB_KEY, 'Content-Type': 'application/json' };
  const rest = (path, opts = {}) => fetch(`${SB_URL}/rest/v1/${path}`, { ...opts, headers: { ...H, ...(opts.headers || {}) } });

  const getRows = async (table, params) => {
    const r = await rest(`${table}?${params}`);
    if (!r.ok) throw new Error('db ' + r.status);
    return r.json();
  };

  const sanitizeSP = (sp) => { if (!sp) return null; const { password, ...rest2 } = sp; return rest2; };

  try {
    switch (op) {

      /* ───────── PUBLIC OPS ───────── */

      case 'insert_subscriber': {
        const d = req.data || {};
        const row = {};
        for (const f of SUB_FIELDS) if (d[f] !== undefined) row[f] = String(d[f]).slice(0, 300);
        if (!SUB_STATUS.includes(row.status)) row.status = 'قيد التحقق';
        row.amount = 200; // never trust the client with the price
        const r = await rest('subscribers', { method: 'POST', body: JSON.stringify(row), headers: { 'Prefer': 'return=minimal' } });
        return json(r.ok ? 200 : 502, { ok: r.ok });
      }

      case 'credit_sale': {
        const ref = String(req.ref || '').slice(0, 60);
        if (!ref || ref === 'مباشر') return json(200, { ok: true });
        const sps = await getRows('salespeople', `ref_code=eq.${encodeURIComponent(ref)}&select=id,customers,revenue`);
        if (!sps[0]) return json(200, { ok: true });
        const r = await rest(`salespeople?id=eq.${encodeURIComponent(sps[0].id)}`, {
          method: 'PATCH',
          body: JSON.stringify({ customers: (sps[0].customers || 0) + 1, revenue: (sps[0].revenue || 0) + 200 })
        });
        return json(r.ok ? 200 : 502, { ok: r.ok });
      }

      case 'sp_login': {
        const code = String(req.code || '').trim().toLowerCase().slice(0, 60);
        const pass = String(req.pass || '');
        if (!code || !pass) return json(401, { sp: null });
        const sps = await getRows('salespeople', `ref_code=eq.${encodeURIComponent(code)}`);
        const sp = sps[0];
        if (!sp || sp.password !== pass) return json(401, { sp: null });
        return json(200, { sp: sanitizeSP(sp) });
      }

      case 'sp_dashboard': {
        const code = String(req.code || '').trim().toLowerCase().slice(0, 60);
        if (!code) return json(400, { error: 'no code' });
        const sps = await getRows('salespeople', `ref_code=eq.${encodeURIComponent(code)}`);
        const sp = sps[0];
        if (!sp) return json(404, { error: 'not found' });
        const authed = isAdmin || (req.pass && sp.password === req.pass);
        if (!authed) return json(401, { error: 'unauthorized' });
        const [subs, allPaid] = await Promise.all([
          getRows('subscribers', `ref_code=eq.${encodeURIComponent(code)}&order=created_at.desc`),
          getRows('subscribers', 'select=id&status=eq.' + encodeURIComponent('مدفوع'))
        ]);
        return json(200, { sp: sanitizeSP(sp), subs, totalPaid: allPaid.length });
      }

      case 'upload_proof': {
        const name = String(req.fileName || '').replace(/[^a-zA-Z0-9._-]/g, '').slice(0, 120);
        const type = String(req.contentType || 'image/jpeg');
        const b64  = String(req.dataBase64 || '');
        if (!name || !b64) return json(400, { error: 'missing file' });
        if (b64.length > 4.8e6) return json(413, { error: 'file too large' });
        const buf = Buffer.from(b64, 'base64');
        const r = await fetch(`${SB_URL}/storage/v1/object/proofs/${name}`, {
          method: 'POST',
          headers: isNewKey ? { 'apikey': SB_KEY, 'Content-Type': type } : { 'apikey': SB_KEY, 'Authorization': 'Bearer ' + SB_KEY, 'Content-Type': type },
          body: buf
        });
        if (!r.ok) return json(502, { error: 'upload failed' });
        return json(200, { url: `${SB_URL}/storage/v1/object/public/proofs/${name}` });
      }

      /* ───────── ADMIN OPS (require x-lfx-admin header) ───────── */

      case 'admin_login':
        return isAdmin ? json(200, { ok: true }) : json(401, { ok: false });

      case 'admin_get': {
        if (!isAdmin) return json(401, { error: 'unauthorized' });
        const table = String(req.table || '');
        if (!TABLES.includes(table)) return json(400, { error: 'bad table' });
        const rows = await getRows(table, String(req.params || ''));
        return json(200, { rows });
      }

      case 'admin_insert': {
        if (!isAdmin) return json(401, { error: 'unauthorized' });
        const table = String(req.table || '');
        if (!TABLES.includes(table)) return json(400, { error: 'bad table' });
        const r = await rest(table, { method: 'POST', body: JSON.stringify(req.data || {}), headers: { 'Prefer': 'return=minimal' } });
        return json(r.ok ? 200 : 502, { ok: r.ok });
      }

      case 'admin_update': {
        if (!isAdmin) return json(401, { error: 'unauthorized' });
        const table = String(req.table || '');
        if (!TABLES.includes(table)) return json(400, { error: 'bad table' });
        const r = await rest(`${table}?id=eq.${encodeURIComponent(req.id)}`, { method: 'PATCH', body: JSON.stringify(req.data || {}) });
        return json(r.ok ? 200 : 502, { ok: r.ok });
      }

      case 'admin_delete': {
        if (!isAdmin) return json(401, { error: 'unauthorized' });
        const table = String(req.table || '');
        if (!TABLES.includes(table)) return json(400, { error: 'bad table' });
        const r = await rest(`${table}?id=eq.${encodeURIComponent(req.id)}`, { method: 'DELETE' });
        return json(r.ok ? 200 : 502, { ok: r.ok });
      }

      default:
        return json(400, { error: 'unknown op' });
    }
  } catch (e) {
    console.error('db function error:', e);
    return json(500, { error: 'server error' });
  }
};
