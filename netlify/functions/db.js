// LFX Academy — Secure DB proxy (Netlify Function)
// All privileged Supabase operations live here. The service key NEVER reaches the browser.
// Required environment variables (Netlify → Site settings → Environment variables):
//   SB_URL          = https://YOUR-PROJECT.supabase.co
//   SB_SERVICE_KEY  = (Supabase service_role key — ROTATE the old leaked one first!)
//   LFX_ADMIN_PASS  = (admin panel password)

const TABLES = ['subscribers', 'salespeople'];

const SUB_FIELDS = ['first_name','last_name','email','phone','ref_code','pay_method','status','date_str','proof_url'];
const SUB_STATUS = ['قيد التحقق','مدفوع'];

// أسعار الباقتين — مصدر الحقيقة الوحيد للمبلغ، السيرفر لا يثق بأي رقم يرسله المتصفح.
// عدّل هنا فقط لو تغيّرت الأسعار مستقبلاً — القيمة تنعكس تلقائياً في insert_subscriber و credit_sale.
const PACKAGE_PRICE = { 'LFX Foundation': 299, 'LFX Elite': 499 };
const DEFAULT_PRICE = 299; // احتياطي فقط لو ما قدرنا نحدد الباقة (لا يفترض يصير)

function detectPackage(text) {
  const t = String(text || '');
  if (t.includes('Elite')) return 'LFX Elite';
  if (t.includes('Foundation')) return 'LFX Foundation';
  return null;
}

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
        // المبلغ يُحدَّد من نوع الباقة المكتوب في pay_method (مثلاً "Ziina — LFX Elite")،
        // مو من رقم يرسله المتصفح — هذا يمنع أي تلاعب بالسعر من جهة العميل.
        const pkgName = detectPackage(row.pay_method) || 'LFX Foundation';
        row.amount = PACKAGE_PRICE[pkgName] || DEFAULT_PRICE;
        const r = await rest('subscribers', { method: 'POST', body: JSON.stringify(row), headers: { 'Prefer': 'return=minimal' } });
        return json(r.ok ? 200 : 502, { ok: r.ok });
      }

      case 'credit_sale': {
        const ref = String(req.ref || '').slice(0, 60);
        if (!ref || ref === 'مباشر') return json(200, { ok: true });
        const pkgName = detectPackage(req.pkg) || 'LFX Foundation';
        const amt = PACKAGE_PRICE[pkgName] || DEFAULT_PRICE;
        const sps = await getRows('salespeople', `ref_code=eq.${encodeURIComponent(ref)}&select=id,customers,revenue`);
        if (!sps[0]) return json(200, { ok: true });
        const r = await rest(`salespeople?id=eq.${encodeURIComponent(sps[0].id)}`, {
          method: 'PATCH',
          body: JSON.stringify({ customers: (sps[0].customers || 0) + 1, revenue: (sps[0].revenue || 0) + amt })
        });
        return json(r.ok ? 200 : 502, { ok: r.ok });
      }

      case 'sp_login': {
        const code = String(req.code || '').trim().toLowerCase().slice(0, 60);
        const pass = String(req.pass || '');
        if (!code || !pass) return json(401, { sp: null });
        const sps = await getRows('salespeople', `ref_code=eq.${encodeURIComponent(code)}`);
