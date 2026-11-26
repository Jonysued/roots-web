// ROOTS · acceso privado con usuario y contraseña (Vercel Routing Middleware)
// Credenciales en variables de entorno del proyecto: ROOTS_USER, ROOTS_PASS, ROOTS_SECRET
export const config = { matcher: ['/((?!favicon\.ico|favicon-32\.png|apple-touch-icon\.png|icon-192\.png).*)'] };

const COOKIE = 'roots_auth';
const enc = new TextEncoder();

async function sign(value, secret) {
  const key = await crypto.subtle.importKey('raw', enc.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const sig = await crypto.subtle.sign('HMAC', key, enc.encode(value));
  return Array.from(new Uint8Array(sig)).map(b => b.toString(16).padStart(2, '0')).join('');
}
function safeEq(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string' || a.length !== b.length) return false;
  let r = 0; for (let i = 0; i < a.length; i++) r |= a.charCodeAt(i) ^ b.charCodeAt(i); return r === 0;
}
function getCookie(req, name) {
  const c = req.headers.get('cookie') || '';
  const m = c.match(new RegExp('(?:^|;\\s*)' + name + '=([^;]+)'));
  return m ? decodeURIComponent(m[1]) : null;
}
const redirect = (url, req, headers = {}) => new Response(null, { status: 303, headers: { Location: new URL(url, req.url).toString(), 'Cache-Control': 'no-store', ...headers } });

export default async function middleware(req) {
  const url = new URL(req.url);
  const USER = process.env.ROOTS_USER, PASS = process.env.ROOTS_PASS, SECRET = process.env.ROOTS_SECRET;
  const configured = !!(USER && PASS && SECRET);
  const token = configured ? await sign('ok:' + USER + ':' + PASS, SECRET) : null;

  if (url.pathname === '/login' && req.method === 'POST') {
    if (!configured) return redirect('/login.html?e=cfg', req);
    const form = await req.formData();
    const u = String(form.get('user') || ''), p = String(form.get('pass') || '');
    const given = await sign('ok:' + u + ':' + p, SECRET);
    if (!safeEq(given, token)) return redirect('/login.html?e=1', req);
    return redirect('/', req, { 'Set-Cookie': `${COOKIE}=${token}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${60 * 60 * 24 * 30}` });
  }
  if (url.pathname === '/logout') {
    return redirect('/login.html', req, { 'Set-Cookie': `${COOKIE}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0` });
  }
  if (url.pathname === '/login' ) return redirect('/login.html' + url.search, req);
  if (url.pathname === '/login.html') return; // la pantalla de ingreso es pública

  const c = getCookie(req, COOKIE);
  if (configured && c && safeEq(c, token)) return; // acceso concedido: sigue a la web
  return redirect('/login.html', req);
}
