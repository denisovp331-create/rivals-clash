const SESSION_TTL_SECONDS = 60 * 60 * 8;
const PBKDF2_ITERATIONS = 310000;

const RESOURCES = {
  teams: { table: "teams", fields: ["name", "captain", "description"] },
  players: { table: "players", fields: ["roblox_name", "team_id", "role", "notes"] },
  news: { table: "news", fields: ["title", "body", "published"] },
  tournaments: { table: "tournaments", fields: ["name", "status"] },
  matches: { table: "matches", fields: ["tournament_id", "round_name", "team_a_id", "team_b_id", "score_a", "score_b", "status", "played_at"] },
  applications: { table: "applications", fields: ["tournament_id", "team_name", "captain_name", "contact", "roster_json", "status"] }
};

function json(data, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store", ...extraHeaders }
  });
}
function b64url(bytes) {
  let binary = "";
  for (const b of new Uint8Array(bytes)) binary += String.fromCharCode(b);
  return btoa(binary).replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
}
function fromB64url(s) {
  const b64 = s.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - s.length % 4) % 4);
  const bin = atob(b64);
  return Uint8Array.from(bin, c => c.charCodeAt(0));
}
async function hmac(secret, message) {
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign", "verify"]);
  return new Uint8Array(await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(message)));
}
async function makeSession(username, secret) {
  const payload = b64url(new TextEncoder().encode(JSON.stringify({ sub: username, exp: Math.floor(Date.now() / 1000) + SESSION_TTL_SECONDS })));
  const signature = b64url(await hmac(secret, payload));
  return payload + "." + signature;
}
async function readSession(token, secret) {
  if (!token || !token.includes(".")) return null;
  const [payload, signature] = token.split(".");
  if (!payload || !signature) return null;
  const expected = b64url(await hmac(secret, payload));
  if (signature.length !== expected.length) return null;
  let diff = 0;
  for (let i = 0; i < signature.length; i++) diff |= signature.charCodeAt(i) ^ expected.charCodeAt(i);
  if (diff !== 0) return null;
  try {
    const data = JSON.parse(new TextDecoder().decode(fromB64url(payload)));
    if (!data.sub || !data.exp || data.exp < Math.floor(Date.now() / 1000)) return null;
    return data;
  } catch { return null; }
}
function cookieValue(request, name) {
  const cookies = request.headers.get("Cookie") || "";
  const match = cookies.split(";").map(v => v.trim()).find(v => v.startsWith(name + "="));
  return match ? decodeURIComponent(match.slice(name.length + 1)) : "";
}
function cleanText(value, max = 5000) {
  return typeof value === "string" ? value.trim().slice(0, max) : "";
}
function corsHeaders(origin, env) {
  const allowed = env.ALLOWED_ORIGIN || "https://denisovp331-create.github.io";
  if (origin !== allowed) return {};
  return { "access-control-allow-origin": origin, "access-control-allow-credentials": "true", "vary": "Origin" };
}
export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const origin = request.headers.get("Origin") || "";
    const cors = corsHeaders(origin, env);
    if (request.method === "OPTIONS") {
      if (!cors["access-control-allow-origin"]) return new Response(null, { status: 403 });
      return new Response(null, { status: 204, headers: { ...cors, "access-control-allow-methods": "GET,POST,PUT,DELETE,OPTIONS", "access-control-allow-headers": "Content-Type", "access-control-max-age": "86400" } });
    }
    if (origin && !cors["access-control-allow-origin"]) return json({ error: "Origin not allowed" }, 403);
    const reply = (data, status = 200, headers = {}) => json(data, status, { ...cors, ...headers });
    if (url.pathname === "/api/health" && request.method === "GET") return reply({ ok: true, service: "rivals-clash-api" });

    if (!env.DB || !env.ADMIN_USERNAME || !env.ADMIN_PASSWORD_HASH || !env.SESSION_SECRET) {
      return reply({ error: "Server is not configured. Set DB binding and required secrets." }, 503);
    }

    if (url.pathname === "/api/login" && request.method === "POST") {
      let body;
      try { body = await request.json(); } catch { return reply({ error: "Invalid JSON" }, 400); }
      const username = cleanText(body.username, 100);
      const password = typeof body.password === "string" ? body.password : "";
      if (username !== env.ADMIN_USERNAME || !(await verifyPassword(password, env.ADMIN_PASSWORD_HASH))) {
        await env.DB.prepare("INSERT INTO audit_log(actor, action, resource_type, resource_id) VALUES (?, ?, ?, ?)")
          .bind(username || "unknown", "login_failed", "auth", null).run().catch(() => {});
        return reply({ error: "Неверный логин или пароль" }, 401);
      }
      const token = await makeSession(username, env.SESSION_SECRET);
      await env.DB.prepare("INSERT INTO audit_log(actor, action, resource_type, resource_id) VALUES (?, ?, ?, ?)")
        .bind(username, "login_success", "auth", null).run().catch(() => {});
      return reply({ ok: true, username }, 200, { "set-cookie": "rc_session=" + encodeURIComponent(token) + "; Path=/; Max-Age=" + SESSION_TTL_SECONDS + "; HttpOnly; Secure; SameSite=Strict" });
    }
    if (url.pathname === "/api/logout" && request.method === "POST") {
      return reply({ ok: true }, 200, { "set-cookie": "rc_session=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Strict" });
    }

    const session = await readSession(cookieValue(request, "rc_session"), env.SESSION_SECRET);
    if (!session) return reply({ error: "Требуется вход в админ-панель" }, 401);

    if (url.pathname === "/api/me" && request.method === "GET") return reply({ ok: true, username: session.sub });
    if (url.pathname === "/api/stats" && request.method === "GET") {
      const counts = await Promise.all(Object.entries(RESOURCES).map(async ([key, cfg]) => {
        const result = await env.DB.prepare("SELECT COUNT(*) AS total FROM " + cfg.table).first();
        return [key, result?.total ?? 0];
      }));
      return reply({ counts: Object.fromEntries(counts) });
    }

    const parts = url.pathname.match(/^\/api\/([a-z]+)(?:\/(\d+))?$/);
    if (!parts || !RESOURCES[parts[1]]) return reply({ error: "Not found" }, 404);
    const resource = parts[1];
    const id = parts[2] ? Number(parts[2]) : null;
    const cfg = RESOURCES[resource];

    if (request.method === "GET") {
      if (id) {
        const item = await env.DB.prepare("SELECT * FROM " + cfg.table + " WHERE id = ?").bind(id).first();
        return item ? reply(item) : reply({ error: "Not found" }, 404);
      }
      const result = await env.DB.prepare("SELECT * FROM " + cfg.table + " ORDER BY id DESC LIMIT 500").all();
      return reply(result.results || []);
    }
    if (!["POST", "PUT", "DELETE"].includes(request.method)) return reply({ error: "Method not allowed" }, 405);

    if (request.method === "DELETE") {
      if (!id) return reply({ error: "ID required" }, 400);
      const result = await env.DB.prepare("DELETE FROM " + cfg.table + " WHERE id = ?").bind(id).run();
      await audit(env, session.sub, "delete", resource, id);
      return reply({ ok: true, changes: result.meta?.changes ?? 0 });
    }

    let body;
    try { body = await request.json(); } catch { return reply({ error: "Invalid JSON" }, 400); }
    const fields = cfg.fields.filter(field => Object.prototype.hasOwnProperty.call(body, field));
    if (!fields.length) return reply({ error: "No valid fields provided" }, 400);
    const values = fields.map(field => {
      const value = body[field];
      if (["team_id", "tournament_id", "team_a_id", "team_b_id", "score_a", "score_b", "published"].includes(field)) {
        if (value === null || value === "") return null;
        const n = Number(value);
        return Number.isFinite(n) ? n : null;
      }
      return typeof value === "string" ? value.trim().slice(0, field === "body" || field === "description" || field === "notes" ? 10000 : 1000) : "";
    });
    if (request.method === "POST") {
      const placeholders = fields.map(() => "?").join(", ");
      const result = await env.DB.prepare("INSERT INTO " + cfg.table + " (" + fields.join(", ") + ") VALUES (" + placeholders + ")").bind(...values).run();
      await audit(env, session.sub, "create", resource, result.meta?.last_row_id);
      return reply({ ok: true, id: result.meta?.last_row_id }, 201);
    }
    if (!id) return reply({ error: "ID required" }, 400);
    const assignments = fields.map(field => field + " = ?").join(", ");
    await env.DB.prepare("UPDATE " + cfg.table + " SET " + assignments + " WHERE id = ?").bind(...values, id).run();
    await audit(env, session.sub, "update", resource, id);
    return reply({ ok: true, id });
  }
};

async function verifyPassword(password, stored) {
  // Format: PBKDF2$iterations$salt_base64url$hash_base64url
  const parts = String(stored).split("$");
  if (parts.length !== 4 || parts[0] !== "PBKDF2") return false;
  const iterations = Number(parts[1]);
  if (!Number.isInteger(iterations) || iterations < 100000 || iterations > 1000000) return false;
  try {
    const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(password), "PBKDF2", false, ["deriveBits"]);
    const derived = new Uint8Array(await crypto.subtle.deriveBits({ name: "PBKDF2", salt: fromB64url(parts[2]), iterations, hash: "SHA-256" }, key, 256));
    const expected = fromB64url(parts[3]);
    if (derived.length !== expected.length) return false;
    let diff = 0;
    for (let i = 0; i < derived.length; i++) diff |= derived[i] ^ expected[i];
    return diff === 0;
  } catch { return false; }
}
async function audit(env, actor, action, type, id) {
  await env.DB.prepare("INSERT INTO audit_log(actor, action, resource_type, resource_id) VALUES (?, ?, ?, ?)")
    .bind(actor, action, type, id == null ? null : String(id)).run().catch(() => {});
}
