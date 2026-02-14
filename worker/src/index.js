/**
 * Cloudflare Worker — Linear API Proxy with Auth
 *
 * Forwards GraphQL requests to Linear's API with the secret key
 * injected server-side. All requests require a valid JWT.
 *
 * Routes:
 *   POST /auth   — exchange password for a JWT
 *   POST /        — proxy GraphQL to Linear (requires JWT)
 *
 * Secrets (set via `wrangler secret put`):
 *   LINEAR_API_KEY      – your Linear personal API key (lin_api_…)
 *   DASHBOARD_PASSWORD  – the password users enter to log in
 *   AUTH_SECRET          – random string used to sign JWTs (e.g. openssl rand -hex 32)
 *
 * Environment vars (wrangler.toml [vars]):
 *   ALLOWED_ORIGIN  – the origin allowed to call this worker
 */

const LINEAR_GQL = "https://api.linear.app/graphql";
const JWT_EXPIRY_SECONDS = 7 * 24 * 60 * 60; // 7 days

// ── JWT helpers (Web Crypto HMAC-SHA256, zero deps) ──

function base64url(data) {
  if (typeof data === "string") {
    data = new TextEncoder().encode(data);
  }
  return btoa(String.fromCharCode(...new Uint8Array(data)))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

function base64urlDecode(str) {
  str = str.replace(/-/g, "+").replace(/_/g, "/");
  while (str.length % 4) str += "=";
  return Uint8Array.from(atob(str), (c) => c.charCodeAt(0));
}

async function getSigningKey(secret) {
  return crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign", "verify"],
  );
}

async function createJWT(payload, secret) {
  const header = base64url(JSON.stringify({ alg: "HS256", typ: "JWT" }));
  const body = base64url(JSON.stringify(payload));
  const key = await getSigningKey(secret);
  const sig = await crypto.subtle.sign(
    "HMAC",
    key,
    new TextEncoder().encode(`${header}.${body}`),
  );
  return `${header}.${body}.${base64url(sig)}`;
}

async function verifyJWT(token, secret) {
  const parts = token.split(".");
  if (parts.length !== 3) return null;
  const [header, body, sig] = parts;
  const key = await getSigningKey(secret);
  const valid = await crypto.subtle.verify(
    "HMAC",
    key,
    base64urlDecode(sig),
    new TextEncoder().encode(`${header}.${body}`),
  );
  if (!valid) return null;
  const payload = JSON.parse(
    new TextDecoder().decode(base64urlDecode(body)),
  );
  if (payload.exp && payload.exp < Math.floor(Date.now() / 1000)) return null;
  return payload;
}

// ── Shared helpers ──

function corsHeaders(env) {
  return {
    "Access-Control-Allow-Origin": env.ALLOWED_ORIGIN || "*",
    "Access-Control-Allow-Methods": "POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization",
    "Access-Control-Max-Age": "86400",
  };
}

function jsonResponse(data, status, env) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json", ...corsHeaders(env) },
  });
}

function jsonError(message, status, env) {
  return jsonResponse({ error: message }, status, env);
}

/** Extract and verify the Bearer token from the request */
async function authenticate(request, env) {
  const authHeader = request.headers.get("Authorization") || "";
  const match = authHeader.match(/^Bearer\s+(.+)$/i);
  if (!match) return null;
  return verifyJWT(match[1], env.AUTH_SECRET);
}

// ── Route handlers ──

async function handleAuth(request, env) {
  let body;
  try {
    body = await request.json();
  } catch {
    return jsonError("Invalid JSON body", 400, env);
  }

  if (!body.password || typeof body.password !== "string") {
    return jsonError("Missing password", 400, env);
  }

  if (!env.DASHBOARD_PASSWORD || !env.AUTH_SECRET) {
    return jsonError("Worker misconfigured: auth secrets not set", 500, env);
  }

  if (body.password !== env.DASHBOARD_PASSWORD) {
    return jsonError("Invalid password", 401, env);
  }

  const now = Math.floor(Date.now() / 1000);
  const token = await createJWT(
    { sub: "dashboard", iat: now, exp: now + JWT_EXPIRY_SECONDS },
    env.AUTH_SECRET,
  );

  return jsonResponse({ token }, 200, env);
}

async function handleProxy(request, env) {
  // ── Auth check ──
  const claims = await authenticate(request, env);
  if (!claims) {
    return jsonError("Unauthorized", 401, env);
  }

  // ── Ensure Linear key is configured ──
  if (!env.LINEAR_API_KEY) {
    return jsonError("Worker misconfigured: LINEAR_API_KEY secret not set", 500, env);
  }

  // ── Parse & validate body ──
  let body;
  try {
    body = await request.json();
  } catch {
    return jsonError("Invalid JSON body", 400, env);
  }

  if (!body.query || typeof body.query !== "string") {
    return jsonError("Missing or invalid 'query' field", 400, env);
  }

  // ── Proxy to Linear ──
  const linearRes = await fetch(LINEAR_GQL, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: env.LINEAR_API_KEY,
    },
    body: JSON.stringify({ query: body.query, variables: body.variables }),
  });

  const data = await linearRes.text();

  return new Response(data, {
    status: linearRes.status,
    headers: {
      "Content-Type": "application/json",
      ...corsHeaders(env),
    },
  });
}

// ── Main router ──

export default {
  async fetch(request, env) {
    // ── CORS preflight ──
    if (request.method === "OPTIONS") {
      return new Response(null, { status: 204, headers: corsHeaders(env) });
    }

    // ── Only POST allowed ──
    if (request.method !== "POST") {
      return jsonError("Method not allowed", 405, env);
    }

    // ── Origin check ──
    const origin = request.headers.get("Origin");
    if (env.ALLOWED_ORIGIN && origin !== env.ALLOWED_ORIGIN) {
      return jsonError("Forbidden", 403, env);
    }

    // ── Routing ──
    const url = new URL(request.url);

    if (url.pathname === "/auth") {
      return handleAuth(request, env);
    }

    // Default: Linear proxy (everything else goes here)
    return handleProxy(request, env);
  },
};
