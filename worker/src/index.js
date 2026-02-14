/**
 * Cloudflare Worker — Linear API Proxy
 *
 * Forwards GraphQL requests to Linear's API with the secret key
 * injected server-side. The browser never sees the key.
 *
 * Secrets (set via `wrangler secret put`):
 *   LINEAR_API_KEY  – your Linear personal API key (lin_api_…)
 *
 * Environment vars (wrangler.toml [vars]):
 *   ALLOWED_ORIGIN  – the origin allowed to call this worker
 */

const LINEAR_GQL = "https://api.linear.app/graphql";

function corsHeaders(env) {
  return {
    "Access-Control-Allow-Origin": env.ALLOWED_ORIGIN || "*",
    "Access-Control-Allow-Methods": "POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type",
    "Access-Control-Max-Age": "86400",
  };
}

function jsonError(message, status, env) {
  return new Response(JSON.stringify({ error: message }), {
    status,
    headers: { "Content-Type": "application/json", ...corsHeaders(env) },
  });
}

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

    // ── Origin check (defense-in-depth on top of CORS) ──
    const origin = request.headers.get("Origin");
    if (env.ALLOWED_ORIGIN && origin !== env.ALLOWED_ORIGIN) {
      return jsonError("Forbidden", 403, env);
    }

    // ── Ensure the secret is configured ──
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
  },
};
