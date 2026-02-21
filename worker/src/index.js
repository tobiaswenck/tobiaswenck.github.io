/**
 * Cloudflare Worker — Linear API Proxy with Auth
 *
 * Forwards GraphQL requests to Linear's API with the secret key
 * injected server-side. All requests require a valid JWT.
 *
 * Routes:
 *   POST /auth          — exchange password for a JWT
 *   POST /              — proxy GraphQL to Linear (requires JWT)
 *   POST /youtrack      — proxy issue queries to YouTrack REST API (requires JWT)
 *   POST /gitlab        — proxy merge request queries to GitLab REST API (requires JWT)
 *   POST /gitlab/file   — fetch raw file from GitLab repo (requires JWT)
 *   POST /gitlab/projects — list projects (for discovering project IDs) (requires JWT)
 *   POST /npm-versions  — batch fetch latest versions from npm registry (requires JWT)
 *
 * Secrets (set via `wrangler secret put`):
 *   LINEAR_API_KEY      – your Linear personal API key (lin_api_…)
 *   YOUTRACK_TOKEN      – YouTrack permanent token for REST API
 *   GITLAB_TOKEN        – GitLab personal access token with read_api scope
 *   DASHBOARD_PASSWORD  – the password users enter to log in
 *   AUTH_SECRET          – random string used to sign JWTs (e.g. openssl rand -hex 32)
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

// ── Query allowlist ──
// Only these root fields may be queried. Mutations, subscriptions,
// and introspection are blocked so the proxy can't be abused as a
// full-access GraphQL gateway.

const ALLOWED_ROOT_FIELDS = new Set(["viewer", "projects"]);

function isQueryAllowed(query) {
  const normalized = query.replace(/\s+/g, " ").trim();
  const lower = normalized.toLowerCase();

  // Block mutations and subscriptions
  if (/^(mutation|subscription)\b/.test(lower)) return false;

  // Block introspection anywhere in the query
  if (/__schema\b/.test(lower) || /__type\b/.test(lower)) return false;

  // Strip optional `query OperationName(…)` prefix to get to the selection set
  let body = normalized;
  const queryPrefix = body.match(/^query\s+\w*\s*(\([^)]*\)\s*)?/i);
  if (queryPrefix) {
    body = body.slice(queryPrefix[0].length);
  }

  // Must start with `{`
  if (!body.startsWith("{")) return false;

  // Extract all top-level field names from the selection set.
  // We walk character-by-character and track brace depth to only
  // capture identifiers at depth === 1 (the root fields).
  // Parentheses are also tracked so that GraphQL arguments like
  // `projects(first: 50, ...)` don't get misread as root fields.
  const rootFields = [];
  let depth = 0;
  let parenDepth = 0;
  let i = 0;
  while (i < body.length) {
    const ch = body[i];
    if (ch === "(") {
      parenDepth++;
      i++;
    } else if (ch === ")") {
      parenDepth--;
      i++;
    } else if (ch === "{") {
      depth++;
      i++;
    } else if (ch === "}") {
      depth--;
      i++;
    } else if (depth === 1 && parenDepth === 0) {
      // Try to match a field name (optionally preceded by alias: )
      const slice = body.slice(i);
      const fieldMatch = slice.match(/^(\w+)\s*:/);
      if (fieldMatch) {
        // This could be an alias — the real field name follows the colon
        i += fieldMatch[0].length;
        const afterColon = body.slice(i).match(/^\s*(\w+)/);
        if (afterColon) {
          rootFields.push(afterColon[1].toLowerCase());
          i += afterColon[0].length;
        }
      } else {
        const nameMatch = slice.match(/^(\w+)/);
        if (nameMatch) {
          rootFields.push(nameMatch[1].toLowerCase());
          i += nameMatch[0].length;
        } else {
          i++;
        }
      }
    } else {
      i++;
    }
  }

  // Reject if no root fields found or any root field is not in the allowlist
  if (rootFields.length === 0) return false;
  return rootFields.every((f) => ALLOWED_ROOT_FIELDS.has(f));
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

  // ── Query allowlist ──
  if (!isQueryAllowed(body.query)) {
    return jsonError("Query not allowed", 403, env);
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

// ── YouTrack proxy ──

async function handleYouTrack(request, env) {
  // ── Auth check ──
  const claims = await authenticate(request, env);
  if (!claims) {
    return jsonError("Unauthorized", 401, env);
  }

  // ── Ensure YouTrack token is configured ──
  if (!env.YOUTRACK_TOKEN) {
    return jsonError("Worker misconfigured: YOUTRACK_TOKEN secret not set", 500, env);
  }

  // ── Parse body ──
  let body;
  try {
    body = await request.json();
  } catch {
    return jsonError("Invalid JSON body", 400, env);
  }

  if (!body.query || typeof body.query !== "string") {
    return jsonError("Missing or invalid 'query' field", 400, env);
  }

  // ── Build YouTrack REST API URL ──
  const ytUrl = new URL("https://edith.youtrack.cloud/api/issues");
  ytUrl.searchParams.set("query", body.query);
  ytUrl.searchParams.set("$top", body.top || "20");
  ytUrl.searchParams.set(
    "fields",
    "idReadable,summary,project(shortName),created,resolved,customFields(name,$type,value(name,color(background)))",
  );

  const ytRes = await fetch(ytUrl.toString(), {
    headers: {
      Accept: "application/json",
      Authorization: `Bearer ${env.YOUTRACK_TOKEN}`,
      "Cache-Control": "no-cache",
    },
  });

  const data = await ytRes.text();

  return new Response(data, {
    status: ytRes.status,
    headers: {
      "Content-Type": "application/json",
      ...corsHeaders(env),
    },
  });
}

// ── GitLab proxy ──

const GITLAB_BASE = "https://gitlab.dev.edith-bahn.de";

async function handleGitLab(request, env) {
  // ── Auth check ──
  const claims = await authenticate(request, env);
  if (!claims) {
    return jsonError("Unauthorized", 401, env);
  }

  // ── Ensure GitLab token is configured ──
  if (!env.GITLAB_TOKEN) {
    return jsonError(
      "Worker misconfigured: GITLAB_TOKEN secret not set",
      500,
      env,
    );
  }

  // ── Build GitLab REST API URL ──
  // Fetch open, non-draft MRs where the token owner is a reviewer
  const glUrl = new URL(`${GITLAB_BASE}/api/v4/merge_requests`);
  glUrl.searchParams.set("scope", "reviews_for_me");
  glUrl.searchParams.set("state", "opened");
  glUrl.searchParams.set("per_page", "25");
  glUrl.searchParams.set("order_by", "updated_at");

  const glRes = await fetch(glUrl.toString(), {
    headers: {
      Accept: "application/json",
      "PRIVATE-TOKEN": env.GITLAB_TOKEN,
    },
  });

  const data = await glRes.text();

  return new Response(data, {
    status: glRes.status,
    headers: {
      "Content-Type": "application/json",
      ...corsHeaders(env),
    },
  });
}

// ── GitLab file fetch (for package.json etc.) ──

async function handleGitLabFile(request, env) {
  const claims = await authenticate(request, env);
  if (!claims) {
    return jsonError("Unauthorized", 401, env);
  }

  if (!env.GITLAB_TOKEN) {
    return jsonError(
      "Worker misconfigured: GITLAB_TOKEN secret not set",
      500,
      env,
    );
  }

  let body;
  try {
    body = await request.json();
  } catch {
    return jsonError("Invalid JSON body", 400, env);
  }

  const { projectId, filePath, ref } = body;
  if (!projectId || !filePath || typeof filePath !== "string") {
    return jsonError("Missing projectId or filePath", 400, env);
  }

  // GitLab file_path: encode slashes as %2F
  const encodedPath = filePath.split("/").map(encodeURIComponent).join("%2F");
  const url = `${GITLAB_BASE}/api/v4/projects/${encodeURIComponent(projectId)}/repository/files/${encodedPath}/raw?ref=${encodeURIComponent(ref || "main")}`;

  const res = await fetch(url, {
    headers: {
      "PRIVATE-TOKEN": env.GITLAB_TOKEN,
    },
  });

  if (!res.ok) {
    const errText = await res.text();
    return jsonResponse(
      { error: `GitLab ${res.status}`, detail: errText },
      res.status,
      env,
    );
  }

  const text = await res.text();
  return new Response(text, {
    status: 200,
    headers: {
      "Content-Type": "application/json",
      ...corsHeaders(env),
    },
  });
}

// ── GitLab projects list (for discovering project IDs) ──

async function handleGitLabProjects(request, env) {
  const claims = await authenticate(request, env);
  if (!claims) {
    return jsonError("Unauthorized", 401, env);
  }

  if (!env.GITLAB_TOKEN) {
    return jsonError(
      "Worker misconfigured: GITLAB_TOKEN secret not set",
      500,
      env,
    );
  }

  const url = `${GITLAB_BASE}/api/v4/projects?membership=true&per_page=50&order_by=last_activity_at`;

  const res = await fetch(url, {
    headers: {
      Accept: "application/json",
      "PRIVATE-TOKEN": env.GITLAB_TOKEN,
    },
  });

  if (!res.ok) {
    return jsonError(`GitLab ${res.status}`, res.status, env);
  }

  const projects = await res.json();
  const list = projects.map((p) => ({
    id: p.id,
    name: p.name,
    path: p.path_with_namespace,
    defaultBranch: p.default_branch || "main",
  }));

  return jsonResponse(list, 200, env);
}

// ── npm registry version lookup ──

async function handleNpmVersions(request, env) {
  const claims = await authenticate(request, env);
  if (!claims) {
    return jsonError("Unauthorized", 401, env);
  }

  let body;
  try {
    body = await request.json();
  } catch {
    return jsonError("Invalid JSON body", 400, env);
  }

  const { packages } = body;
  if (!Array.isArray(packages) || packages.length === 0) {
    return jsonError("Missing or empty packages array", 400, env);
  }

  // Cap at 100 to avoid timeout
  const toFetch = packages.slice(0, 100).filter((p) => typeof p === "string");

  const results = await Promise.all(
    toFetch.map(async (name) => {
      try {
        const res = await fetch(
          `https://registry.npmjs.org/${encodeURIComponent(name)}/latest`,
          { headers: { Accept: "application/json" } },
        );
        if (!res.ok) return { name, latest: null };
        const data = await res.json();
        return { name, latest: data.version || null };
      } catch {
        return { name, latest: null };
      }
    }),
  );

  return jsonResponse(results, 200, env);
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

    if (url.pathname === "/youtrack") {
      return handleYouTrack(request, env);
    }

    if (url.pathname === "/gitlab") {
      return handleGitLab(request, env);
    }

    if (url.pathname === "/gitlab/file") {
      return handleGitLabFile(request, env);
    }

    if (url.pathname === "/gitlab/projects") {
      return handleGitLabProjects(request, env);
    }

    if (url.pathname === "/npm-versions") {
      return handleNpmVersions(request, env);
    }

    // Default: Linear proxy (everything else goes here)
    return handleProxy(request, env);
  },
};
