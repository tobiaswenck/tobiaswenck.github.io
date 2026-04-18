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
 *   POST /gitlab/tree     — list files in a repository directory (requires JWT)
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
const MAX_AUTH_ATTEMPTS = 5;
const LOCKOUT_SECONDS = 900; // 15 minutes

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

// ── Rate limiting (requires KV namespace binding "RATE_LIMIT") ──

async function checkRateLimit(ip, env) {
  if (!env.RATE_LIMIT) return true;
  const key = `auth:${ip}`;
  const val = await env.RATE_LIMIT.get(key);
  if (!val) return true;
  return parseInt(val, 10) < MAX_AUTH_ATTEMPTS;
}

async function recordFailedAuth(ip, env) {
  if (!env.RATE_LIMIT) return;
  const key = `auth:${ip}`;
  const val = await env.RATE_LIMIT.get(key);
  const attempts = val ? parseInt(val, 10) + 1 : 1;
  await env.RATE_LIMIT.put(key, String(attempts), {
    expirationTtl: LOCKOUT_SECONDS,
  });
}

async function clearAuthAttempts(ip, env) {
  if (!env.RATE_LIMIT) return;
  await env.RATE_LIMIT.delete(`auth:${ip}`);
}

// ── Persisted Linear queries ──
// The client never sends raw GraphQL. Instead it sends a queryId + variables,
// and the worker looks up a pre-approved query string. This eliminates the
// proxy-as-GraphQL-gateway risk entirely (no introspection, no mutations,
// no unexpected root fields — all by construction).

const PERSISTED_QUERIES = {
  myIssues: `{
    viewer {
      assignedIssues(
        first: 15
        orderBy: updatedAt
        filter: { state: { type: { nin: ["completed", "canceled"] } } }
      ) {
        nodes {
          identifier
          title
          priority
          updatedAt
          state { name color }
          url
        }
      }
    }
  }`,
  projectUpdates: `{
    projects(
      first: 50
      filter: {
        members: { some: { isMe: { eq: true } } }
        state: { nin: ["completed", "canceled"] }
      }
    ) {
      nodes {
        name
        url
        projectUpdates(first: 1, orderBy: createdAt) {
          nodes {
            body
            createdAt
            health
            user { name }
          }
        }
      }
    }
  }`,
  weeklyCompleted: `query WeeklyCompleted($gte: DateTime!, $lt: DateTime) {
    viewer {
      assignedIssues(
        first: 50
        orderBy: updatedAt
        filter: {
          state: { type: { eq: "completed" } }
          completedAt: { gte: $gte, lt: $lt }
        }
      ) {
        nodes {
          identifier
          title
          completedAt
          state { name color }
          url
        }
      }
    }
  }`,
};

// ── GitLab project allowlist ──

const ALLOWED_PROJECT_PATHS = new Set([
  "Rail-Network/gps-s/mobileapp",
  "Rail-Network/report/mobileapp",
  "Rail-Network/komreg/komregapp",
  "Rail-Network/fahrplan-app",
]);

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

  const ip = request.headers.get("CF-Connecting-IP") || "unknown";
  if (!(await checkRateLimit(ip, env))) {
    return jsonError("Too many attempts. Try again later.", 429, env);
  }

  if (body.password !== env.DASHBOARD_PASSWORD) {
    await recordFailedAuth(ip, env);
    return jsonError("Invalid password", 401, env);
  }

  await clearAuthAttempts(ip, env);
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

  const { queryId, variables } = body;
  if (!queryId || typeof queryId !== "string" || !Object.prototype.hasOwnProperty.call(PERSISTED_QUERIES, queryId)) {
    return jsonError("Unknown queryId", 403, env);
  }

  const query = PERSISTED_QUERIES[queryId];

  // ── Proxy to Linear ──
  const linearRes = await fetch(LINEAR_GQL, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: env.LINEAR_API_KEY,
    },
    body: JSON.stringify({ query, variables: variables || {} }),
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
const GITLAB_GROUP = "Rail-Network";
const GITLAB_MR_CAP = 40; // stay under Cloudflare's 50-subrequest limit
const FRONTEND_FILE_RE = /\.(css|scss|sass|less|ts|tsx|js|jsx|mjs|cjs|vue)$/i;

/** Count +/- lines in a unified diff string, ignoring the file header lines (+++/---). */
function countDiffLines(diff) {
  if (!diff || typeof diff !== "string") return { added: 0, removed: 0 };
  let added = 0;
  let removed = 0;
  for (const line of diff.split("\n")) {
    if (line.startsWith("+++") || line.startsWith("---")) continue;
    if (line.startsWith("+")) added++;
    else if (line.startsWith("-")) removed++;
  }
  return { added, removed };
}

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

  // ── Fetch all open MRs across the whole group ──
  const glUrl = new URL(
    `${GITLAB_BASE}/api/v4/groups/${encodeURIComponent(GITLAB_GROUP)}/merge_requests`,
  );
  glUrl.searchParams.set("state", "opened");
  glUrl.searchParams.set("per_page", "50");
  glUrl.searchParams.set("order_by", "updated_at");

  const glRes = await fetch(glUrl.toString(), {
    headers: {
      Accept: "application/json",
      "PRIVATE-TOKEN": env.GITLAB_TOKEN,
    },
  });

  if (!glRes.ok) {
    const errText = await glRes.text();
    return jsonResponse(
      { error: `GitLab ${glRes.status}`, detail: errText },
      glRes.status,
      env,
    );
  }

  const allMrs = await glRes.json();
  const truncated = allMrs.length > GITLAB_MR_CAP;
  const mrs = allMrs.slice(0, GITLAB_MR_CAP);

  if (truncated) {
    console.warn(
      `GitLab: got ${allMrs.length} open MRs, capping at ${GITLAB_MR_CAP} to stay under subrequest limit`,
    );
  }

  // ── For each MR, fetch changes in parallel, filter by file extension ──
  const enriched = await Promise.all(
    mrs.map(async (mr) => {
      try {
        const changesUrl = `${GITLAB_BASE}/api/v4/projects/${mr.project_id}/merge_requests/${mr.iid}/changes`;
        const cRes = await fetch(changesUrl, {
          headers: {
            Accept: "application/json",
            "PRIVATE-TOKEN": env.GITLAB_TOKEN,
          },
        });
        if (!cRes.ok) return null;
        const detail = await cRes.json();
        const changes = Array.isArray(detail.changes) ? detail.changes : [];

        const matched = changes
          .map((c) => c.new_path || c.old_path || "")
          .filter((p) => FRONTEND_FILE_RE.test(p));

        if (matched.length === 0) return null;

        let added = 0;
        let removed = 0;
        for (const c of changes) {
          const stats = countDiffLines(c.diff);
          added += stats.added;
          removed += stats.removed;
        }

        const project_name =
          mr.references?.full?.split("!")[0]?.split("/").pop() || "";

        // detailed_merge_status is on the detail response; merge base MR + merge info
        return {
          ...mr,
          project_name,
          lines_added: added,
          lines_removed: removed,
          matched_files: matched,
          has_conflicts: detail.has_conflicts ?? mr.has_conflicts,
          detailed_merge_status:
            detail.detailed_merge_status ?? mr.detailed_merge_status,
          merge_status: detail.merge_status ?? mr.merge_status,
          changes_count: detail.changes_count ?? mr.changes_count,
        };
      } catch (e) {
        console.warn(
          `GitLab: failed to fetch changes for !${mr.iid} in project ${mr.project_id}`,
          e,
        );
        return null;
      }
    }),
  );

  const filtered = enriched.filter(Boolean);

  return jsonResponse(filtered, 200, env);
}

// ── GitLab file fetch (for package.json etc.) ──

const ALLOWED_FILE_PATHS = new Set(["package.json"]);

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

  const { projectPath, filePath, ref } = body;
  if (!projectPath || !filePath || typeof filePath !== "string") {
    return jsonError("Missing projectPath or filePath", 400, env);
  }

  if (!ALLOWED_PROJECT_PATHS.has(projectPath)) {
    return jsonError("Project not allowed", 403, env);
  }

  if (filePath.includes("..") || filePath.startsWith("/")) {
    return jsonError("Invalid filePath", 400, env);
  }

  const fileAllowed =
    ALLOWED_FILE_PATHS.has(filePath) ||
    (typeof filePath === "string" &&
      (filePath.endsWith(".svg") || filePath.endsWith(".vue") || filePath.endsWith(".ts")));

  if (!fileAllowed) {
    return jsonError(
      `File not allowed: ${filePath}. Allowed: ${[...ALLOWED_FILE_PATHS].join(", ")}, *.svg, *.vue, *.ts`,
      403,
      env,
    );
  }

  const encodedPath = filePath.split("/").map(encodeURIComponent).join("%2F");
  const url = `${GITLAB_BASE}/api/v4/projects/${encodeURIComponent(projectPath)}/repository/files/${encodedPath}/raw?ref=${encodeURIComponent(ref || "main")}`;

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
  const contentType = filePath.endsWith(".svg")
    ? "image/svg+xml"
    : (filePath.endsWith(".vue") || filePath.endsWith(".ts"))
      ? "text/plain"
      : "application/json";
  return new Response(text, {
    status: 200,
    headers: {
      "Content-Type": contentType,
      ...corsHeaders(env),
    },
  });
}

// ── GitLab repository tree (for listing files in a directory) ──

const ALLOWED_TREE_PREFIXES = ["public/icons", "src"];

async function handleGitLabTree(request, env) {
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

  const { projectPath, path, ref, recursive } = body;
  if (!projectPath || !path || typeof path !== "string") {
    return jsonError("Missing projectPath or path", 400, env);
  }

  if (!ALLOWED_PROJECT_PATHS.has(projectPath)) {
    return jsonError("Project not allowed", 403, env);
  }

  if (!ALLOWED_TREE_PREFIXES.some((prefix) => path === prefix || path.startsWith(prefix + "/"))) {
    return jsonError(
      `Path not allowed: ${path}. Allowed prefixes: ${ALLOWED_TREE_PREFIXES.join(", ")}`,
      403,
      env,
    );
  }

  const allEntries = [];
  let page = 1;
  const perPage = 100;

  while (true) {
    const url = `${GITLAB_BASE}/api/v4/projects/${encodeURIComponent(projectPath)}/repository/tree?path=${encodeURIComponent(path)}&per_page=${perPage}&page=${page}&ref=${encodeURIComponent(ref || "main")}${recursive ? "&recursive=true" : ""}`;

    const res = await fetch(url, {
      headers: {
        Accept: "application/json",
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

    const entries = await res.json();
    allEntries.push(...entries);

    if (entries.length < perPage) break;
    page++;
    if (page > 20) break;
  }

  return jsonResponse(allEntries, 200, env);
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

    if (url.pathname === "/gitlab/tree") {
      return handleGitLabTree(request, env);
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
