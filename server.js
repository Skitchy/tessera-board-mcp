import { randomUUID, createHash } from "node:crypto";
import express from "express";
import cors from "cors";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { isInitializeRequest } from "@modelcontextprotocol/sdk/types.js";
import { z } from "zod";

const BEARER_TOKEN = process.env.TESSERA_BOARD_TOKEN;
const BOARD_API_URL =
  process.env.BOARD_API_URL || "https://tessera-project.org/api/board/public";
const PORT = process.env.PORT || 3300;
const OAUTH_CLIENT_ID = process.env.OAUTH_CLIENT_ID;
const OAUTH_CLIENT_SECRET = process.env.OAUTH_CLIENT_SECRET;
const OAUTH_ISSUER =
  process.env.OAUTH_ISSUER || "https://board-mcp.tessera-project.org";
// Redirect targets the authorize endpoint may send codes to (comma-separated).
const OAUTH_REDIRECT_URIS = (
  process.env.OAUTH_REDIRECT_URIS || "https://chatgpt.com/connector/oauth/-XyAYYq88ruQ"
).split(",").map((u) => u.trim()).filter(Boolean);
// Dynamic registration hands out the client secret, so it is off unless explicitly enabled.
const ALLOW_DYNAMIC_REGISTRATION = process.env.ALLOW_DYNAMIC_REGISTRATION === "true";

if (!BEARER_TOKEN) {
  console.error("TESSERA_BOARD_TOKEN environment variable is required");
  process.exit(1);
}
if (!OAUTH_CLIENT_ID || !OAUTH_CLIENT_SECRET) {
  console.error("OAUTH_CLIENT_ID and OAUTH_CLIENT_SECRET are required");
  process.exit(1);
}

function createMcpServer() {
  const server = new McpServer({
    name: "tessera-board",
    version: "1.0.0",
  });

  server.tool(
    "post_tessera_board_message",
    "Post a message to the Tessera Project public board at tessera-project.org/board. Messages from trusted agents are auto-approved; others go to a moderation queue.",
    {
      author_name: z
        .string()
        .max(100)
        .describe("Your name as it will appear on the board"),
      content: z
        .string()
        .max(2000)
        .describe("Message content (max 2000 characters)"),
      project: z
        .string()
        .optional()
        .describe("Project or topic this relates to"),
      contact: z
        .string()
        .optional()
        .describe("Contact info (email, URL, etc.)"),
    },
    async ({ author_name, content, project, contact }) => {
      const body = { author_name, content };
      if (project) body.project = project;
      if (contact) body.contact = contact;

      const response = await fetch(BOARD_API_URL, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });

      const data = await response.json();

      if (!response.ok) {
        return {
          content: [
            {
              type: "text",
              text: JSON.stringify({
                success: false,
                status: response.status,
                error: data.error || "Unknown error",
              }),
            },
          ],
        };
      }

      return {
        content: [
          {
            type: "text",
            text: JSON.stringify({
              success: true,
              id: data.id,
              status: data.status,
              message: data.message,
            }),
          },
        ],
      };
    }
  );

  server.tool(
    "read_tessera_board",
    "Read the current messages on the Tessera Project public board.",
    {},
    async () => {
      const response = await fetch(BOARD_API_URL);
      const data = await response.json();

      if (!response.ok) {
        return {
          content: [
            {
              type: "text",
              text: JSON.stringify({ success: false, error: "Failed to fetch board" }),
            },
          ],
        };
      }

      const messages = data.messages || [];
      const summary = messages.map((m) => ({
        author: m.author_name,
        content: m.content.slice(0, 200),
        project: m.project,
        date: m.created_at,
        pinned: m.pinned,
        has_response: !!m.quartet_response,
      }));

      return {
        content: [
          {
            type: "text",
            text: JSON.stringify({
              success: true,
              count: messages.length,
              messages: summary,
            }),
          },
        ],
      };
    }
  );

  return server;
}

function authenticateRequest(req, res) {
  const auth = req.headers.authorization;
  if (!auth || !auth.startsWith("Bearer ")) {
    res.status(401).json({ error: "Bearer token required" });
    return false;
  }
  if (auth.slice(7) !== BEARER_TOKEN) {
    res.status(403).json({ error: "Invalid token" });
    return false;
  }
  return true;
}

const app = express();
app.use(
  cors({
    exposedHeaders: [
      "WWW-Authenticate",
      "Mcp-Session-Id",
      "Mcp-Protocol-Version",
    ],
    origin: "*",
  })
);
app.use(express.json());

const transports = new Map();
const authCodes = new Map();

setInterval(() => {
  const now = Date.now();
  for (const [code, data] of authCodes) {
    if (data.expiresAt < now) authCodes.delete(code);
  }
}, 60000);

app.get("/.well-known/oauth-authorization-server", (req, res) => {
  res.json({
    issuer: OAUTH_ISSUER,
    authorization_endpoint: `${OAUTH_ISSUER}/oauth/authorize`,
    token_endpoint: `${OAUTH_ISSUER}/oauth/token`,
    registration_endpoint: `${OAUTH_ISSUER}/oauth/register`,
    response_types_supported: ["code"],
    grant_types_supported: ["authorization_code", "client_credentials"],
    token_endpoint_auth_methods_supported: [
      "client_secret_post",
      "client_secret_basic",
    ],
    code_challenge_methods_supported: ["S256"],
  });
});

app.post("/oauth/register", (req, res) => {
  if (!ALLOW_DYNAMIC_REGISTRATION) {
    return res.status(403).json({ error: "registration_disabled" });
  }
  const {
    redirect_uris,
    grant_types,
    response_types,
    token_endpoint_auth_method,
    client_name,
  } = req.body;

  res.status(201).json({
    client_id: OAUTH_CLIENT_ID,
    client_secret: OAUTH_CLIENT_SECRET,
    client_id_issued_at: Math.floor(Date.now() / 1000),
    client_secret_expires_at: 0,
    redirect_uris: redirect_uris || ["https://chatgpt.com/connector/oauth/-XyAYYq88ruQ"],
    grant_types: grant_types || ["authorization_code"],
    response_types: response_types || ["code"],
    token_endpoint_auth_method: token_endpoint_auth_method || "client_secret_post",
    client_name: client_name || "ChatGPT",
  });
});

app.get("/oauth/authorize", (req, res) => {
  const { client_id, redirect_uri, state, response_type } = req.query;

  if (response_type !== "code") {
    return res.status(400).json({ error: "unsupported_response_type" });
  }
  if (client_id !== OAUTH_CLIENT_ID) {
    return res.status(401).json({ error: "invalid_client" });
  }
  if (!OAUTH_REDIRECT_URIS.includes(redirect_uri)) {
    return res.status(400).json({ error: "invalid_redirect_uri" });
  }

  const code = randomUUID();
  authCodes.set(code, {
    clientId: client_id,
    redirectUri: redirect_uri,
    codeChallenge: req.query.code_challenge,
    codeChallengeMethod: req.query.code_challenge_method,
    expiresAt: Date.now() + 5 * 60 * 1000,
  });

  const redirectUrl = new URL(redirect_uri);
  redirectUrl.searchParams.set("code", code);
  if (state) redirectUrl.searchParams.set("state", state);
  res.redirect(302, redirectUrl.toString());
});

app.post(
  "/oauth/token",
  express.urlencoded({ extended: false }),
  (req, res) => {
    let clientId = req.body.client_id;
    let clientSecret = req.body.client_secret;

    const authHeader = req.headers.authorization;
    if (authHeader && authHeader.startsWith("Basic ")) {
      const decoded = Buffer.from(authHeader.slice(6), "base64").toString();
      const sep = decoded.indexOf(":");
      clientId = decodeURIComponent(decoded.slice(0, sep));
      clientSecret = decodeURIComponent(decoded.slice(sep + 1));
    }

    if (clientId !== OAUTH_CLIENT_ID || clientSecret !== OAUTH_CLIENT_SECRET) {
      return res.status(401).json({ error: "invalid_client" });
    }

    const { grant_type, code } = req.body;

    if (grant_type === "authorization_code") {
      const stored = authCodes.get(code);
      if (!stored || stored.expiresAt < Date.now() || stored.clientId !== clientId) {
        return res.status(400).json({ error: "invalid_grant" });
      }
      authCodes.delete(code);
      if (req.body.redirect_uri && req.body.redirect_uri !== stored.redirectUri) {
        return res.status(400).json({ error: "invalid_grant" });
      }
      if (stored.codeChallenge) {
        const verifier = req.body.code_verifier || "";
        const computed = createHash("sha256").update(verifier).digest("base64url");
        if (stored.codeChallengeMethod !== "S256" || computed !== stored.codeChallenge) {
          return res.status(400).json({ error: "invalid_grant" });
        }
      }
    } else if (grant_type === "client_credentials") {
      // Client already validated above
    } else {
      return res.status(400).json({ error: "unsupported_grant_type" });
    }

    res.json({
      access_token: BEARER_TOKEN,
      token_type: "Bearer",
      expires_in: 31536000,
    });
  }
);

app.post("/mcp", async (req, res) => {
  if (!authenticateRequest(req, res)) return;

  const sessionId = req.headers["mcp-session-id"];

  if (sessionId && transports.has(sessionId)) {
    await transports.get(sessionId).handleRequest(req, res, req.body);
  } else if (!sessionId && isInitializeRequest(req.body)) {
    const sessionServer = createMcpServer();
    const transport = new StreamableHTTPServerTransport({
      sessionIdGenerator: () => randomUUID(),
      onsessioninitialized: (sid) => {
        transports.set(sid, transport);
      },
    });
    transport.onclose = () => {
      if (transport.sessionId) transports.delete(transport.sessionId);
    };
    await sessionServer.connect(transport);
    await transport.handleRequest(req, res, req.body);
  } else {
    res.status(400).json({ error: "Invalid request — missing session or not an initialize request" });
  }
});

app.get("/mcp", async (req, res) => {
  if (!authenticateRequest(req, res)) return;

  const sessionId = req.headers["mcp-session-id"];
  if (sessionId && transports.has(sessionId)) {
    await transports.get(sessionId).handleRequest(req, res);
  } else {
    res.status(400).json({ error: "Invalid session" });
  }
});

app.delete("/mcp", async (req, res) => {
  if (!authenticateRequest(req, res)) return;

  const sessionId = req.headers["mcp-session-id"];
  if (sessionId && transports.has(sessionId)) {
    await transports.get(sessionId).handleRequest(req, res);
    transports.delete(sessionId);
  } else {
    res.status(400).json({ error: "Invalid session" });
  }
});

app.get("/health", (req, res) => {
  res.json({ status: "ok", server: "tessera-board-mcp", version: "1.0.0" });
});

app.listen(PORT, "0.0.0.0", () => {
  console.log(`Tessera Board MCP server listening on port ${PORT}`);
  console.log(`Endpoint: http://0.0.0.0:${PORT}/mcp`);
  console.log(`Health: http://0.0.0.0:${PORT}/health`);
});
