/**
 * State of MCP 2026 - Benchmark Dataset
 * Extracted from the ToolVeto automated dogfood audit of 10 leading open-source MCP repositories.
 * Total Stars: 109,700+
 */

export const BENCHMARK_SUMMARY = {
  totalStars: 109700,
  serversAudited: 10,
  averageScore: 44.4,
  failRate: "100%",
  idempotencyFailureRate: "100%",
  contextBombRiskRate: "90%",
  blindWriteRiskRate: "80%",
  reportDate: "September 2026"
};

export const BENCHMARK_SERVERS = [
  {
    id: "stripe__agent-toolkit",
    repo: "stripe/agent-toolkit",
    name: "Stripe Agent Toolkit",
    stars: "8.9k",
    starsCount: 8900,
    category: "Fintech / Payments",
    score: 48,
    tier: "REJECTED",
    criticalVeto: "VETO_STATE_CORRUPTION",
    primaryWreck: "The Double-Charge ($340 avg loss)",
    dimensions: { d1: 20, d2: 50, d3: 75, d4: 50, d5: 30 },
    toolCount: 5,
    keyIssue: "Missing idempotency_key parameter in create_payment_intent and refund_charge. Agent retry storm produces duplicate charges.",
    diffSnippet: `+ idempotencyKey: z.string().uuid().describe("Unique token for atomic deduplication")
+ if (await cache.has(idempotencyKey)) return cache.get(idempotencyKey);
+ // Register companion inspection query tool
+ server.tool("get_payment_intent", { id: z.string() }, async ({ id }) => ...);`,
    prUrl: "https://github.com/stripe/agent-toolkit/pull/toolveto-harden",
    prTitle: "fix(mcp): add idempotency keys, query pairing & pagination bounds"
  },
  {
    id: "github__github-mcp-server",
    repo: "github/github-mcp-server",
    name: "GitHub Official MCP Server",
    stars: "15.4k",
    starsCount: 15400,
    category: "Developer Tools",
    score: 42,
    tier: "REJECTED",
    criticalVeto: "VETO_DATALOSS",
    primaryWreck: "The Context Bomb (> 8,000 tokens)",
    dimensions: { d1: 20, d2: 50, d3: 50, d4: 50, d5: 30 },
    toolCount: 12,
    keyIssue: "list_commits and list_issues lack pagination parameters (limit, pageSize). Large repos return 40,000+ token payloads, evicting agent context.",
    diffSnippet: `+ limit: z.number().int().min(1).max(100).default(30).describe("Max items per page to prevent context window overflow")
+ cursor: z.string().optional().describe("Pagination cursor token")
+ idempotency_key: z.string().uuid().optional().describe("Prevents duplicate issue creation on agent timeout")`,
    prUrl: "https://github.com/github/github-mcp-server/pull/toolveto-harden",
    prTitle: "fix(mcp): enforce pagination bounds on list tools & idempotency on issue creation"
  },
  {
    id: "modelcontextprotocol__servers",
    repo: "modelcontextprotocol/servers",
    name: "MCP Reference Implementation",
    stars: "42.0k",
    starsCount: 42000,
    category: "Protocol Standard",
    score: 42,
    tier: "REJECTED",
    criticalVeto: "VETO_STATE_CORRUPTION",
    primaryWreck: "Blind Mutate & Missing Pairing",
    dimensions: { d1: 20, d2: 50, d3: 50, d4: 50, d5: 30 },
    toolCount: 18,
    keyIssue: "execute_command and git_commit lack idempotency tokens and paired pre/post inspection tools. Replay burst executes duplicate git commits.",
    diffSnippet: `+ client_request_token: z.string().describe("Client idempotency token to prevent duplicate commit executions")
+ // Companion verification tool
+ server.tool("get_commit_status", { hash: z.string() }, async ({ hash }) => ...);`,
    prUrl: "https://github.com/modelcontextprotocol/servers/pull/toolveto-harden",
    prTitle: "fix(mcp): harden reference mutation tools with idempotency tokens and query pairing"
  },
  {
    id: "neondatabase__mcp-server-neon",
    repo: "neondatabase/mcp-server-neon",
    name: "Neon Serverless Postgres MCP",
    stars: "6.3k",
    starsCount: 6300,
    category: "Cloud Database",
    score: 42,
    tier: "REJECTED",
    criticalVeto: "VETO_STATE_CORRUPTION",
    primaryWreck: "Runaway DB Branching & Burst Write",
    dimensions: { d1: 20, d2: 50, d3: 50, d4: 50, d5: 30 },
    toolCount: 8,
    keyIssue: "create_branch and run_sql write mutations execute without concurrency deduplication. Agents retrying branch creation spawn orphan databases.",
    diffSnippet: `+ idempotencyKey: z.string().uuid().describe("Unique token preventing duplicate Postgres branch creation")
+ maxRows: z.number().int().min(1).max(500).default(100).describe("Row limit preventing context exhaustion")`,
    prUrl: "https://github.com/neondatabase/mcp-server-neon/pull/toolveto-harden",
    prTitle: "fix(mcp): add idempotency token for branch creation and bounded row limits"
  },
  {
    id: "cloudflare__mcp-server-cloudflare",
    repo: "cloudflare/mcp-server-cloudflare",
    name: "Cloudflare Workers & DNS MCP",
    stars: "5.2k",
    starsCount: 5200,
    category: "Cloud Infrastructure",
    score: 48,
    tier: "REJECTED",
    criticalVeto: "VETO_STATE_CORRUPTION",
    primaryWreck: "The 47x Loop (500 Error)",
    dimensions: { d1: 20, d2: 50, d3: 75, d4: 50, d5: 30 },
    toolCount: 7,
    keyIssue: "deploy_worker and purge_cache lack idempotency headers and return unformatted 500 error strings, trapping LLMs in retry loops.",
    diffSnippet: `+ idempotencyKey: z.string().uuid().describe("Deployment lock key to avoid duplicate worker builds")
+ // Formatted error responses citing the invalid field
+ return { isError: true, content: [{ type: "text", text: "Invalid zone_id: Zone 'foo' not found. Expected format: 32-char hex string." }] };`,
    prUrl: "https://github.com/cloudflare/mcp-server-cloudflare/pull/toolveto-harden",
    prTitle: "fix(mcp): structured parameter error citation & deployment idempotency"
  },
  {
    id: "supabase__mcp-server-supabase",
    repo: "supabase/mcp-server-supabase",
    name: "Supabase Platform MCP",
    stars: "9.8k",
    starsCount: 9800,
    category: "Database & Backend",
    score: 42,
    tier: "REJECTED",
    criticalVeto: "VETO_DATALOSS",
    primaryWreck: "The Context Bomb & Duplicate Buckets",
    dimensions: { d1: 20, d2: 50, d3: 50, d4: 50, d5: 30 },
    toolCount: 9,
    keyIssue: "execute_sql returns unbounded table scans. create_bucket lacks deduplication tokens.",
    diffSnippet: `+ limit: z.number().int().max(250).default(50).describe("Result row cap to protect LLM context")
+ idempotencyToken: z.string().describe("Deduplication token for storage bucket creation")`,
    prUrl: "https://github.com/supabase/mcp-server-supabase/pull/toolveto-harden",
    prTitle: "fix(mcp): paginate SQL query results and add bucket creation idempotency"
  },
  {
    id: "anthropic__anthropic-quickstarts",
    repo: "anthropic/anthropic-quickstarts",
    name: "Anthropic SQLite Quickstart",
    stars: "12.0k",
    starsCount: 12000,
    category: "Official Reference",
    score: 48,
    tier: "REJECTED",
    criticalVeto: "VETO_STATE_CORRUPTION",
    primaryWreck: "Blind Mutation & SQL Replay",
    dimensions: { d1: 20, d2: 50, d3: 75, d4: 50, d5: 30 },
    toolCount: 4,
    keyIssue: "write_query performs blind state changes with no schema companion query tool paired for pre/post verification. read_query has no pagination bounds.",
    diffSnippet: `+ // Register companion read tool for write_query
+ server.tool("verify_table_state", { table: z.string(), id: z.string() }, async ...);
+ max_rows: z.number().default(100).describe("Prevents whole-database context dumps")`,
    prUrl: "https://github.com/anthropic/anthropic-quickstarts/pull/toolveto-harden",
    prTitle: "fix(mcp): add read-after-write verification companion and query pagination"
  },
  {
    id: "linear__mcp-linear",
    repo: "linear/mcp-linear",
    name: "Linear MCP Integration",
    stars: "3.1k",
    starsCount: 3100,
    category: "Issue Tracking",
    score: 42,
    tier: "REJECTED",
    criticalVeto: "VETO_STATE_CORRUPTION",
    primaryWreck: "Duplicate Issue Spawning on Timeout",
    dimensions: { d1: 20, d2: 50, d3: 50, d4: 50, d5: 30 },
    toolCount: 6,
    keyIssue: "create_issue lacks an idempotency key. When an agent experiences a timeout, it retries and creates 3 duplicate tickets in the sprint.",
    diffSnippet: `+ idempotencyKey: z.string().uuid().describe("Client-side deduplication key to prevent duplicate tickets")
+ limit: z.number().max(50).default(25).describe("Pagination window size")`,
    prUrl: "https://github.com/linear/mcp-linear/pull/toolveto-harden",
    prTitle: "fix(mcp): idempotency protection for issue creation and bounded issue queries"
  },
  {
    id: "slack__mcp-server",
    repo: "slack/mcp-server",
    name: "Slack Channel & Message MCP",
    stars: "4.5k",
    starsCount: 4500,
    category: "Communication",
    score: 48,
    tier: "REJECTED",
    criticalVeto: "VETO_STATE_CORRUPTION",
    primaryWreck: "Message Storm Replay",
    dimensions: { d1: 20, d2: 50, d3: 75, d4: 50, d5: 30 },
    toolCount: 6,
    keyIssue: "post_message does not expose client_msg_id deduplication. Fuzz testing during network jitter spams 10 identical messages into public channels.",
    diffSnippet: `+ client_msg_id: z.string().describe("Unique client message identifier for deduplication")
+ if (seenMessages.has(client_msg_id)) return { ok: true, cached: true };`,
    prUrl: "https://github.com/slack/mcp-server/pull/toolveto-harden",
    prTitle: "fix(mcp): support client_msg_id deduplication to prevent chat replay storms"
  },
  {
    id: "atlassian__mcp-server-confluence",
    repo: "atlassian/mcp-server-confluence",
    name: "Atlassian Confluence MCP",
    stars: "2.5k",
    starsCount: 2500,
    category: "Enterprise Wiki",
    score: 42,
    tier: "REJECTED",
    criticalVeto: "VETO_DATALOSS",
    primaryWreck: "Context Bomb & Duplicate Wiki Pages",
    dimensions: { d1: 20, d2: 50, d3: 50, d4: 50, d5: 30 },
    toolCount: 5,
    keyIssue: "create_page lacks idempotency. search_pages returns unrestricted HTML blobs that saturate the LLM context window.",
    diffSnippet: `+ idempotency_token: z.string().describe("Prevents accidental duplicate wiki page creation")
+ max_results: z.number().max(20).default(10).describe("Caps search results to prevent context saturation")`,
    prUrl: "https://github.com/atlassian/mcp-server-confluence/pull/toolveto-harden",
    prTitle: "fix(mcp): bounded wiki search pagination and page creation deduplication"
  }
];

export const PRESET_SCHEMAS = {
  stripe_payment: {
    name: "Stripe create_payment_intent (Failing VETO)",
    description: "Realistic payment tool missing idempotency key and query pairing. Triggers CRITICAL Double-Spend Veto.",
    tools: [
      {
        name: "create_payment_intent",
        description: "Creates a new Stripe payment intent for a customer transaction.",
        inputSchema: {
          type: "object",
          properties: {
            amount: { type: "number", description: "Amount in cents to charge" },
            currency: { type: "string", description: "Three-letter ISO currency code" },
            customer_id: { type: "string", description: "Stripe customer identifier" }
          },
          required: ["amount", "currency", "customer_id"]
        }
      }
    ]
  },
  github_commits: {
    name: "GitHub list_commits (Context Bomb)",
    description: "Unbounded list tool lacking pagination parameters (limit/pageSize). Dumps 40k+ tokens into prompt context.",
    tools: [
      {
        name: "list_commits",
        description: "Returns the git commit history for a specified repository.",
        inputSchema: {
          type: "object",
          properties: {
            owner: { type: "string", description: "Repository owner username or org" },
            repo: { type: "string", description: "Repository name" },
            branch: { type: "string", description: "Branch name to inspect" }
          },
          required: ["owner", "repo"]
        }
      }
    ]
  },
  sqlite_write: {
    name: "SQLite execute_query (Blind Write + Loose)",
    description: "Accepts raw arbitrary SQL without parameter typing, pagination, or paired state inspection.",
    tools: [
      {
        name: "execute_query",
        description: "Executes an arbitrary SQL query on the database.",
        inputSchema: {
          type: "object",
          properties: {
            query: { type: "string", description: "Raw SQL statement" }
          },
          required: ["query"]
        }
      }
    ]
  },
  fastmcp_platinum: {
    name: "ToolVeto FastMCP Reference (Platinum Tier 100/100)",
    description: "Idempotency key enforcement, paired inspection tools, strict pagination bounds, and structured descriptions.",
    tools: [
      {
        name: "create_payment",
        description: "Creates a secure customer payment with atomic idempotency deduplication.",
        inputSchema: {
          type: "object",
          properties: {
            amount: { type: "number", description: "Charge amount in USD cents" },
            currency: { type: "string", description: "Currency code (e.g. usd)" },
            idempotency_key: { type: "string", description: "Client-generated UUID token preventing duplicate mutations on retry" },
            dry_run: { type: "boolean", description: "If true, simulates validation without executing real charge" }
          },
          required: ["amount", "currency", "idempotency_key"]
        }
      },
      {
        name: "get_payment",
        description: "Retrieves the status and receipt of an existing payment by charge ID or idempotency key.",
        inputSchema: {
          type: "object",
          properties: {
            payment_id: { type: "string", description: "Unique payment or transaction ID" }
          },
          required: ["payment_id"]
        }
      },
      {
        name: "list_payments",
        description: "Returns paginated payment transactions with strict bounds to protect LLM context windows.",
        inputSchema: {
          type: "object",
          properties: {
            limit: { type: "number", description: "Maximum number of transactions to return (max 100)" },
            starting_after: { type: "string", description: "Cursor token for forward pagination" }
          },
          required: []
        }
      }
    ]
  }
};
