import Link from "next/link";
import { Brand } from "@/components/brand";

const repository = "https://github.com/yonathanalulam/upsilonAuth";

export const metadata = {
  title: "UpsilonAuth",
  description: "Run, integrate, verify, revoke, and operate UpsilonAuth capability leases.",
};

const sections = [
  ["quickstart", "Quickstart"],
  ["model", "Authority model"],
  ["api", "HTTP API"],
  ["sdk", "Go SDK"],
  ["revocation", "Revocation & uses"],
  ["operations", "Deployment"],
  ["limits", "Limits"],
] as const;

const routes = [
  ["POST", "/v1/workloads", "Admin", "Register a public key and authority grant. Returns workload metadata with status 201."],
  ["GET", "/v1/workloads/:id", "Admin", "Get the workload status, key thumbprint, and normalized grant."],
  ["POST", "/v1/workloads/:id/disable", "Admin", "Disable the workload and revoke the leases it holds, including their children."],
  ["POST", "/v1/workloads/:id/rotate-key", "Admin", "Replace the public key, with an optional overlap of up to 24 hours."],
  ["POST", "/v1/leases", "Signed workload", "Request a root lease within the workload's current grant. Returns the lease and JWT with status 201."],
  ["GET", "/v1/leases/:id", "Admin", "Get stored lease claims, use state, and revocation state. The JWT is not returned."],
  ["POST", "/v1/leases/:id/delegate", "Parent JWT + signed workload", "Create a smaller lease for a named, active workload."],
  ["POST", "/v1/leases/:id/revoke", "Admin", "Revoke this lease and all of its current descendants in one transaction."],
  ["POST", "/v1/leases/:id/consume", "Consumption credential + capability", "Spend one finite use. An idempotency key makes retries safe."],
  ["GET", "/v1/leases/:id/trace", "Admin", "Get the path from the root lease to this lease."],
  ["GET", "/v1/audit-events", "Admin", "List filtered audit events, up to 200 per request."],
  ["GET", "/.well-known/jwks.json", "Public", "Get the active and overlapping Ed25519 verification keys."],
  ["GET", "/.well-known/revocations.json", "Public", "Get unexpired revoked lease IDs. Conditional requests use ETags."],
  ["GET", "/healthz", "Public", "Check whether the process is running. A 204 does not check PostgreSQL."],
  ["GET", "/readyz", "Public", "Check PostgreSQL readiness. Returns 204 or 503."],
  ["GET", "/metrics", "Admin", "Get Prometheus counters and cumulative latency metrics."],
] as const;

const enrollCommand = `curl -X POST http://127.0.0.1:8080/v1/workloads \\
  -H "Authorization: Bearer $ADMIN_TOKEN" \\
  -H "Content-Type: application/json" \\
  -d '{
    "name":"payments-worker",
    "public_key":"'$WORKLOAD_PUBLIC_KEY'",
    "grant":{
      "audiences":["service:payments"],
      "actions":["payments:read","payments:refund"],
      "resources":["customer/*"],
      "max_ttl":"5m",
      "max_delegation_depth":2,
      "can_delegate":true
    }
  }'`;

const leaseBodies = `// POST /v1/leases — signed with the workload SDK
{
  "audience":"service:payments",
  "actions":["payments:refund"],
  "resources":["customer/*"],
  "ttl":"60s",
  "max_depth":2,
  "proof_of_possession":false,
  "max_uses":0,
  "constraints":{"environment":"prod"}
}

// POST /v1/leases/:id/delegate — parent JWT + signed request
{
  "delegate_to":"recipient-workload-uuid",
  "actions":["payments:refund"],
  "resources":["customer/cus_123"],
  "ttl":"30s",
  "proof_of_possession":false,
  "max_uses":0,
  "constraints":{"environment":"prod"}
}`;

const sdkCommand = `control, err := client.NewControlPlane("https://auth.example", nil, false)
signer, err := client.NewSigner(workloadID, privateKey)

root, err := control.RequestLease(ctx, signer, client.LeaseRequest{
  Audience: "service:payments",
  Actions: []string{"payments:refund"},
  Resources: []string{"customer/*"},
  TTL: "60s",
  MaxDepth: 2,
})

child, err := control.DelegateLease(ctx, signer, root.ID, root.Token,
  client.DelegationRequest{
    DelegateTo: recipientID,
    Actions: []string{"payments:refund"},
    Resources: []string{"customer/cus_123"},
    TTL: "30s",
  },
)`;

const verifyCommand = `verifier, err := middleware.New(middleware.Config{
  JWKSURL: "https://auth.example/.well-known/jwks.json",
  RevocationsURL: "https://auth.example/.well-known/revocations.json",
  Issuer: "https://auth.example",
  Audience: "service:payments",
  RevocationMode: middleware.RevocationStrict,
})

router.POST("/customers/:customerID/refunds",
  verifier.Require("payments:refund", func(c *gin.Context) string {
    return "customer/" + c.Param("customerID")
  }),
  refundHandler,
)`;

export default function DocsPage() {
  return (
    <main className="docs-page">
      <header className="docs-header">
        <Brand />
        <div className="docs-header-links">
          <Link href="/security">Security</Link>
          <Link href="/">Home</Link>
          <a href={repository} target="_blank" rel="noreferrer">GitHub</a>
        </div>
      </header>

      <div className="docs-layout">
        <aside className="docs-sidebar">
          <strong>Developer guide</strong>
          {sections.map(([id, label]) => <a key={id} href={`#${id}`}>{label}</a>)}
        </aside>

        <article className="docs-content">
          <h1>Run UpsilonAuth and protect a service.</h1>
          <p className="docs-lead">Start with the local smoke test, then use the Go client to register workloads, request leases, delegate them, and verify them in Gin.</p>

          <section id="quickstart" className="docs-section">
            <h2>Start the local stack</h2>
            <p>You need Git, Go 1.26 or newer, Docker with Compose v2, and port 8080 available. Generate development credentials, load them into your shell, and start PostgreSQL and UpsilonAuth.</p>
            <pre><code>{`git clone ${repository}.git
cd upsilonAuth
go run ./cmd/keygen > .env

set -a
. ./.env
set +a

docker compose up --build -d
curl --fail http://127.0.0.1:8080/readyz`}</code></pre>
            <p><code>cmd/keygen</code> writes fresh values for the database, admin and consumption credentials, server signing key, and example workload keys. Then run <code>{'go run ./cmd/smoke -base http://127.0.0.1:8080 -admin "$ADMIN_TOKEN"'}</code>. The smoke test registers workloads, issues and delegates a lease, verifies it in Gin, revokes it, and confirms that the revoked lease is denied. The <a href={`${repository}/blob/main/docs/quickstart.md`}>repository quickstart</a> includes PowerShell commands and cleanup steps.</p>
          </section>

          <section id="model" className="docs-section">
            <h2>Set a workload&apos;s authority grant</h2>
            <p>Every workload needs a grant before it can request a lease. The grant sets the maximum audience, actions, resources, TTL, delegation depth, delegation permission, PoP mode, finite uses, and constraints. Root leases must stay inside that grant. Delegated leases keep the parent audience, name an active recipient, cannot outlive the parent, and normally narrow at least one permission.</p>
            <p><code>Authority(child) ⊆ Authority(parent) ⊆ Authority(root lease) ⊆ Authority(workload grant)</code></p>
            <p>Resources are case-sensitive NFC exact strings or a final bounded prefix wildcard such as <code>customer/*</code>. Percent encoding, traversal, backslashes, duplicate separators, empty segments, and arbitrary globs are rejected.</p>
            <pre><code>{enrollCommand}</code></pre>
            <pre><code>{leaseBodies}</code></pre>
          </section>

          <section id="api" className="docs-section">
            <h2>HTTP API</h2>
            <p>Admin routes accept a bearer token in the Authorization header. Workload requests sign the HTTP method, canonical escaped path, timestamp, nonce, and SHA-256 body digest. JSON bodies reject unknown fields. See the <a href={`${repository}/blob/main/docs/api.md`}>API contract</a> for request bodies, responses, and error codes.</p>
            <div className="docs-table" role="table" aria-label="UpsilonAuth HTTP routes">
              {routes.map(([method, path, auth, behavior]) => (
                <div className="docs-table-row" role="row" key={`${method}-${path}`}>
                  <code>{method}</code><code>{path}</code><span>{auth}</span><p>{behavior}</p>
                </div>
              ))}
            </div>
            <pre><code>{`// Successful lease issuance (201)
{"id":"lease-uuid","token":"<JWT>","workload_id":"workload-uuid","audience":"service:payments","expiration":"...","depth":0,"max_depth":2}

// Consistent error envelope
{"error":{"code":"AUTHORITY_ESCALATION","message":"requested authority is not permitted"},"request_id":"req-uuid"}`}</code></pre>
            <p>Common statuses are 400 malformed input, 401 missing/invalid authentication, 403 authenticated but denied, 404 absent resource, 409 conflict/replay, 413 oversized input, 422 authority validation, 429 rate limit, and 503 unavailable dependency.</p>
          </section>

          <section id="sdk" className="docs-section">
            <h2>Use the Go client and Gin middleware</h2>
            <p>The client signs root and delegation requests and returns structured <code>APIError</code> values. The verifier reports stable reasons such as <code>TOKEN_EXPIRED</code>, <code>INVALID_AUDIENCE</code>, <code>RESOURCE_OUT_OF_SCOPE</code>, <code>LEASE_REVOKED</code>, and <code>MAX_USES_EXCEEDED</code>.</p>
            <pre><code>{sdkCommand}</code></pre>
            <p>Derive resource identifiers from the route or trusted application state. Do not authorize one representation and later reinterpret it as a decoded filesystem or URL path.</p>
            <pre><code>{verifyCommand}</code></pre>
            <p>PoP clients use <code>client.NewAuthorizedRequest</code> to attach a DPoP-style proof bound to the method, URL, and token hash. See the <a href={`${repository}/blob/main/docs/sdk.md`}>SDK guide</a> and <a href={`${repository}/tree/main/examples/gin-protected`}>Gin example</a>.</p>
          </section>

          <section id="revocation" className="docs-section">
            <h2>Choose how revocation should fail</h2>
            <p><code>STRICT</code> denies requests when the verifier needs current revocation data and cannot refresh it. <code>BOUNDED_STALE</code> accepts the last good snapshot up to a configured age. <code>EXPIRY_ONLY</code> skips live revocation checks and relies on short lease expiration. None of these modes makes revocation instant across every verifier.</p>
            <p><code>max_uses</code> is stateful. Configure a <code>client.Consumer</code> with the distinct <code>CONSUMPTION_TOKEN</code> and assign its <code>Consume</code> method to the verifier. Consumption happens atomically before the handler; idempotency retries do not spend twice, and a handler failure does not refund a use.</p>
          </section>

          <section id="operations" className="docs-section">
            <h2>Configure a deployment</h2>
            <p>Production mode refuses to start without an HTTPS issuer, TLS enforcement, a TLS PostgreSQL URL, strong and separate admin and consumption credentials, a valid signing key, and verified migrations. Secret <code>_FILE</code> settings let you mount values from a secret manager.</p>
            <p>The distroless image runs non-root. Compose drops capabilities, enables no-new-privileges and a read-only filesystem, exposes the API only on loopback, and keeps PostgreSQL private. Use <code>cmd/migrate</code> as a separate migration job, then run replicas with <code>MIGRATION_MODE=verify</code>.</p>
            <p>Before a real deployment, follow the <a href={`${repository}/blob/main/docs/deployment.md`}>deployment guide</a>, <a href={`${repository}/blob/main/RELEASE_CHECKLIST.md`}>release checklist</a>, and signing/workload key rotation procedures.</p>
          </section>

          <section id="limits" className="docs-section">
            <h2>Current limits</h2>
            <div className="docs-callout">
              <h3>UpsilonAuth is beta software.</h3>
              <p>It has no independent security assessment or substantial production operating history. Rate limiting and PoP replay caches are instance-local. Revocation snapshots rely on HTTPS rather than independent signatures. Signing-key rotation is operator-managed, and V1 administration uses a static high-entropy bearer credential. The beta does not include an enterprise support SLA.</p>
            </div>
            <p>Maximums include 64 KiB request bodies, 16 KiB JWTs, 64 actions, 64 resources, 256 bytes per action/resource, delegation depth 16, and server-configured lease TTL up to 24 hours. Review all residual risks on the <Link href="/security">security page</Link>.</p>
          </section>

          <footer className="docs-footer">
            <Link href="/">UpsilonAuth</Link>
            <Link href="/security">Security</Link>
            <span>MIT licensed</span>
            <a href={repository} target="_blank" rel="noreferrer">Source on GitHub</a>
          </footer>
        </article>
      </div>
    </main>
  );
}
