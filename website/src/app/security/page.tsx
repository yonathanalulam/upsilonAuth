import Link from "next/link";
import { Brand } from "@/components/brand";

const repository = "https://github.com/yonathanalulam/upsilonAuth";

export const metadata = {
  title: "UpsilonAuth",
  description: "How UpsilonAuth signs, delegates, verifies, and revokes capability leases.",
};

const sections = [
  ["trust", "Trust boundaries"],
  ["tokens", "Tokens & proof"],
  ["delegation", "Delegation"],
  ["revocation", "Revocation"],
  ["keys", "Keys & replay"],
  ["limits", "Limitations"],
] as const;

export default function SecurityPage() {
  return (
    <main className="docs-page">
      <header className="docs-header">
        <Brand />
        <div className="docs-header-links">
          <Link href="/docs">Documentation</Link>
          <Link href="/">Home</Link>
          <a href={repository} target="_blank" rel="noreferrer">GitHub</a>
        </div>
      </header>

      <div className="docs-layout">
        <aside className="docs-sidebar">
          <strong>Security model</strong>
          {sections.map(([id, label]) => <a key={id} href={`#${id}`}>{label}</a>)}
        </aside>

        <article className="docs-content">
          <h1>How UpsilonAuth checks authority.</h1>
          <p className="docs-lead">This page covers the checks performed by the control plane and Go middleware, the settings that affect availability, and the risks that remain.</p>

          <section id="trust" className="docs-section">
            <h2>What you need to protect</h2>
            <p>Keep PostgreSQL, the server signing key, admin and consumption credentials, workload private keys, and configured metadata endpoints protected. Each protected service should accept one configured issuer and an exact audience intended for that service.</p>
            <p>Human administrator login is separate from machine authorization. This beta uses high-entropy bearer credentials for the admin and finite-use consumption APIs. If you build a management UI, add a normal human login system such as OIDC or SSO without changing how workload leases are verified.</p>
          </section>

          <section id="tokens" className="docs-section">
            <h2>Signed workload requests and lease tokens</h2>
            <p>Workloads sign lease requests with Ed25519. UpsilonAuth issues Ed25519 JWS/JWT-style tokens with <code>typ=upsilon-lease+jwt</code>, schema version 1, a key ID, issuer, one audience, current and root workload, subject, time claims, a unique JTI, lease lineage IDs, depth, actions, and canonical resources. The parser rejects the wrong type, version, or algorithm; unknown or duplicate claims; missing values; the wrong issuer or audience; invalid times; and tokens larger than 16 KiB.</p>
            <div className="docs-table compact">
              <div className="docs-table-row"><strong>Bearer</strong><p>Possession of a valid JWT is sufficient. Use TLS, narrowly scoped authority, and short TTLs.</p></div>
              <div className="docs-table-row"><strong>PoP</strong><p>The token carries an Ed25519 JWK thumbprint in <code>cnf.jkt</code>. Each request also needs a fresh DPoP-style proof over method, URL, and token hash.</p></div>
            </div>
            <p>Proof of possession helps when an attacker steals only the token. It does not help if the attacker also steals the bound private key.</p>
          </section>

          <section id="delegation" className="docs-section">
            <h2>Delegation rules</h2>
            <p>When an administrator registers a workload, they also set its authority grant. Before issuing a root lease, UpsilonAuth checks the active workload, the exact key used to sign the request, the current grant version, and the requested authority in one transaction. A delegation request must include the parent JWT, a signature from the parent lease&apos;s current subject, and an active <code>delegate_to</code> workload.</p>
            <pre><code>{`Authority(child)
  ⊆ Authority(parent)
  ⊆ Authority(root lease)
  ⊆ Authority(workload grant)`}</code></pre>
            <p>A child cannot add actions, broaden resources or audiences, extend expiration, increase depth, regain delegation, weaken constraints, or restore removed permissions. Resources can be exact values or bounded prefixes ending in <code>{"/*"}</code>. UpsilonAuth rejects encoded traversal, ambiguous percent encoding, duplicate separators, backslashes, non-NFC Unicode, and malformed wildcards.</p>
          </section>

          <section id="revocation" className="docs-section">
            <h2>Revocation and use counts</h2>
            <p>Revoking a lease also revokes its descendants. Disabling a workload blocks new signed requests and revokes the leases it currently holds, including their children. Choose a revocation mode based on how your service should behave when it cannot refresh revocation data:</p>
            <div className="docs-table compact">
              <div className="docs-table-row"><code>STRICT</code><p>Use cached data for the refresh interval. If a refresh is due and unavailable, deny the request.</p></div>
              <div className="docs-table-row"><code>BOUNDED_STALE</code><p>Keep using the last good snapshot until it reaches the configured maximum age, then deny.</p></div>
              <div className="docs-table-row"><code>EXPIRY_ONLY</code><p>Skip live revocation checks and rely on short lease expiration.</p></div>
            </div>
            <p>The revocation feed supports ETags and refreshes every 30 seconds by default, so a revoked lease may remain accepted until a verifier refreshes. Finite <code>max_uses</code> values are checked with an atomic PostgreSQL call and an idempotency key. They cannot be enforced by local JWT verification alone, and the verifier fails closed if that call is unavailable.</p>
          </section>

          <section id="keys" className="docs-section">
            <h2>Key rotation and replay protection</h2>
            <p>The JWKS endpoint publishes the active verification key and any previous key still in its overlap period. During normal server-key rotation, keep the old public key available for the longest token lifetime plus clock skew and propagation time. During emergency rotation, remove it immediately and revoke affected lease chains. Signing keys can be loaded from mounted secret files and are never returned by the API.</p>
            <p>Workload key rotation supports an overlap of up to 24 hours, or immediate retirement with optional revocation of outstanding leases. Root and delegation signatures cover the HTTP method, escaped path, timestamp, one-time nonce, and SHA-256 body digest. UpsilonAuth also checks stored token hashes, lease IDs, parent IDs, subjects, and database claims before accepting a parent lease.</p>
          </section>

          <section id="limits" className="docs-section">
            <h2>Current limitations</h2>
            <div className="docs-callout">
              <h3>UpsilonAuth is currently in beta.</h3>
              <p>It is intended for developer evaluation and controlled deployments. It has not had an independent security audit or substantial production use. Rate limits and PoP replay caches are process-local. Revocation snapshots use HTTPS but are not separately signed. Signing-key rotation is operator-managed, V1 administration uses a static high-entropy bearer credential, and the beta has no enterprise support SLA. Container base images are version-pinned but not digest-pinned.</p>
            </div>
            <p>An attacker with the server signing key can mint leases until verifiers stop trusting that key. An attacker with database access can change grants and revocation state. A stolen workload private key can sign requests until you rotate the key or disable the workload. Verifiers may use stale revocation data within the selected mode. Isolate keys, keep TTLs short, use small grants and PoP where appropriate, monitor the service, and rehearse key rotation.</p>
            <p>Read the full <a href={`${repository}/blob/main/THREAT_MODEL.md`}>threat model</a>, <a href={`${repository}/blob/main/SECURITY.md`}>security policy and compromise guidance</a>, and <a href={`${repository}/blob/main/SECURITY_AUDIT.md`}>pre-remediation audit</a>.</p>
          </section>

          <footer className="docs-footer">
            <Link href="/">UpsilonAuth</Link>
            <Link href="/docs">Developer guide</Link>
            <a href={`${repository}/blob/main/THREAT_MODEL.md`}>Threat model</a>
          </footer>
        </article>
      </div>
    </main>
  );
}
