"use client";

import {
  ArrowRight,
  ArrowUp,
  Check,
  ChevronRight,
  Code2,
  Copy,
  GitBranch,
  KeyRound,
  Moon,
  ShieldCheck,
  Sun,
  Terminal,
  Timer,
  Workflow,
} from "lucide-react";
import {
  AnimatePresence,
  motion,
  useMotionValueEvent,
  useReducedMotion,
  useScroll,
  type Variants,
} from "framer-motion";
import { useEffect, useRef, useState } from "react";
import clsx from "clsx";
import { AuthorizationDemo } from "@/components/authorization-demo";
import { Brand } from "@/components/brand";

const repository = "https://github.com/yonathanalulam/upsilonAuth";

const quickstart = [
  {
    label: "Start",
    title: "Clone and start the local stack",
    language: "shell",
    code: `git clone https://github.com/yonathanalulam/upsilonAuth.git
cd upsilonAuth
go run ./cmd/keygen > .env

set -a
. ./.env
set +a

docker compose up --build -d
curl --fail http://127.0.0.1:8080/readyz`,
  },
  {
    label: "Register",
    title: "Register a workload and set its grant",
    language: "shell",
    code: `curl -X POST http://127.0.0.1:8080/v1/workloads \\
  -H "Authorization: Bearer $ADMIN_TOKEN" \\
  -H "Content-Type: application/json" \\
  -d '{
    "name": "payments-worker",
    "public_key": "'$WORKLOAD_PUBLIC_KEY'",
    "grant": {
      "audiences": ["service:payments"],
      "actions": ["payments:read", "payments:refund"],
      "resources": ["customer/*"],
      "max_ttl": "5m",
      "max_delegation_depth": 2,
      "can_delegate": true
    }
  }'`,
  },
  {
    label: "Request",
    title: "Request a temporary root lease",
    language: "go",
    code: `control, _ := client.NewControlPlane(
  "http://127.0.0.1:8080", nil, true,
)
signer, _ := client.NewSigner(workloadID, privateKey)

root, err := control.RequestLease(ctx, signer, client.LeaseRequest{
  Audience: "service:payments",
  Actions: []string{"payments:refund"},
  Resources: []string{"customer/*"},
  TTL: "60s",
  MaxDepth: 2,
})`,
  },
  {
    label: "Delegate",
    title: "Delegate a smaller lease to another workload",
    language: "go",
    code: `child, err := control.DelegateLease(
  ctx, signer, root.ID, root.Token,
  client.DelegationRequest{
    DelegateTo: recipientWorkloadID,
    Actions: []string{"payments:refund"},
    Resources: []string{"customer/cus_123"},
    TTL: "30s",
  },
)
// The SDK signs this request as the parent lease's current subject.`,
  },
  {
    label: "Verify",
    title: "Verify the lease in a Gin route",
    language: "go",
    code: `verifier, err := middleware.New(middleware.Config{
    JWKSURL: "https://auth.example/.well-known/jwks.json",
    RevocationsURL: "https://auth.example/.well-known/revocations.json",
    Issuer: "https://auth.example",
    Audience: "service:payments",
    RevocationMode: middleware.RevocationStrict,
})
if err != nil {
    log.Fatal(err)
}

router.POST("/customers/:customerID/refunds",
    verifier.Require("payments:refund", func(c *gin.Context) string {
      return "customer/" + c.Param("customerID")
    }),
    refundHandler,
)`,
  },
  {
    label: "Revoke",
    title: "Revoke the root lease and its children",
    language: "go",
    code: `revoked, err := control.RevokeLease(
  ctx,
  adminToken,
  root.ID,
)
if err != nil {
  return err
}

log.Printf("revoked %d leases", revoked)`,
  },
];

const endpoints = [
  ["POST", "/v1/workloads", "Register a workload and its authority grant"],
  ["GET", "/v1/workloads/:id", "Get a workload and its grant"],
  ["POST", "/v1/workloads/:id/disable", "Disable a workload and revoke its leases"],
  ["POST", "/v1/workloads/:id/rotate-key", "Replace a workload public key"],
  ["POST", "/v1/leases", "Request a root capability lease"],
  ["POST", "/v1/leases/:id/delegate", "Delegate a smaller lease to a workload"],
  ["GET", "/v1/leases/:id", "Get lease metadata and use state"],
  ["GET", "/v1/leases/:id/trace", "Get the lease's delegation path"],
  ["POST", "/v1/leases/:id/revoke", "Revoke a lease and its descendants"],
  ["POST", "/v1/leases/:id/consume", "Consume one use of a finite lease"],
  ["GET", "/v1/audit-events", "List audit events"],
  ["GET", "/.well-known/jwks.json", "Get Ed25519 verification keys"],
  ["GET", "/.well-known/revocations.json", "Get current lease revocations"],
  ["GET", "/healthz", "Check process health"],
  ["GET", "/readyz", "Check database readiness"],
  ["GET", "/metrics", "Get Prometheus metrics"],
];

const reveal: Variants = {
  hidden: { opacity: 0, y: 18 },
  visible: (delay: number = 0) => ({
    opacity: 1,
    y: 0,
    transition: { type: "spring", stiffness: 105, damping: 22, mass: 0.78, delay },
  }),
};

type Theme = "light" | "dark";

function ThemeToggle({ theme, onToggle }: { theme: Theme; onToggle: () => void }) {
  const reduceMotion = useReducedMotion();
  const nextTheme = theme === "dark" ? "light" : "dark";

  return (
    <button
      className="theme-toggle"
      type="button"
      onClick={onToggle}
      aria-label={`Switch to ${nextTheme} mode`}
      title={`Switch to ${nextTheme} mode`}
    >
      <AnimatePresence mode="wait" initial={false}>
        <motion.span
          key={theme}
          initial={reduceMotion ? false : { opacity: 0, rotate: -18, scale: 0.88 }}
          animate={{ opacity: 1, rotate: 0, scale: 1 }}
          exit={reduceMotion ? undefined : { opacity: 0, rotate: 18, scale: 0.88 }}
          transition={{ duration: reduceMotion ? 0 : 0.16 }}
        >
          {theme === "dark" ? <Sun size={16} /> : <Moon size={16} />}
        </motion.span>
      </AnimatePresence>
    </button>
  );
}

function CopyButton({ value, label }: { value: string; label: string }) {
  const [copied, setCopied] = useState(false);
  const reduceMotion = useReducedMotion();

  async function copy() {
    await navigator.clipboard.writeText(value);
    setCopied(true);
    window.setTimeout(() => setCopied(false), 1400);
  }

  return (
    <button className="copy-button" type="button" onClick={copy} aria-label={label} title={label}>
      <AnimatePresence mode="wait" initial={false}>
        <motion.span
          key={copied ? "done" : "copy"}
          initial={reduceMotion ? false : { opacity: 0, scale: 0.9 }}
          animate={{ opacity: 1, scale: 1 }}
          exit={reduceMotion ? undefined : { opacity: 0, scale: 0.9 }}
          transition={{ duration: reduceMotion ? 0 : 0.12 }}
        >
          {copied ? <Check size={15} /> : <Copy size={15} />}
        </motion.span>
      </AnimatePresence>
    </button>
  );
}

function Header({ theme, onThemeToggle }: { theme: Theme; onThemeToggle: () => void }) {
  const { scrollY } = useScroll();
  const reduceMotion = useReducedMotion();
  const [visible, setVisible] = useState(true);
  const [showScrollTop, setShowScrollTop] = useState(false);

  useMotionValueEvent(scrollY, "change", (latest) => {
    const previous = scrollY.getPrevious() ?? latest;
    setShowScrollTop(latest > 400);

    if (latest <= 50) {
      setVisible(true);
      return;
    }

    if (latest > previous) {
      setVisible(false);
      return;
    }

    if (latest < previous) {
      setVisible(true);
    }
  });

  return (
    <>
      <motion.header
        className="site-header"
        initial={false}
        animate={{ y: visible ? "0%" : "-120%" }}
        transition={reduceMotion ? { duration: 0 } : { type: "spring", stiffness: 430, damping: 39 }}
      >
        <div className="nav-inner">
          <Brand href="#top" />
          <nav aria-label="Primary navigation">
            <a href="#why">Why</a>
            <a href="#flow">How it works</a>
            <a href="#demo">Demo</a>
            <a href="#quickstart">Quickstart</a>
            <a href="#security">Security</a>
            <a href="/docs">Docs</a>
          </nav>
          <div className="nav-actions">
            <ThemeToggle theme={theme} onToggle={onThemeToggle} />
            <a className="github-button" href={repository} target="_blank" rel="noreferrer" aria-label="Open UpsilonAuth on GitHub">
              <Code2 size={16} />
              <span>GitHub</span>
            </a>
          </div>
        </div>
      </motion.header>
      <AnimatePresence>
        {showScrollTop && (
          <motion.button
            className="scroll-top"
            type="button"
            aria-label="Scroll to top"
            title="Scroll to top"
            onClick={() => window.scrollTo({ top: 0, behavior: "smooth" })}
            initial={reduceMotion ? false : { opacity: 0, y: 10, scale: 0.94 }}
            animate={{ opacity: 1, y: 0, scale: 1 }}
            exit={reduceMotion ? undefined : { opacity: 0, y: 8, scale: 0.94 }}
            whileHover={reduceMotion ? undefined : { y: -2 }}
            whileTap={reduceMotion ? undefined : { scale: 0.96 }}
            transition={reduceMotion ? { duration: 0 } : { type: "spring", stiffness: 420, damping: 30 }}
          >
            <ArrowUp size={16} />
          </motion.button>
        )}
      </AnimatePresence>
    </>
  );
}

function LeasePreview() {
  const reduceMotion = useReducedMotion();

  return (
    <motion.div
      className="lease-preview"
      initial={false}
      whileInView={{ opacity: 1, y: 0 }}
      viewport={{ once: true, margin: "-40px" }}
      transition={reduceMotion ? { duration: 0 } : { type: "spring", stiffness: 100, damping: 22, delay: 0.14 }}
    >
      <div className="preview-header">
        <span><Terminal size={14} /> Lease issued</span>
        <span className="preview-state"><Check size={12} /> Signed</span>
      </div>
      <div className="preview-body">
        <div className="claim-row">
          <span>audience</span>
          <strong>service:payments</strong>
        </div>
        <div className="claim-row">
          <span>actions</span>
          <strong>payments:refund, payments:read</strong>
        </div>
        <div className="claim-row">
          <span>resources</span>
          <strong>customer/*</strong>
        </div>
        <div className="claim-row claim-row-last">
          <span>expires</span>
          <strong>in 5 minutes</strong>
        </div>
      </div>
      <div className="preview-lineage" aria-label="Lease lineage">
        <div className="lineage-item lineage-item-root"><KeyRound size={15} /><span>Root</span></div>
        <span className="lineage-link" />
        <div className="lineage-item"><ShieldCheck size={15} /><span>Child</span></div>
        <span className="lineage-link" />
        <div className="lineage-item"><ShieldCheck size={15} /><span>Leaf</span></div>
      </div>
    </motion.div>
  );
}

function Hero() {
  const reduceMotion = useReducedMotion();

  return (
    <section className="hero" id="top">
      <div className="hero-inner">
        <motion.div
          className="hero-copy"
          initial={false}
          animate={{ opacity: 1, y: 0 }}
          transition={reduceMotion ? { duration: 0 } : { type: "spring", stiffness: 105, damping: 22 }}
        >
          <h1>Temporary, delegated authority for machine workloads.</h1>
          <p>UpsilonAuth gives machine workloads temporary permissions without relying on long-lived credentials. Services, workers, and automated agents can request scoped capability leases, delegate smaller leases, and verify them inside the services they call.</p>
          <div className="hero-actions">
            <a className="primary-button" href="#quickstart">
              Try out uAuth
              <ArrowRight size={16} />
            </a>
            <a className="text-link" href={repository} target="_blank" rel="noreferrer">
              Read the source
            </a>
          </div>
        </motion.div>
        <LeasePreview />
      </div>
    </section>
  );
}

function Concept() {
  const reduceMotion = useReducedMotion();
  const items = [
    {
      icon: Timer,
      title: "Set a limit for each workload",
      text: "When you register a workload, you set its allowed audiences, actions, resources, maximum TTL, and delegation depth.",
    },
    {
      icon: GitBranch,
      title: "Delegate less authority",
      text: "A workload can pass a smaller lease to another workload. The child cannot add permissions or outlive its parent.",
    },
    {
      icon: ShieldCheck,
      title: "Inspect and revoke the chain",
      text: "Each lease records its parent and root. You can trace that path or revoke a lease together with every child created from it.",
    },
  ];

  return (
    <section className="section concept-section" id="why">
      <motion.div className="section-intro" initial={false} whileInView="visible" viewport={{ once: true, margin: "-60px" }} variants={reveal}>
        <h2>Use temporary permissions instead of shared credentials.</h2>
        <p>UpsilonAuth is an authorization service for machine workloads. It issues capability leases for a specific audience, set of actions, resources, and period of time.</p>
      </motion.div>
      <div className="principles">
        {items.map((item, index) => {
          const Icon = item.icon;
          return (
            <motion.article
              className="principle"
              key={item.title}
              custom={reduceMotion ? 0 : index * 0.07}
              initial={false}
              whileInView="visible"
              viewport={{ once: true, margin: "-50px" }}
              variants={reveal}
            >
              <Icon size={19} />
              <h3>{item.title}</h3>
              <p>{item.text}</p>
            </motion.article>
          );
        })}
      </div>
    </section>
  );
}

function DelegationFlow() {
  const reduceMotion = useReducedMotion();

  return (
    <section className="section flow-section" id="flow">
      <motion.div className="section-intro" initial={false} whileInView="visible" viewport={{ once: true, margin: "-60px" }} variants={reveal}>
        <h2>How authority moves through UpsilonAuth.</h2>
        <p>An administrator sets the workload&apos;s maximum permissions. The workload requests a temporary lease, delegates a smaller lease when needed, and sends that lease to the service it wants to call.</p>
      </motion.div>
      <motion.div
        className="delegation-board"
        initial={false}
        whileInView={{ opacity: 1, y: 0 }}
        viewport={{ once: true, margin: "-50px" }}
        transition={reduceMotion ? { duration: 0 } : { type: "spring", stiffness: 96, damping: 22 }}
      >
        <div className="delegation-stage">
          <div className="stage-heading"><KeyRound size={17} /><span>Workload grant</span></div>
          <strong>refund / read</strong>
          <span>customer/*</span>
          <small>admin policy - max 5m</small>
        </div>
        <div className="flow-connector"><ChevronRight size={18} /><span>issue</span></div>
        <div className="delegation-stage">
          <div className="stage-heading"><Workflow size={17} /><span>Root lease</span></div>
          <strong>refund / read</strong>
          <span>customer/*</span>
          <small>payments-worker - 2m</small>
        </div>
        <div className="flow-connector"><ChevronRight size={18} /><span>attenuate</span></div>
        <div className="delegation-stage">
          <div className="stage-heading"><GitBranch size={17} /><span>Delegated lease</span></div>
          <strong>refund</strong>
          <span>customer/cus_123</span>
          <small>refund-job - 30s</small>
        </div>
        <div className="flow-connector"><ChevronRight size={18} /><span>verify</span></div>
        <div className="delegation-stage delegation-stage-last">
          <div className="stage-heading"><ShieldCheck size={17} /><span>Protected service</span></div>
          <strong>refund</strong>
          <span>customer/cus_123</span>
          <small>aud service:payments</small>
        </div>
      </motion.div>
      <motion.div className="guardrail" initial={false} whileInView="visible" viewport={{ once: true, margin: "-40px" }} variants={reveal}>
        <ShieldCheck size={17} />
        <p>A delegated lease can remove actions, narrow resources, shorten its lifetime, add constraints, or stop further delegation. It cannot add authority that its parent did not have.</p>
      </motion.div>
    </section>
  );
}

function ProductFit() {
  return (
    <section className="section fit-section" id="fit">
      <motion.div className="section-intro" initial={false} whileInView="visible" viewport={{ once: true, margin: "-60px" }} variants={reveal}>
        <h2>Where UpsilonAuth fits.</h2>
        <p>Human authentication systems answer who a person is. UpsilonAuth focuses on what an automated workload is temporarily allowed to do.</p>
      </motion.div>
      <div className="fit-grid">
        <motion.article initial={false} whileInView="visible" viewport={{ once: true }} variants={reveal}>
          <h3>Use it for machine workloads</h3>
          <p>UpsilonAuth is built for services, background workers, CI/CD jobs, serverless functions, pipelines, MCP servers, agents, and other internal automation.</p>
        </motion.article>
        <motion.article initial={false} whileInView="visible" viewport={{ once: true }} variants={reveal}>
          <h3>Use other tools for human identity</h3>
          <p>UpsilonAuth is not a human authentication provider, OAuth or Auth0 replacement, secrets manager, API gateway, complete IAM system, or general-purpose policy engine.</p>
        </motion.article>
      </div>
    </section>
  );
}

function Quickstart() {
  const [active, setActive] = useState(0);
  const reduceMotion = useReducedMotion();
  const selected = quickstart[active];

  return (
    <section className="section quickstart-section" id="quickstart">
      <motion.div className="section-intro" initial={false} whileInView="visible" viewport={{ once: true, margin: "-60px" }} variants={reveal}>
        <h2>Run a complete local example.</h2>
        <p>You need Git, Go 1.26 or newer, and Docker with Compose v2. The steps below start PostgreSQL and UpsilonAuth, register a workload, request and delegate a lease, verify it in Gin, and revoke it.</p>
      </motion.div>
      <motion.div
        className="quickstart-workbench"
        initial={false}
        whileInView={{ opacity: 1, y: 0 }}
        viewport={{ once: true, margin: "-50px" }}
        transition={reduceMotion ? { duration: 0 } : { type: "spring", stiffness: 96, damping: 22 }}
      >
        <div className="step-tabs" role="tablist" aria-label="Quickstart steps">
          {quickstart.map((step, index) => (
            <button
              className={clsx("step-tab", index === active && "is-active")}
              key={step.label}
              type="button"
              role="tab"
              aria-selected={index === active}
              onClick={() => setActive(index)}
            >
              <span>{index + 1}</span>
              {step.label}
              {index === active && <motion.i layoutId="active-tab" transition={reduceMotion ? { duration: 0 } : { type: "spring", stiffness: 420, damping: 35 }} />}
            </button>
          ))}
        </div>
        <div className="code-heading">
          <div>
            <span>{selected.language}</span>
            <strong>{selected.title}</strong>
          </div>
          <CopyButton value={selected.code} label={`Copy ${selected.title}`} />
        </div>
        <div className="code-body" role="tabpanel">
          <AnimatePresence mode="wait">
            <motion.pre
              key={active}
              initial={reduceMotion ? false : { opacity: 0, y: 6, filter: "blur(2px)" }}
              animate={{ opacity: 1, y: 0, filter: "blur(0px)" }}
              exit={reduceMotion ? undefined : { opacity: 0, y: -4, filter: "blur(2px)" }}
              transition={{ duration: reduceMotion ? 0 : 0.18 }}
            >
              <code>{selected.code}</code>
            </motion.pre>
          </AnimatePresence>
        </div>
      </motion.div>
    </section>
  );
}

function Reference() {
  const [copiedEndpoint, setCopiedEndpoint] = useState<string | null>(null);
  const copyTimer = useRef<number | null>(null);
  const reduceMotion = useReducedMotion();

  useEffect(() => {
    return () => {
      if (copyTimer.current !== null) {
        window.clearTimeout(copyTimer.current);
      }
    };
  }, []);

  async function copyEndpoint(path: string) {
    await navigator.clipboard.writeText(path);
    setCopiedEndpoint(path);

    if (copyTimer.current !== null) {
      window.clearTimeout(copyTimer.current);
    }

    copyTimer.current = window.setTimeout(() => {
      setCopiedEndpoint(null);
      copyTimer.current = null;
    }, 2000);
  }

  return (
    <section className="section reference-section">
      <motion.div className="section-intro" initial={false} whileInView="visible" viewport={{ once: true, margin: "-60px" }} variants={reveal}>
        <h2>HTTP API</h2>
        <p>Admin calls manage workloads and leases. Workloads sign lease requests with Ed25519. Protected services fetch public verification and revocation data.</p>
      </motion.div>
      <div className="endpoint-list">
        {endpoints.map(([method, path, description], index) => (
          <motion.button
            className={clsx("endpoint-row", copiedEndpoint === path && "is-copied")}
            key={path}
            type="button"
            aria-label={`Copy endpoint ${path}`}
            title={`Copy ${path}`}
            onClick={() => copyEndpoint(path)}
            custom={index * 0.05}
            initial={false}
            whileInView="visible"
            viewport={{ once: true, margin: "-30px" }}
            variants={reveal}
          >
            <span className="endpoint-method">{method}</span>
            <code>{path}</code>
            <span>{description}</span>
            <AnimatePresence mode="wait" initial={false}>
              <motion.span
                className="endpoint-feedback"
                key={copiedEndpoint === path ? "copied" : "copy"}
                initial={reduceMotion ? false : { opacity: 0, scale: 0.9 }}
                animate={{ opacity: 1, scale: 1 }}
                exit={reduceMotion ? undefined : { opacity: 0, scale: 0.9 }}
                transition={{ duration: reduceMotion ? 0 : 0.14 }}
              >
                {copiedEndpoint === path ? <Check size={16} /> : <ArrowRight size={16} />}
              </motion.span>
            </AnimatePresence>
          </motion.button>
        ))}
      </div>
    </section>
  );
}

function Protocol() {
  const reduceMotion = useReducedMotion();
  const steps = [
    ["01", "Register a workload", "Store the workload's Ed25519 public key. The private key stays with the workload."],
    ["02", "Set its maximum permissions", "Define the audiences, actions, resources, TTL, and delegation rules the workload may request."],
    ["03", "Request a lease", "The workload signs its request. UpsilonAuth checks the signature, timestamp, nonce, and authority grant."],
    ["04", "Delegate when needed", "The current lease holder signs a request for a smaller lease and names the workload that will receive it."],
    ["05", "Verify inside the service", "The Gin middleware checks the signature, issuer, audience, time, action, resource, constraints, and configured revocation mode."],
  ];
  return (
    <section className="section protocol-section" id="protocol">
      <motion.div className="section-intro" initial={false} whileInView="visible" viewport={{ once: true, margin: "-60px" }} variants={reveal}>
        <h2>The request flow, step by step.</h2>
        <p>Registration sets the upper bound. Signed requests create leases. Protected services verify those leases before running application code.</p>
      </motion.div>
      <div className="protocol-steps">
        {steps.map(([number, title, text], index) => (
          <motion.article
            className="protocol-step"
            key={number}
            custom={reduceMotion ? 0 : index * 0.07}
            initial={false}
            whileInView="visible"
            viewport={{ once: true, margin: "-50px" }}
            variants={reveal}
          >
            <span className="protocol-number">{number}</span>
            <h3>{title}</h3>
            <p>{text}</p>
          </motion.article>
        ))}
      </div>
      <motion.div className="protocol-contract" initial={false} whileInView={{ opacity: 1, y: 0 }} viewport={{ once: true, margin: "-50px" }} transition={reduceMotion ? { duration: 0 } : { type: "spring", stiffness: 96, damping: 22 }}>
        <div className="protocol-contract-heading">
          <span>Signed request contract</span>
          <code>SHA-256</code>
        </div>
        <pre><code>{`POST
/v1/leases
1700000000
nonce-from-workload
hex(sha256(request_body))`}</code></pre>
        <p>The workload signs this input with Ed25519. UpsilonAuth rejects a reused nonce, a timestamp outside the configured window, or a request whose path or body no longer matches the signature.</p>
      </motion.div>
    </section>
  );
}

function SecuritySnapshot() {
  const controls = [
    {
      label: "LOCAL",
      title: "Signed requests and leases",
      text: "Workloads sign lease requests with Ed25519. Services verify Ed25519 lease signatures, token type and version, issuer, audience, expiration, actions, resources, and constraints.",
    },
    {
      label: "OPTIONAL",
      title: "Bearer or proof of possession",
      text: "Bearer leases require the token. PoP leases also require a DPoP-style proof from the workload key bound to that token.",
    },
    {
      label: "STATEFUL",
      title: "Revocation and finite uses",
      text: "Revocation checks follow the configured STRICT, BOUNDED_STALE, or EXPIRY_ONLY mode. Finite-use leases call UpsilonAuth for an atomic, idempotent use count.",
    },
  ];

  return (
    <section className="section security-section" id="security">
      <motion.div className="section-intro" initial={false} whileInView="visible" viewport={{ once: true, margin: "-60px" }} variants={reveal}>
        <h2>Security behavior</h2>
        <p>Services perform signature and claim checks locally. Revocation freshness and finite-use counters require shared state, so their availability rules are configured separately.</p>
      </motion.div>
      <div className="security-grid">
        {controls.map((control, index) => (
          <motion.article key={control.title} custom={index * 0.06} initial={false} whileInView="visible" viewport={{ once: true }} variants={reveal}>
            <span>{control.label}</span>
            <h3>{control.title}</h3>
            <p>{control.text}</p>
          </motion.article>
        ))}
      </div>
      <motion.div className="status-panel" initial={false} whileInView="visible" viewport={{ once: true }} variants={reveal}>
        <div>
          <h3>Current status: beta</h3>
          <p>UpsilonAuth is currently in beta. It is designed for developer evaluation and controlled deployments. It has automated security tests, but it has not had an independent security audit or substantial production use.</p>
        </div>
        <div className="status-links">
          <a href="/security">Read the security model <ArrowRight size={15} /></a>
          <a href={`${repository}/blob/main/THREAT_MODEL.md`} target="_blank" rel="noreferrer">Open the threat model <ArrowRight size={15} /></a>
        </div>
      </motion.div>
    </section>
  );
}

function Footer() {
  return (
    <footer className="footer">
      <div>
        <Brand href="#top" />
        <p>Temporary authorization for machine workloads.</p>
      </div>
      <div className="footer-links">
        <a href="/security">Security</a>
        <a href="/docs">Documentation</a>
        <a href={`${repository}/blob/main/LICENSE`} target="_blank" rel="noreferrer">MIT License</a>
        <a href={repository} target="_blank" rel="noreferrer">GitHub</a>
        <span>Yonathan Alula</span>
      </div>
    </footer>
  );
}

export function LandingPage() {
  const [theme, setTheme] = useState<Theme>("dark");

  useEffect(() => {
    const frame = window.requestAnimationFrame(() => {
      const stored = window.localStorage.getItem("upsilonauth-theme") as Theme | null;
      const preferred = window.matchMedia("(prefers-color-scheme: light)").matches ? "light" : "dark";
      const initial = stored ?? preferred;
      setTheme(initial);
      document.documentElement.dataset.theme = initial;
    });

    return () => window.cancelAnimationFrame(frame);
  }, []);

  function toggleTheme() {
    const next = theme === "dark" ? "light" : "dark";
    setTheme(next);
    document.documentElement.dataset.theme = next;
    window.localStorage.setItem("upsilonauth-theme", next);
  }

  return (
    <main>
      <Header theme={theme} onThemeToggle={toggleTheme} />
      <Hero />
      <AuthorizationDemo />
      <Concept />
      <DelegationFlow />
      <ProductFit />
      <Quickstart />
      <Reference />
      <Protocol />
      <SecuritySnapshot />
      <Footer />
    </main>
  );
}
