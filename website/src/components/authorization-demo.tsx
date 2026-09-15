"use client";

import {
  ArrowDown,
  Check,
  Fingerprint,
  Globe2,
  ShieldX,
  Workflow,
  type LucideIcon,
} from "lucide-react";
import { AnimatePresence, motion, useReducedMotion } from "framer-motion";
import { useState } from "react";
import clsx from "clsx";

type DecisionName = "allowed" | "restricted";

type Workload = {
  name: string;
  id: string;
  lease: string;
  authorityLabel: string;
  actions: string[];
  icon: LucideIcon;
  removedAfter?: string;
};

const workloads: Workload[] = [
  {
    name: "Orchestrator",
    id: "workload:orchestrator",
    lease: "Root lease · expires in 5m",
    authorityLabel: "Allowed",
    actions: ["web:read", "documents:write", "email:send"],
    icon: Fingerprint,
    removedAfter: "email:send",
  },
  {
    name: "Research Agent",
    id: "workload:research-agent",
    lease: "Delegated lease · expires in 2m",
    authorityLabel: "Delegated",
    actions: ["web:read", "documents:write"],
    icon: Workflow,
    removedAfter: "documents:write",
  },
  {
    name: "Browser Worker",
    id: "workload:browser-worker",
    lease: "Delegated lease · expires in 30s",
    authorityLabel: "Delegated",
    actions: ["web:read"],
    icon: Globe2,
  },
];

const decisions = {
  allowed: {
    status: "ALLOW",
    action: "web:read",
    workload: "browser-worker",
    resource: "example.com",
    reason: "Capability was delegated to this workload.",
  },
  restricted: {
    status: "DENY",
    action: "database:delete",
    workload: "browser-worker",
    resource: "primary-database",
    reason: "Permission was never delegated.",
  },
} as const;

const middlewareExample = `router.GET("/browse",
  verifier.Require(
    "web:read",
    "example.com",
  ),
  browserHandler,
)`;

export function AuthorizationDemo() {
  const [selection, setSelection] = useState<DecisionName>("allowed");
  const reduceMotion = useReducedMotion();
  const decision = decisions[selection];
  const direction = selection === "restricted" ? 1 : -1;

  return (
    <section
      className="section demo-section"
      id="demo"
      aria-labelledby="demo-heading"
    >
      <motion.div
        className="section-intro"
        initial={reduceMotion ? false : { opacity: 0, transform: "translateY(14px)" }}
        whileInView={{ opacity: 1, transform: "translateY(0px)" }}
        viewport={{ once: true, margin: "-60px" }}
        transition={reduceMotion ? { duration: 0 } : { duration: 0.64, ease: [0.23, 1, 0.32, 1] }}
      >
        <h2 id="demo-heading">See delegation in action.</h2>
        <p>This frontend-only interactive example shows how a capability gets smaller as it moves between workloads. Choose a request to see the decision a protected service would make.</p>
      </motion.div>

      <motion.div
        className="demo-workspace"
        initial={reduceMotion ? false : { opacity: 0, transform: "translateY(14px)" }}
        whileInView={{ opacity: 1, transform: "translateY(0px)" }}
        viewport={{ once: true, margin: "-40px" }}
        transition={reduceMotion ? { duration: 0 } : { duration: 0.7, delay: 0.06, ease: [0.23, 1, 0.32, 1] }}
      >
        <div className="demo-lineage" aria-label="Delegation chain">
          <div className="demo-panel-heading">
            <strong>Capability lineage</strong>
            <span>Illustrative leases</span>
          </div>

          <div className="demo-workload-chain">
            {workloads.map((workload, index) => {
              const Icon = workload.icon;

              return (
                <div key={workload.id}>
                  <article className={clsx("demo-workload", index === workloads.length - 1 && "is-current")}>
                    <div className="demo-workload-header">
                      <span className="demo-workload-icon"><Icon size={17} aria-hidden="true" /></span>
                      <div>
                        <h3>{workload.name}</h3>
                        <code>{workload.id}</code>
                      </div>
                    </div>
                    <div className="demo-workload-meta">
                      <span>{workload.authorityLabel}</span>
                      <small>{workload.lease}</small>
                    </div>
                    <ul className="demo-permissions" aria-label={`${workload.name} permissions`}>
                      {workload.actions.map((action) => <li key={action}><code>{action}</code></li>)}
                    </ul>
                  </article>

                  {workload.removedAfter && (
                    <div className="demo-delegation-link" aria-label={`${workload.removedAfter} removed during delegation`}>
                      <span className="demo-delegation-track"><ArrowDown size={15} aria-hidden="true" /></span>
                      <p>Delegate smaller lease <code>{workload.removedAfter}</code> removed</p>
                    </div>
                  )}
                </div>
              );
            })}
          </div>

          <p className="demo-invariant">
            Browser Worker authority ⊆ Research Agent authority ⊆ Orchestrator authority
          </p>
        </div>

        <div className="demo-console">
          <div className="demo-controls">
            <div className="demo-panel-heading">
              <strong>Request</strong>
              <span>Evaluated as browser-worker</span>
            </div>
            <div className="demo-action-buttons" aria-label="Example authorization requests">
              <button
                className={clsx(selection === "allowed" && "is-active")}
                type="button"
                aria-pressed={selection === "allowed"}
                onClick={() => setSelection("allowed")}
              >
                {selection === "allowed" && (
                  <motion.i
                    className="demo-active-indicator"
                    layoutId="active-request"
                    transition={reduceMotion ? { duration: 0 } : { duration: 0.24, ease: [0.77, 0, 0.175, 1] }}
                  />
                )}
                <span>Run allowed request</span>
                <code>web:read</code>
              </button>
              <button
                className={clsx(selection === "restricted" && "is-active")}
                type="button"
                aria-pressed={selection === "restricted"}
                onClick={() => setSelection("restricted")}
              >
                {selection === "restricted" && (
                  <motion.i
                    className="demo-active-indicator"
                    layoutId="active-request"
                    transition={reduceMotion ? { duration: 0 } : { duration: 0.24, ease: [0.77, 0, 0.175, 1] }}
                  />
                )}
                <span>Attempt restricted action</span>
                <code>database:delete</code>
              </button>
            </div>
          </div>

          <div className="demo-decision" aria-live="polite" aria-atomic="true">
            <div className="demo-decision-heading">
              <strong>Authorization decision</strong>
              <span>Interactive example</span>
            </div>
            <AnimatePresence mode="wait" initial={false}>
              <motion.div
                className="demo-decision-result"
                key={selection}
                role="status"
                initial={reduceMotion ? false : { opacity: 0, transform: `translateX(${direction * 9}px)` }}
                animate={{ opacity: 1, transform: "translateX(0px)" }}
                exit={reduceMotion ? undefined : { opacity: 0, transform: `translateX(${direction * -6}px)` }}
                transition={{ duration: reduceMotion ? 0 : 0.22, ease: [0.77, 0, 0.175, 1] }}
              >
                <div className={clsx("demo-decision-status", decision.status === "ALLOW" ? "is-allow" : "is-deny")}>
                  {decision.status === "ALLOW" ? <Check size={17} aria-hidden="true" /> : <ShieldX size={17} aria-hidden="true" />}
                  {decision.status}
                </div>
                <dl>
                  <div><dt>Action</dt><dd><code>{decision.action}</code></dd></div>
                  <div><dt>Workload</dt><dd><code>{decision.workload}</code></dd></div>
                  <div><dt>Resource</dt><dd><code>{decision.resource}</code></dd></div>
                  <div><dt>Reason</dt><dd>{decision.reason}</dd></div>
                  <div><dt>Granted actions</dt><dd><code>web:read</code></dd></div>
                </dl>
              </motion.div>
            </AnimatePresence>
          </div>

          <div className="demo-code">
            <div className="demo-code-heading">
              <strong>Gin middleware</strong>
              <code>protected route</code>
            </div>
            <pre><code>{middlewareExample}</code></pre>
            <p>The middleware checks the token&apos;s audience, action, and resource before <code>browserHandler</code> runs.</p>
          </div>
        </div>
      </motion.div>
    </section>
  );
}
