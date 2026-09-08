CREATE TABLE workloads (
    id UUID PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    public_key BYTEA NOT NULL CHECK (octet_length(public_key) = 32),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE leases (
    id UUID PRIMARY KEY,
    workload_id UUID NOT NULL REFERENCES workloads(id) ON DELETE RESTRICT,
    parent_lease_id UUID REFERENCES leases(id) ON DELETE RESTRICT,
    actions JSONB NOT NULL CHECK (jsonb_typeof(actions) = 'array'),
    resources JSONB NOT NULL CHECK (jsonb_typeof(resources) = 'array'),
    expires_at TIMESTAMPTZ NOT NULL,
    depth INTEGER NOT NULL CHECK (depth >= 0),
    token_hash BYTEA NOT NULL UNIQUE CHECK (octet_length(token_hash) = 32),
    issued_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    revoked_at TIMESTAMPTZ,
    CHECK (expires_at > issued_at),
    CHECK ((parent_lease_id IS NULL AND depth = 0) OR (parent_lease_id IS NOT NULL AND depth > 0))
);

CREATE INDEX leases_parent_lease_id_idx ON leases (parent_lease_id) WHERE parent_lease_id IS NOT NULL;
CREATE INDEX leases_workload_id_idx ON leases (workload_id);
CREATE INDEX leases_expires_at_idx ON leases (expires_at);

CREATE TABLE audit_events (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    workload_id UUID REFERENCES workloads(id) ON DELETE SET NULL,
    lease_id UUID REFERENCES leases(id) ON DELETE SET NULL,
    event_type TEXT NOT NULL,
    actor TEXT NOT NULL,
    details JSONB NOT NULL DEFAULT '{}'::JSONB CHECK (jsonb_typeof(details) = 'object'),
    occurred_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX audit_events_workload_id_occurred_at_idx ON audit_events (workload_id, occurred_at DESC);
CREATE INDEX audit_events_lease_id_occurred_at_idx ON audit_events (lease_id, occurred_at DESC);
CREATE INDEX audit_events_occurred_at_idx ON audit_events (occurred_at DESC);
