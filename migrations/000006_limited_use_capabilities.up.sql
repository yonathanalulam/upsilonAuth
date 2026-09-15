ALTER TABLE workloads ADD COLUMN max_uses INTEGER NOT NULL DEFAULT 0;
ALTER TABLE workloads ADD CONSTRAINT workloads_max_uses_check CHECK (max_uses BETWEEN 0 AND 1000000);

ALTER TABLE leases ADD COLUMN max_uses INTEGER NOT NULL DEFAULT 0;
ALTER TABLE leases ADD COLUMN uses_consumed INTEGER NOT NULL DEFAULT 0;
ALTER TABLE leases ADD CONSTRAINT leases_max_uses_check CHECK (max_uses BETWEEN 0 AND 1000000);
ALTER TABLE leases ADD CONSTRAINT leases_uses_consumed_check CHECK (
    uses_consumed >= 0
    AND ((max_uses = 0 AND uses_consumed = 0) OR (max_uses > 0 AND uses_consumed <= max_uses))
);
ALTER TABLE leases ADD CONSTRAINT leases_limited_use_no_delegation_check CHECK (max_uses = 0 OR max_depth = depth);

CREATE TABLE lease_consumptions (
    lease_id UUID NOT NULL REFERENCES leases(id) ON DELETE RESTRICT,
    idempotency_key TEXT NOT NULL CHECK (char_length(idempotency_key) BETWEEN 16 AND 128),
    use_number INTEGER NOT NULL CHECK (use_number > 0),
    consumed_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (lease_id, idempotency_key),
    UNIQUE (lease_id, use_number)
);

CREATE INDEX lease_consumptions_consumed_at_idx ON lease_consumptions (consumed_at DESC);
