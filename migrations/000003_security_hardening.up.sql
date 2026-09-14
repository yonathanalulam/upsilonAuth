ALTER TABLE workloads ADD COLUMN disabled_at TIMESTAMPTZ;
ALTER TABLE workloads ADD CONSTRAINT workloads_name_length_check CHECK (char_length(name) BETWEEN 3 AND 128);
ALTER TABLE workloads ADD CONSTRAINT workloads_public_key_unique UNIQUE (public_key);

ALTER TABLE leases ADD CONSTRAINT leases_actions_count_check CHECK (jsonb_array_length(actions) BETWEEN 1 AND 64);
ALTER TABLE leases ADD CONSTRAINT leases_resources_count_check CHECK (jsonb_array_length(resources) BETWEEN 1 AND 64);
ALTER TABLE leases ADD CONSTRAINT leases_audience_length_check CHECK (char_length(audience) BETWEEN 1 AND 256);
ALTER TABLE leases ADD CONSTRAINT leases_depth_limit_check CHECK (max_depth <= 16);

ALTER TABLE audit_events ADD CONSTRAINT audit_events_type_not_empty CHECK (event_type <> '');
ALTER TABLE audit_events ADD CONSTRAINT audit_events_actor_not_empty CHECK (actor <> '');

CREATE TABLE workload_nonces (
    workload_id UUID NOT NULL REFERENCES workloads(id) ON DELETE CASCADE,
    nonce_hash BYTEA NOT NULL CHECK (octet_length(nonce_hash) = 32),
    expires_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (workload_id, nonce_hash)
);

CREATE INDEX workload_nonces_expires_at_idx ON workload_nonces (expires_at);
CREATE INDEX leases_active_revocations_idx ON leases (expires_at, id) WHERE revoked_at IS NOT NULL;
