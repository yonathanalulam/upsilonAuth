DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM workloads) THEN
        RAISE EXCEPTION 'workload grants cannot be inferred safely; export and re-enroll existing workloads with explicit grants before applying 000005';
    END IF;
END $$;

ALTER TABLE workloads ADD COLUMN allowed_audiences JSONB NOT NULL;
ALTER TABLE workloads ADD COLUMN allowed_actions JSONB NOT NULL;
ALTER TABLE workloads ADD COLUMN allowed_resources JSONB NOT NULL;
ALTER TABLE workloads ADD COLUMN max_ttl_seconds BIGINT NOT NULL;
ALTER TABLE workloads ADD COLUMN max_delegation_depth INTEGER NOT NULL;
ALTER TABLE workloads ADD COLUMN can_delegate BOOLEAN NOT NULL;
ALTER TABLE workloads ADD COLUMN require_proof_of_possession BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE workloads ADD COLUMN grant_version BIGINT NOT NULL DEFAULT 1;
ALTER TABLE workloads ADD COLUMN previous_public_key BYTEA;
ALTER TABLE workloads ADD COLUMN previous_key_expires_at TIMESTAMPTZ;

ALTER TABLE workloads ADD CONSTRAINT workloads_allowed_audiences_check CHECK (jsonb_typeof(allowed_audiences) = 'array' AND jsonb_array_length(allowed_audiences) BETWEEN 1 AND 16);
ALTER TABLE workloads ADD CONSTRAINT workloads_allowed_actions_check CHECK (jsonb_typeof(allowed_actions) = 'array' AND jsonb_array_length(allowed_actions) BETWEEN 1 AND 64);
ALTER TABLE workloads ADD CONSTRAINT workloads_allowed_resources_check CHECK (jsonb_typeof(allowed_resources) = 'array' AND jsonb_array_length(allowed_resources) BETWEEN 1 AND 64);
ALTER TABLE workloads ADD CONSTRAINT workloads_max_ttl_check CHECK (max_ttl_seconds BETWEEN 1 AND 86400);
ALTER TABLE workloads ADD CONSTRAINT workloads_max_delegation_depth_check CHECK (max_delegation_depth BETWEEN 0 AND 16);
ALTER TABLE workloads ADD CONSTRAINT workloads_delegation_consistency_check CHECK (can_delegate OR max_delegation_depth = 0);
ALTER TABLE workloads ADD CONSTRAINT workloads_grant_version_check CHECK (grant_version > 0);
ALTER TABLE workloads ADD CONSTRAINT workloads_previous_key_check CHECK (
    (previous_public_key IS NULL AND previous_key_expires_at IS NULL)
    OR
    (octet_length(previous_public_key) = 32 AND previous_key_expires_at IS NOT NULL)
);
CREATE UNIQUE INDEX workloads_previous_public_key_unique ON workloads (previous_public_key) WHERE previous_public_key IS NOT NULL;

ALTER TABLE leases ADD COLUMN token_id UUID NOT NULL;
ALTER TABLE leases ADD COLUMN root_workload_id UUID NOT NULL REFERENCES workloads(id) ON DELETE RESTRICT;
ALTER TABLE leases ADD COLUMN root_lease_id UUID NOT NULL REFERENCES leases(id) ON DELETE RESTRICT DEFERRABLE INITIALLY IMMEDIATE;
ALTER TABLE leases ADD COLUMN delegated_by_workload_id UUID REFERENCES workloads(id) ON DELETE RESTRICT;
ALTER TABLE leases ADD COLUMN grant_version BIGINT NOT NULL;
ALTER TABLE leases ADD COLUMN confirmation_thumbprint TEXT;

ALTER TABLE leases ADD CONSTRAINT leases_token_id_unique UNIQUE (token_id);
ALTER TABLE leases ADD CONSTRAINT leases_grant_version_check CHECK (grant_version > 0);
ALTER TABLE leases ADD CONSTRAINT leases_confirmation_thumbprint_check CHECK (confirmation_thumbprint IS NULL OR char_length(confirmation_thumbprint) = 43);
ALTER TABLE leases ADD CONSTRAINT leases_lineage_identity_check CHECK (
    (parent_lease_id IS NULL AND depth = 0 AND root_lease_id = id AND root_workload_id = workload_id AND delegated_by_workload_id IS NULL)
    OR
    (parent_lease_id IS NOT NULL AND depth > 0 AND delegated_by_workload_id IS NOT NULL)
);

CREATE INDEX leases_root_lease_id_idx ON leases (root_lease_id);
CREATE INDEX leases_root_workload_id_idx ON leases (root_workload_id);
CREATE INDEX leases_delegated_by_workload_id_idx ON leases (delegated_by_workload_id) WHERE delegated_by_workload_id IS NOT NULL;
