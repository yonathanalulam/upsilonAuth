ALTER TABLE workloads ADD COLUMN grant_constraints JSONB NOT NULL DEFAULT '{}'::JSONB;
ALTER TABLE workloads ADD CONSTRAINT workloads_grant_constraints_check CHECK (
    jsonb_typeof(grant_constraints) = 'object'
);

ALTER TABLE leases ADD COLUMN constraints JSONB NOT NULL DEFAULT '{}'::JSONB;
ALTER TABLE leases ADD CONSTRAINT leases_constraints_check CHECK (
    jsonb_typeof(constraints) = 'object'
);
