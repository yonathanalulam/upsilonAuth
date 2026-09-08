ALTER TABLE leases ALTER COLUMN workload_id DROP NOT NULL;
ALTER TABLE leases ADD COLUMN audience TEXT NOT NULL DEFAULT 'legacy';
ALTER TABLE leases ALTER COLUMN audience DROP DEFAULT;
ALTER TABLE leases ADD COLUMN max_depth INTEGER;
UPDATE leases SET max_depth = depth;
ALTER TABLE leases ALTER COLUMN max_depth SET NOT NULL;
ALTER TABLE leases ALTER COLUMN max_depth SET DEFAULT 0;
ALTER TABLE leases ADD CONSTRAINT leases_max_depth_check CHECK (max_depth >= depth);
ALTER TABLE leases ADD CONSTRAINT leases_audience_not_empty CHECK (audience <> '');
