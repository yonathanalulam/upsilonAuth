DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM leases WHERE workload_id IS NULL) THEN
        RAISE EXCEPTION 'cannot enforce non-null lease ownership: existing leases have no workload';
    END IF;
END $$;

ALTER TABLE leases ALTER COLUMN workload_id SET NOT NULL;
