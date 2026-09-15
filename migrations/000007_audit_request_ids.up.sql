ALTER TABLE audit_events ADD COLUMN request_id TEXT;
ALTER TABLE audit_events ADD CONSTRAINT audit_events_request_id_check CHECK (
    request_id IS NULL OR (char_length(request_id) BETWEEN 16 AND 64 AND request_id ~ '^[A-Za-z0-9_-]+$')
);
CREATE INDEX audit_events_request_id_idx ON audit_events (request_id) WHERE request_id IS NOT NULL;
