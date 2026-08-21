-- Add identity-provider fields to the target users table.
-- Adjust the table/column names if the target project uses a different user schema.
ALTER TABLE users ADD COLUMN IF NOT EXISTS google_id TEXT UNIQUE;
ALTER TABLE users ADD COLUMN IF NOT EXISTS apple_id TEXT UNIQUE;
ALTER TABLE users ADD COLUMN IF NOT EXISTS auth_provider TEXT;
ALTER TABLE users ADD COLUMN IF NOT EXISTS avatar_url TEXT;