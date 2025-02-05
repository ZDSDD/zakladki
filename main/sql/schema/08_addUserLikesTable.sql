-- +goose Up
CREATE TABLE users_bookmarks_likes (
    user_id UUID NOT NULL,
    bookmark_id INTEGER NOT NULL,
    is_liked BOOLEAN DEFAULT TRUE,
    reaction_type VARCHAR(50),  -- Optional, for different reactions
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (user_id, bookmark_id),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (bookmark_id) REFERENCES bookmarks(id) ON DELETE CASCADE
);

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION trigger_set_timestamp()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE TRIGGER set_timestamp
BEFORE UPDATE ON users_bookmarks_likes
FOR EACH ROW
EXECUTE FUNCTION trigger_set_timestamp();
-- +goose StatementEnd

-- +goose Down
-- Drop the trigger first
DROP TRIGGER IF EXISTS set_timestamp ON users_bookmarks_likes;

-- +goose StatementBegin
DROP FUNCTION IF EXISTS trigger_set_timestamp;
-- +goose StatementEnd

-- Drop the table
DROP TABLE IF EXISTS users_bookmarks_likes;
