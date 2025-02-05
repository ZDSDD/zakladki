-- +goose Up
ALTER TABLE users
ADD COLUMN role INTEGER NOT NULL DEFAULT 1;

-- +goose Down

ALTER TABLE users
DROP COLUMN role;