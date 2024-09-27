-- +goose Up
ALTER TABLE users ADD CONSTRAINT u_email_unique UNIQUE (email);

-- +goose Down
ALTER TABLE users DROP CONSTRAINT u_email_unique;
