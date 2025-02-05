-- +goose Up
ALTER TABLE users
    ALTER COLUMN hashed_password DROP NOT NULL,
    ALTER COLUMN email DROP NOT NULL,
    ADD COLUMN email_verified BOOLEAN NOT NULL DEFAULT FALSE;

CREATE TYPE auth_provider AS ENUM ('google', 'facebook');

CREATE TABLE user_auth_provider(
    user_id UUID NOT NULL,
    provider_user_id VARCHAR(255) NOT NULL,
    provider auth_provider NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP NOT NULL DEFAULT NOW(),
    CONSTRAINT user_auth_pk PRIMARY KEY (user_id, provider_user_id),
    CONSTRAINT provider_provider_uid_q UNIQUE(provider_user_id, provider),
    CONSTRAINT user_auth_fk FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- +goose Down
DROP TABLE user_auth_provider;
DROP TYPE auth_provider;

ALTER TABLE users
    ALTER COLUMN hashed_password SET NOT NULL,
    ALTER COLUMN email SET NOT NULL,
    DROP COLUMN email_verified;
