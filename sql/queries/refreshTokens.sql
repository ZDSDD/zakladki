-- name: GetRefreshToken :one
SELECT
    *
FROM
    refresh_tokens
WHERE
    token = $1;

-- name: GetRefreshTokenForUser :one
SELECT
    *
FROM
    refresh_tokens
WHERE
    user_id = $1;

-- name: CreateRefreshToken :one
INSERT INTO
    refresh_tokens (
        token,
        created_at,
        updated_at,
        user_id,
        expires_at
    )
VALUES
    ($1, NOW(), NOW(), $2, $3) RETURNING *;

-- name: RevokeRefreshToken :exec
UPDATE
    refresh_tokens
SET
    revoked_at = NOW(),
    updated_at = NOW()
WHERE
    token = $1;

-- name: PurgeRefreshTokens :exec
DELETE FROM
    refresh_tokens;

-- name: PurgeRevokedToknes :exec
DELETE FROM
    refresh_tokens
WHERE
    revoked_at IS NOT NULL;

-- name: UpdateExpiresAtRefreshToken :one
UPDATE refresh_tokens
SET updated_at=NOW(),
    expires_at=$1
WHERE user_id=$2
RETURNING *;