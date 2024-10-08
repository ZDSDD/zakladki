// Code generated by sqlc. DO NOT EDIT.
// versions:
//   sqlc v1.27.0
// source: refreshTokens.sql

package database

import (
	"context"
	"time"

	"github.com/google/uuid"
)
// #nosec G101: False positive - No hardcoded credentials
const createRefreshToken = `-- name: CreateRefreshToken :one
INSERT INTO
    refresh_tokens (
        token,
        created_at,
        updated_at,
        user_id,
        expires_at
    )
VALUES
    ($1, NOW(), NOW(), $2, $3) RETURNING token, created_at, updated_at, user_id, expires_at, revoked_at
`

type CreateRefreshTokenParams struct {
	Token     string
	UserID    uuid.UUID
	ExpiresAt time.Time
}

func (q *Queries) CreateRefreshToken(ctx context.Context, arg CreateRefreshTokenParams) (RefreshToken, error) {
	row := q.db.QueryRowContext(ctx, createRefreshToken, arg.Token, arg.UserID, arg.ExpiresAt)
	var i RefreshToken
	err := row.Scan(
		&i.Token,
		&i.CreatedAt,
		&i.UpdatedAt,
		&i.UserID,
		&i.ExpiresAt,
		&i.RevokedAt,
	)
	return i, err
}
// #nosec G101: False positive - No hardcoded credentials
const getRefreshToken = `-- name: GetRefreshToken :one
SELECT
    token, created_at, updated_at, user_id, expires_at, revoked_at
FROM
    refresh_tokens
WHERE
    token = $1
`

func (q *Queries) GetRefreshToken(ctx context.Context, token string) (RefreshToken, error) {
	row := q.db.QueryRowContext(ctx, getRefreshToken, token)
	var i RefreshToken
	err := row.Scan(
		&i.Token,
		&i.CreatedAt,
		&i.UpdatedAt,
		&i.UserID,
		&i.ExpiresAt,
		&i.RevokedAt,
	)
	return i, err
}
// #nosec G101: False positive - No hardcoded credentials
const getRefreshTokenForUser = `-- name: GetRefreshTokenForUser :one
SELECT
    token, created_at, updated_at, user_id, expires_at, revoked_at
FROM
    refresh_tokens
WHERE
    user_id = $1
`

func (q *Queries) GetRefreshTokenForUser(ctx context.Context, userID uuid.UUID) (RefreshToken, error) {
	row := q.db.QueryRowContext(ctx, getRefreshTokenForUser, userID)
	var i RefreshToken
	err := row.Scan(
		&i.Token,
		&i.CreatedAt,
		&i.UpdatedAt,
		&i.UserID,
		&i.ExpiresAt,
		&i.RevokedAt,
	)
	return i, err
}
// #nosec G101: False positive - No hardcoded credentials
const purgeRefreshTokens = `-- name: PurgeRefreshTokens :exec
DELETE FROM
    refresh_tokens
`

func (q *Queries) PurgeRefreshTokens(ctx context.Context) error {
	_, err := q.db.ExecContext(ctx, purgeRefreshTokens)
	return err
}
// #nosec G101: False positive - No hardcoded credentials
const purgeRevokedToknes = `-- name: PurgeRevokedToknes :exec
DELETE FROM
    refresh_tokens
WHERE
    revoked_at IS NOT NULL
`

func (q *Queries) PurgeRevokedToknes(ctx context.Context) error {
	_, err := q.db.ExecContext(ctx, purgeRevokedToknes)
	return err
}
// #nosec G101: False positive - No hardcoded credentials
const revokeRefreshToken = `-- name: RevokeRefreshToken :exec
UPDATE
    refresh_tokens
SET
    revoked_at = NOW(),
    updated_at = NOW()
WHERE
    token = $1
`

func (q *Queries) RevokeRefreshToken(ctx context.Context, token string) error {
	_, err := q.db.ExecContext(ctx, revokeRefreshToken, token)
	return err
}
// #nosec G101: False positive - No hardcoded credentials
const updateExpiresAtRefreshToken = `-- name: UpdateExpiresAtRefreshToken :one
UPDATE refresh_tokens
SET updated_at=NOW(),
    expires_at=$1
WHERE user_id=$2
RETURNING token, created_at, updated_at, user_id, expires_at, revoked_at
`

type UpdateExpiresAtRefreshTokenParams struct {
	ExpiresAt time.Time
	UserID    uuid.UUID
}

func (q *Queries) UpdateExpiresAtRefreshToken(ctx context.Context, arg UpdateExpiresAtRefreshTokenParams) (RefreshToken, error) {
	row := q.db.QueryRowContext(ctx, updateExpiresAtRefreshToken, arg.ExpiresAt, arg.UserID)
	var i RefreshToken
	err := row.Scan(
		&i.Token,
		&i.CreatedAt,
		&i.UpdatedAt,
		&i.UserID,
		&i.ExpiresAt,
		&i.RevokedAt,
	)
	return i, err
}
