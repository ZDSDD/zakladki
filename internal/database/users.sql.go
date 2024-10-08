// Code generated by sqlc. DO NOT EDIT.
// versions:
//   sqlc v1.27.0
// source: users.sql

package database

import (
	"context"

	"github.com/google/uuid"
)

const createUser = `-- name: CreateUser :one
INSERT INTO
    users (
        id,
        created_at,
        updated_at,
        email,
        hashed_password,
        name
    )
VALUES
    (
        gen_random_uuid(),
        NOW(),
        NOW(),
        $1,
        $2,
        $3
    ) RETURNING id, email, hashed_password, created_at, updated_at, role, name
`

type CreateUserParams struct {
	Email          string
	HashedPassword string
	Name           string
}

func (q *Queries) CreateUser(ctx context.Context, arg CreateUserParams) (User, error) {
	row := q.db.QueryRowContext(ctx, createUser, arg.Email, arg.HashedPassword, arg.Name)
	var i User
	err := row.Scan(
		&i.ID,
		&i.Email,
		&i.HashedPassword,
		&i.CreatedAt,
		&i.UpdatedAt,
		&i.Role,
		&i.Name,
	)
	return i, err
}

const getUserByEmail = `-- name: GetUserByEmail :one
SELECT
    users.id, users.email, users.hashed_password, users.created_at, users.updated_at, users.role, users.name
FROM
    users
WHERE
    email = $1
`

func (q *Queries) GetUserByEmail(ctx context.Context, email string) (User, error) {
	row := q.db.QueryRowContext(ctx, getUserByEmail, email)
	var i User
	err := row.Scan(
		&i.ID,
		&i.Email,
		&i.HashedPassword,
		&i.CreatedAt,
		&i.UpdatedAt,
		&i.Role,
		&i.Name,
	)
	return i, err
}

const getUserById = `-- name: GetUserById :one
SELECT
    users.id, users.email, users.hashed_password, users.created_at, users.updated_at, users.role, users.name
FROM
    users
WHERE
    id = $1
`

func (q *Queries) GetUserById(ctx context.Context, id uuid.UUID) (User, error) {
	row := q.db.QueryRowContext(ctx, getUserById, id)
	var i User
	err := row.Scan(
		&i.ID,
		&i.Email,
		&i.HashedPassword,
		&i.CreatedAt,
		&i.UpdatedAt,
		&i.Role,
		&i.Name,
	)
	return i, err
}

const purgeUsers = `-- name: PurgeUsers :exec
DELETE FROM
    users
`

func (q *Queries) PurgeUsers(ctx context.Context) error {
	_, err := q.db.ExecContext(ctx, purgeUsers)
	return err
}

const updateUser = `-- name: UpdateUser :one
UPDATE
    users
SET
    email = $1,
    hashed_password = $2,
    updated_at = NOW()
WHERE
    id = $3
RETURNING id, email, hashed_password, created_at, updated_at, role, name
`

type UpdateUserParams struct {
	Email          string
	HashedPassword string
	ID             uuid.UUID
}

func (q *Queries) UpdateUser(ctx context.Context, arg UpdateUserParams) (User, error) {
	row := q.db.QueryRowContext(ctx, updateUser, arg.Email, arg.HashedPassword, arg.ID)
	var i User
	err := row.Scan(
		&i.ID,
		&i.Email,
		&i.HashedPassword,
		&i.CreatedAt,
		&i.UpdatedAt,
		&i.Role,
		&i.Name,
	)
	return i, err
}

const updateUserEmail = `-- name: UpdateUserEmail :one
UPDATE
    users
SET
    email = $1,
    updated_at = NOW()
WHERE
    id = $2
RETURNING id, email, hashed_password, created_at, updated_at, role, name
`

type UpdateUserEmailParams struct {
	Email string
	ID    uuid.UUID
}

func (q *Queries) UpdateUserEmail(ctx context.Context, arg UpdateUserEmailParams) (User, error) {
	row := q.db.QueryRowContext(ctx, updateUserEmail, arg.Email, arg.ID)
	var i User
	err := row.Scan(
		&i.ID,
		&i.Email,
		&i.HashedPassword,
		&i.CreatedAt,
		&i.UpdatedAt,
		&i.Role,
		&i.Name,
	)
	return i, err
}

// #nosec G101: False positive - No hardcoded credentials
const updateUserPassword = `-- name: UpdateUserPassword :one
UPDATE
    users
SET
    hashed_password = $1,
    updated_at = NOW()
WHERE
    id = $2
RETURNING id, email, hashed_password, created_at, updated_at, role, name
`

type UpdateUserPasswordParams struct {
	HashedPassword string
	ID             uuid.UUID
}

func (q *Queries) UpdateUserPassword(ctx context.Context, arg UpdateUserPasswordParams) (User, error) {
	row := q.db.QueryRowContext(ctx, updateUserPassword, arg.HashedPassword, arg.ID)
	var i User
	err := row.Scan(
		&i.ID,
		&i.Email,
		&i.HashedPassword,
		&i.CreatedAt,
		&i.UpdatedAt,
		&i.Role,
		&i.Name,
	)
	return i, err
}

const updateUserRole = `-- name: UpdateUserRole :one
UPDATE
    users
SET
    role = $1,
    updated_at = NOW()
WHERE
    id = $2
RETURNING id, email, hashed_password, created_at, updated_at, role, name
`

type UpdateUserRoleParams struct {
	Role int32
	ID   uuid.UUID
}

func (q *Queries) UpdateUserRole(ctx context.Context, arg UpdateUserRoleParams) (User, error) {
	row := q.db.QueryRowContext(ctx, updateUserRole, arg.Role, arg.ID)
	var i User
	err := row.Scan(
		&i.ID,
		&i.Email,
		&i.HashedPassword,
		&i.CreatedAt,
		&i.UpdatedAt,
		&i.Role,
		&i.Name,
	)
	return i, err
}
