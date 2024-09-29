-- name: CreateUser :one
INSERT INTO
    users (
        id,
        created_at,
        updated_at,
        email,
        hashed_password
    )
VALUES
    (
        gen_random_uuid(),
        NOW(),
        NOW(),
        $1,
        $2
    ) RETURNING *;

-- name: PurgeUsers :exec
DELETE FROM
    users;

-- name: GetUserById :one
SELECT
    users.*
FROM
    users
WHERE
    id = $1;

-- name: GetUserByEmail :one
SELECT
    users.*
FROM
    users
WHERE
    email = $1;

-- name: UpdateUser :one
UPDATE
    users
SET
    email = $1,
    hashed_password = $2,
    updated_at = NOW()
WHERE
    id = $3
RETURNING *;

-- name: UpdateUserEmail :one
UPDATE
    users
SET
    email = $1,
    updated_at = NOW()
WHERE
    id = $2
RETURNING *;

-- name: UpdateUserPassword :one
UPDATE
    users
SET
    hashed_password = $1,
    updated_at = NOW()
WHERE
    id = $2
RETURNING *;

-- name: UpdateUserRole :one
UPDATE
    users
SET
    role = $1,
    updated_at = NOW()
WHERE
    id = $2
RETURNING *;
