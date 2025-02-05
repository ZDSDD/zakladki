-- name: GetUserByProvider :one
SELECT u.* 
FROM user_auth_provider up
JOIN users u on u.id = up.user_id
WHERE $1 = up.provider AND $2 = up.provider_user_id;

-- name: CreateUserWithProvider :one

INSERT INTO user_auth_provider (user_id, provider_user_id, provider)
VALUES($1, $2, $3) RETURNING *;

