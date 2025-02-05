-- name: GetActiveBookmarks :many
SELECT
    b.id,
    b.name,
    available_amount,
    size,
    price,
    material,
    c.name as category,
    b.description,
    image_url,
    b.created_at,
    b.updated_at,
    b.is_active
FROM
    bookmarks b
    JOIN bookmark_category c ON b.category_id = c.id
WHERE
    b.is_active = TRUE
ORDER BY
    b.created_at DESC;

-- name: GetBookmarkById :one
SELECT
    b.id,
    b.name,
    available_amount,
    size,
    price,
    material,
    c.name,
    description,
    image_url,
    b.created_at,
    b.updated_at,
    b.is_active
FROM
    bookmarks b
    JOIN bookmark_category c ON b.category_id = c.id
WHERE
    b.id = $1;