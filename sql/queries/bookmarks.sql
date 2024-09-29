-- name: GetBookmarks :many
SELECT
    *
FROM
    bookmarks
WHERE
    is_active = TRUE
ORDER BY
    created_at DESC;