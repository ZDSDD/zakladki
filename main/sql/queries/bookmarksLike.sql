-- name: GetUserBookmarksLikes :many

SELECT bookmarks.* FROM bookmarks INNER JOIN
users_bookmarks_likes ON bookmarks.id = users_bookmarks_likes.bookmark_id
WHERE users_bookmarks_likes.user_id = $1 AND users_bookmarks_likes.is_liked = TRUE;

-- name: LikeBookmark :one

INSERT INTO users_bookmarks_likes (user_id, bookmark_id, is_liked, reaction_type)
VALUES ($1, $2, TRUE, $3)
RETURNING *;

-- name: UnlikeBookmark :exec

UPDATE users_bookmarks_likes
SET is_liked = FALSE
WHERE user_id = $1 AND bookmark_id = $2
RETURNING *;