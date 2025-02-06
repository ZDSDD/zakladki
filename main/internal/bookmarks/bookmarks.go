package bookmarks

import (
	"fmt"
	"net/http"
	"strconv"

	"github.com/go-chi/chi"
	"github.com/google/uuid"
	"github.com/zdsdd/zakladki/internal/database"
	"github.com/zdsdd/zakladki/internal/jsonUtils"
	"github.com/zdsdd/zakladki/internal/users"
)

type BookmarksHandler struct {
	db         *database.Queries
	CDNBaseURL string
}

type LikesHandler struct {
	uh *users.UsersHandler
	bh *BookmarksHandler
}

func NewLikesHandler(bh *BookmarksHandler, uh *users.UsersHandler) *LikesHandler {
	return &LikesHandler{bh: bh, uh: uh}
}

func (lh *LikesHandler) LikesRouter() http.Handler {
	mux := chi.NewRouter()
	mux.Get("/{user_id}", lh.HandleGetLikesForUser)
	mux.Post("/{bookmark_id}", lh.uh.RequireValidJWTToken(http.HandlerFunc(lh.HandleLike)))
	mux.Post("/unlike/{bookmark_id}", lh.uh.RequireValidJWTToken(http.HandlerFunc(lh.HandleUnlike)))
	return mux
}

func NewBookmarksHandler(db *database.Queries, CDNBaseUrl string) *BookmarksHandler {
	return &BookmarksHandler{db: db, CDNBaseURL: CDNBaseUrl}
}

func (bh *BookmarksHandler) BookmarksRouter() http.Handler {
	mux := chi.NewRouter()
	mux.Get("/", bh.HandleGetBookmarks)
	return mux
}
func (lh *LikesHandler) getUserAndBookmarkID(r *http.Request) (uuid.UUID, int32, error) {
	userID, err := users.GetUserIDFromContext(r)
	if err != nil {
		return uuid.UUID{}, 0, err
	}
	bookmarkIDStr := chi.URLParam(r, "bookmark_id")
	bookmarkIDInt, err := strconv.Atoi(bookmarkIDStr)
	if err != nil {
		return uuid.UUID{}, 0, err
	}
	return userID, int32(bookmarkIDInt), nil
}
func (lh *LikesHandler) HandleUnlike(w http.ResponseWriter, r *http.Request) {
	userID, bookmarkID, err := lh.getUserAndBookmarkID(r)
	if err != nil {
		jsonUtils.RespondWithJsonError(w, "Invalid user or bookmark ID", http.StatusBadRequest)
		return
	}
	err = lh.bh.db.UnlikeBookmark(r.Context(), database.UnlikeBookmarkParams{
		UserID:     userID,
		BookmarkID: bookmarkID,
	})
	if err != nil {
		jsonUtils.RespondWithJsonError(w, err.Error(), 500)
		return
	}
	jsonUtils.ResponseWithJson("Success", w, http.StatusOK)
}
func (lh *LikesHandler) HandleGetLikesForUser(w http.ResponseWriter, r *http.Request) {
	userID, err := uuid.Parse(chi.URLParam(r, "user_id"))
	if err != nil {
		jsonUtils.RespondWithJsonError(w, "Invalid user ID", http.StatusBadRequest)
		return
	}
	bookmarks, err := lh.bh.db.GetUserBookmarksLikes(r.Context(), userID)
	if err != nil {
		jsonUtils.RespondWithJsonError(w, err.Error(), 500)
		return
	}
	jsonUtils.ResponseWithJson(bookmarks, w, http.StatusOK)
}

func (lh *LikesHandler) HandleLike(w http.ResponseWriter, r *http.Request) {
	userID, bookmarkID, err := lh.getUserAndBookmarkID(r)
	if err != nil {
		jsonUtils.RespondWithJsonError(w, "Invalid user or bookmark ID", 400)
		return
	}

	// Check if the bookmark is already liked by the user
	_, err = lh.bh.db.GetLike(r.Context(), database.GetLikeParams{
		UserID:     userID,
		BookmarkID: bookmarkID,
	})
	if err != nil && err.Error() != "sql: no rows in result set" {
		jsonUtils.RespondWithJsonError(w, err.Error(), 500)
		return
	}

	if err == nil {
		// Update the like flag if the bookmark is already liked
		_, err = lh.bh.db.UpdateBookmarkLike(r.Context(), database.UpdateBookmarkLikeParams{
			UserID:     userID,
			BookmarkID: bookmarkID,
			IsLiked:    true,
		})
		if err != nil {
			jsonUtils.RespondWithJsonError(w, err.Error(), 500)
			return
		}
	} else {
		// Insert a new like if the bookmark is not already liked
		_, err = lh.bh.db.LikeBookmark(r.Context(), database.LikeBookmarkParams{
			UserID:     userID,
			BookmarkID: bookmarkID,
		})
		if err != nil {
			jsonUtils.RespondWithJsonError(w, err.Error(), 500)
			return
		}
	}

	jsonUtils.ResponseWithJson("Success", w, http.StatusOK)
}

func (bh *BookmarksHandler) HandleGetBookmarks(w http.ResponseWriter, r *http.Request) {
	bookmarks, err := bh.db.GetActiveBookmarks(r.Context())
	if err != nil {
		jsonUtils.RespondWithJsonError(w, err.Error(), 500)
		return
	}
	for i, v := range bookmarks {
		bookmarks[i].ImageUrl = fmt.Sprintf("%s/%s", bh.CDNBaseURL, v.ImageUrl)
	}
	jsonUtils.ResponseWithJson(bookmarks, w, http.StatusOK)
}
