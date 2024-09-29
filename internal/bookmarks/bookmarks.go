package bookmarks

import (
	"net/http"

	"github.com/go-chi/chi"
	"github.com/zdsdd/zakladki/internal/database"
	"github.com/zdsdd/zakladki/internal/jsonUtils"
)

type BookmarksHandler struct {
	db *database.Queries
}

func NewBookmarksHandler(db *database.Queries) *BookmarksHandler {
	return &BookmarksHandler{db: db}
}

func (bh *BookmarksHandler) BookmarksRouter() http.Handler {
	mux := chi.NewRouter()
	mux.Get("/", bh.HandleGetBookmarks)
	return mux
}

func (bh *BookmarksHandler) HandleGetBookmarks(w http.ResponseWriter, r *http.Request) {
	bookmarks, err := bh.db.GetBookmarks(r.Context())
	if err != nil {
		jsonUtils.ResponseWithJsonError(w, err.Error(), 500)
		return
	}
	jsonUtils.ResponseWithJson(bookmarks, w, http.StatusOK)
}
