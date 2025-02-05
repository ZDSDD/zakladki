package bookmarks

import (
	"fmt"
	"net/http"

	"github.com/go-chi/chi"
	"github.com/zdsdd/zakladki/internal/database"
	"github.com/zdsdd/zakladki/internal/jsonUtils"
)

type BookmarksHandler struct {
	db         *database.Queries
	CDNBaseURL string
}

func NewBookmarksHandler(db *database.Queries, CDNBaseUrl string) *BookmarksHandler {
	return &BookmarksHandler{db: db, CDNBaseURL: CDNBaseUrl}
}

func (bh *BookmarksHandler) BookmarksRouter() http.Handler {
	mux := chi.NewRouter()
	mux.Get("/", bh.HandleGetBookmarks)
	return mux
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
