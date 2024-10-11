package bookmarks

import (
	"net/http"
	"strings"

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
	mux.Get("/images", getImageHandler)
	return mux
}

func (bh *BookmarksHandler) HandleGetBookmarks(w http.ResponseWriter, r *http.Request) {
	bookmarks, err := bh.db.GetActiveBookmarks(r.Context())
	if err != nil {
		jsonUtils.RespondWithJsonError(w, err.Error(), 500)
		return
	}
	jsonUtils.ResponseWithJson(bookmarks, w, http.StatusOK)
}

// Handler to fetch a specific image based on its name
func getImageHandler(w http.ResponseWriter, r *http.Request) {
	imageName := r.URL.Query().Get("name")

	if imageName == "" {
		http.Error(w, "Image name is required", http.StatusBadRequest)
		return
	}

	// Enforcing case insensitivity for image names
	imageName = strings.ToLower(imageName)

	// Construct the file path
	filePath := "./images/" + imageName + ".jpg" // Assuming images are .jpg

	// Serve the image
	http.ServeFile(w, r, filePath)
}
