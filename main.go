package main

import (
	"database/sql"
	"log"
	"net/http"
	"os"
	"sync/atomic"
	"time"

	"github.com/go-chi/chi"
	"github.com/go-chi/chi/middleware"
	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
	"github.com/zdsdd/zakladki/internal/bookmarks"
	"github.com/zdsdd/zakladki/internal/database"
	"github.com/zdsdd/zakladki/internal/users"
)

func main() {
	r := chi.NewRouter()
	r.Use(middleware.Logger)

	// A good base middleware stack
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(middleware.Timeout(60 * time.Second))

	godotenv.Load()
	port := getEnvVariable("PORT")
	dbURL := getEnvVariable("DB_URL")
	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		log.Fatalf("Error opening database: %s", err)
		os.Exit(1)
	}
	dbQueries := database.New(db)

	cfg := &apiConfig{
		fileserverHits:     atomic.Int32{},
		db:                 dbQueries,
		jwtSecret:          getEnvVariable("JWT_SECRET"),
		minPasswordEntropy: 60.0,
	}
	server := http.Server{
		Handler: r,
		Addr:    ":" + port,
	}

	// api router
	apiRouter := chi.NewRouter()
	apiRouter.Use(cfg.middlewareMetricsInc)

	// User-related routes
	userHandler := users.NewUserHandler(dbQueries, cfg.jwtSecret, cfg.minPasswordEntropy)
	apiRouter.Mount("/users", userHandler.UsersRouter())

	// Health check and metrics routes
	apiRouter.Get("/healthz", handleHealthz)
	apiRouter.Get("/metrics", cfg.handleMetrics)
	r.Mount("/api", apiRouter)

	r.Handle("/app/", cfg.middlewareMetricsInc(http.StripPrefix("/app/", http.FileServer(http.Dir(".")))))

	// Admin-related routes
	r.Mount("/admin", cfg.adminRouter(userHandler))

	// bookmarks related routes
	bh := bookmarks.NewBookmarksHandler(dbQueries)
	r.Mount("/bookmarks", bh.BookmarksRouter())
	log.Printf("Server running successfully on port: %s\n", port)
	log.Fatal(server.ListenAndServe())
}

func (cfg *apiConfig) adminRouter(uh *users.UsersHandler) http.Handler {
	r := chi.NewRouter()
	r.Use(cfg.middlewareMetricsInc)
	// r.Use(uh.RequireValidJWTToken) // Move JWT validation before AdminOnly
	r.Use(uh.AdminOnly)
	r.Post("/reset", cfg.handleReset)
	r.Get("/metrics", cfg.handleAdminMetrics)
	return r
}

func handleHealthz(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK\n"))
}

func getEnvVariable(key string) string {
	err := godotenv.Load(".env")
	if err != nil {
		log.Fatalf("Error loading .env file")
	}
	return os.Getenv(key)
}
