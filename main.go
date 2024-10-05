package main

import (
	"database/sql"
	"log"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"github.com/go-chi/chi"
	"github.com/go-chi/chi/middleware"
	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
	"github.com/rs/cors"
	"github.com/zdsdd/zakladki/internal/bookmarks"
	"github.com/zdsdd/zakladki/internal/database"
	"github.com/zdsdd/zakladki/internal/users"
)

func main() {
	err := godotenv.Load("app.env")
	if err != nil {
		log.Fatalf("Error loading .env file")
	}
	r := chi.NewRouter()
	r.Use(middleware.Logger)

	// A good base middleware stack
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(middleware.Timeout(60 * time.Second))
	var allowedOrigins []string
	allowedOrigins = strings.Split(os.Getenv("ALLOWED_ORIGINS"), ", ")
	if allowedOrigins == nil {
		allowedOrigins = []string{"http://localhost:5173"}
	}
	log.Default().Printf("Allowed origins: %v\n", allowedOrigins)
	c := cors.New(cors.Options{
		// AllowedOrigins:   []string{"https://foo.com"}, // Use this to allow specific origin hosts
		AllowedOrigins: allowedOrigins,
		// AllowOriginFunc:  func(r *http.Request, origin string) bool { return true },
		AllowedMethods:   []string{"GET", "POST", "PUT", "OPTIONS"},
		AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type", "X-CSRF-Token"},
		ExposedHeaders:   []string{"Link", "Content-Length"},
		AllowCredentials: true,
		MaxAge:           300, // Maximum value not ignored by any of major browsers
	})
	r.Use(c.Handler)
	r.Handle("/images/*", http.StripPrefix("/images/", http.FileServer(http.Dir("./images"))))
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

	// bookmarks related routes
	bh := bookmarks.NewBookmarksHandler(dbQueries)
	apiRouter.Mount("/bookmarks", bh.BookmarksRouter())
	// Health check and metrics routes
	apiRouter.Get("/healthz", handleHealthz)
	apiRouter.Get("/metrics", cfg.handleMetrics)
	r.Mount("/api", apiRouter)

	r.Handle("/app/", cfg.middlewareMetricsInc(http.StripPrefix("/app/", http.FileServer(http.Dir(".")))))

	// Admin-related routes
	r.Mount("/admin", cfg.adminRouter(userHandler))

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
	err := godotenv.Load("app.env")
	if err != nil {
		log.Fatalf("Error loading .env file")
	}
	return os.Getenv(key)
}
