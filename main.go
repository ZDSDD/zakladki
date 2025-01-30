package main

import (
	"database/sql"
	"fmt"
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
	"github.com/zdsdd/zakladki/internal/jsonUtils"
	"github.com/zdsdd/zakladki/internal/users"
)

func init() {
	// Load .env only once at startup (ignore error in production)
	err := godotenv.Load(".env")
	if err != nil {
		log.Println("Warning: .env file not found, relying on environment variables")
	}
}

// Safe function to get env variables with a fallback
func getEnvVariable(key, fallback string) string {
	value := os.Getenv(key)
	if value == "" {
		return fallback
	}
	return value
}

func main() {
	// init() is called implicitly
	r := chi.NewRouter()
	r.Use(middleware.Logger)

	// A good base middleware stack
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(middleware.Timeout(60 * time.Second))

	allowedOrigins := strings.Split(os.Getenv("ALLOWED_ORIGINS"), ",")
	if len(allowedOrigins) == 0 || allowedOrigins[0] == "" {
		allowedOrigins = []string{"http://localhost:5173"} // Default for local development
	}

	log.Printf("Allowed origins: %v\n", allowedOrigins)

	corsDebugMode := getEnvVariable("CORS_DEBUG", "false") == "true"
	c := cors.New(cors.Options{
		AllowedOrigins: allowedOrigins,
		AllowedMethods: []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		Debug:          corsDebugMode,
		MaxAge:         300,
	})

	r.Use(c.Handler)
	r.Handle("/images/*", http.StripPrefix("/images/", http.FileServer(http.Dir("./images"))))
	port := getEnvVariable("PORT", "8080")
	dbURL := getEnvVariable("DB_URL", "")
	if dbURL == "" {
		log.Fatal("Missing required environment variable: DB_URL")
	}
	fmt.Printf("DB URL: %v\n", dbURL)
	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		log.Fatalf("Error opening database: %s", err)
		os.Exit(1)
	}
	defer db.Close()
	dbQueries := database.New(db)

	jwtSec := getEnvVariable("JWT_SECRET", "")
	if jwtSec == "" {
		log.Fatal("Missing required environment variable: JWT_SECRET")
	}

	cfg := &apiConfig{
		fileserverHits:     atomic.Int32{},
		db:                 dbQueries,
		jwtSecret:          jwtSec,
		minPasswordEntropy: 60.0,
	}
	server := http.Server{
		Handler:      r,
		Addr:         ":" + port,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// api router
	apiRouter := chi.NewRouter()
	apiRouter.Use(cfg.middlewareMetricsInc)

	// User-related routes
	userHandler := users.NewUserHandler(dbQueries, cfg.jwtSecret, cfg.minPasswordEntropy)
	apiRouter.Mount("/users", userHandler.UsersRouter())

	// bookmarks related routes

	cdn := getEnvVariable("CDN", "") //content delivery network (cdn)
	if cdn == "" {
		log.Fatal("Missing required environment variable: CDN")
	}
	bh := bookmarks.NewBookmarksHandler(dbQueries, cdn)
	apiRouter.Mount("/bookmarks", bh.BookmarksRouter())
	// Health check and metrics routes
	apiRouter.Get("/healthz", handleHealthz)
	apiRouter.Get("/metrics", cfg.handleMetrics)
	r.Mount("/api", apiRouter)

	r.Handle("/app/", cfg.middlewareMetricsInc(http.StripPrefix("/app/", http.FileServer(http.Dir(".")))))

	// Admin-related routes
	r.Mount("/admin", cfg.adminRouter(userHandler))

	log.Printf("Server running successfully on port: %s\n", port)
	log.Printf("full address: %v", server.Addr)
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
	_, err := w.Write([]byte("OK\n"))
	if err != nil {
		jsonUtils.RespondWithJsonError(w, err.Error(), 500)
	}
}
