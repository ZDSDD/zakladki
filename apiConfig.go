package main

import (
	"fmt"
	"net/http"
	"sync/atomic"

	"github.com/zdsdd/zakladki/internal/database"
	"github.com/zdsdd/zakladki/internal/jsonUtils"
)

type apiConfig struct {
	fileserverHits     atomic.Int32
	db                 *database.Queries
	jwtSecret          string
	minPasswordEntropy float64
}

func (cfg *apiConfig) middlewareMetricsInc(next http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		cfg.fileserverHits.Add(1)
		next.ServeHTTP(rw, req)
	})
}

func (cfg *apiConfig) handleReset(w http.ResponseWriter, r *http.Request) {
	platform := getEnvVariable("PLATFORM")
	if platform != "dev" {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	cfg.fileserverHits.Store(0)
	err := cfg.db.PurgeUsers(r.Context())
	if err != nil {
		jsonUtils.RespondWithJsonError(w, err.Error(), 500)
		return
	}
	w.WriteHeader(204)
}

func (cfg *apiConfig) handleMetrics(w http.ResponseWriter, _ *http.Request) {
	_, err := w.Write([]byte(fmt.Sprintf("Hits: %d", cfg.fileserverHits.Load())))
	if err != nil {
		jsonUtils.RespondWithJsonError(w, err.Error(), 500)
		return
	}
}
func (cfg *apiConfig) handleAdminMetrics(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("Content-Type", "text/html; charset=utf-8")
	_, err := w.Write([]byte(fmt.Sprintf(`
<html>
  <body>
    <h1>Welcome, Chirpy Admin</h1>
    <p>Chirpy has been visited %d times!</p>
  </body>
</html>`, cfg.fileserverHits.Load())))
	if err != nil {
		jsonUtils.RespondWithJsonError(w, err.Error(), 500)
		return
	}
}
