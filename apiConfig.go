package main

import (
	"fmt"
	"net/http"
	"sync/atomic"

	"github.com/zdsdd/zakladki/internal/database"
)

type apiConfig struct {
	fileserverHits atomic.Int32
	db             *database.Queries
	jwtSecret      string
}

func (cfg *apiConfig) middlewareMetricsInc(next http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		cfg.fileserverHits.Add(1)
		next.ServeHTTP(rw, req)
	})
}

func (cfg *apiConfig) handleReset(rw http.ResponseWriter, r *http.Request) {
	platform := getEnvVariable("PLATFORM")
	if platform != "dev" {
		rw.WriteHeader(http.StatusForbidden)
		return
	}
	cfg.fileserverHits.Store(0)
	cfg.db.PurgeUsers(r.Context())
	rw.WriteHeader(204)
}

func (cfg *apiConfig) handleMetrics(rw http.ResponseWriter, _ *http.Request) {
	rw.Write([]byte(fmt.Sprintf("Hits: %d", cfg.fileserverHits.Load())))

}
func (cfg *apiConfig) handleAdminMetrics(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(fmt.Sprintf(`
<html>
  <body>
    <h1>Welcome, Chirpy Admin</h1>
    <p>Chirpy has been visited %d times!</p>
  </body>
</html>`, cfg.fileserverHits.Load())))
}
