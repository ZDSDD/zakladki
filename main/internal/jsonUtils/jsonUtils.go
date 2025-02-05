package jsonUtils

import (
	"encoding/json"
	"log"
	"net/http"
)

func ResponseWithJson(data interface{}, w http.ResponseWriter, code int) {
	dat, ok := MarshalToJson(data)
	if !ok {
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_, err := w.Write(dat)
	if err != nil {
		log.Printf("ResponseWithJson: Couldn't write:\n%v.\n", dat)
	}
}

func MarshalToJson(data interface{}) (dat []byte, ok bool) {
	dat, err := json.Marshal(data)
	if err != nil {
		log.Printf("Error marshalling JSON: %s", err)
		return nil, false
	}
	return dat, true
}

func RespondWithJsonError(w http.ResponseWriter, message string, errorCode int) {
	type ErrorResponse struct {
		Error string `json:"error"`
	}

	response := ErrorResponse{Error: message}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(errorCode)

	if err := json.NewEncoder(w).Encode(response); err != nil {
		log.Printf("ResponseWithJsonError: Couldn't encode response: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
}
