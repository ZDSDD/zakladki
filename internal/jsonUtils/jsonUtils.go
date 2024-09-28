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
	w.Write(dat)
}

func MarshalToJson(data interface{}) (dat []byte, ok bool) {
	dat, err := json.Marshal(data)
	if err != nil {
		log.Printf("Error marshalling JSON: %s", err)
		return nil, false
	}
	return dat, true
}

func ResponseWithJsonError(w http.ResponseWriter, message string, errorCode int) {
	dat, ok := MarshalToJson(struct {
		Error string `json:"error"`
	}{Error: message})
	if !ok {
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(errorCode)
	w.Write(dat)
}
