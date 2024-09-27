package main

import (
	"encoding/json"
	"log"
	"net/http"
)

func responseWithJson(data interface{}, w http.ResponseWriter, code int) {
	dat, ok := marshalToJson(data)
	if !ok {
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	w.Write(dat)
}

func marshalToJson(data interface{}) (dat []byte, ok bool) {
	dat, err := json.Marshal(data)
	if err != nil {
		log.Printf("Error marshalling JSON: %s", err)
		return nil, false
	}
	return dat, true
}

func responseWithJsonError(w http.ResponseWriter, message string, errorCode int) {
	dat, ok := marshalToJson(struct {
		Error string `json:"error"`
	}{Error: message})
	if !ok {
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(errorCode)
	w.Write(dat)
}
