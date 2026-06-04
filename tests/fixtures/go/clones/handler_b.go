package handlers

import (
	"fmt"
	"log"
	"net/http"
)

func HandleOrders(w http.ResponseWriter, r *http.Request) {
	data, err := fetchData(r)
	if err != nil {
		log.Printf("error fetching data: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	result, err := processData(data)
	if err != nil {
		log.Printf("error processing data: %v", err)
		http.Error(w, "processing error", http.StatusInternalServerError)
		return
	}

	if err := validateResult(result); err != nil {
		log.Printf("validation failed: %v", err)
		http.Error(w, "validation error", http.StatusBadRequest)
		return
	}

	fmt.Fprintf(w, "OK: %v", result)
}
