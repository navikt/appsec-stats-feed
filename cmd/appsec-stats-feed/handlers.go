package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

func postHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		logError("Invalid request method", nil)
		return
	}

	// Validate HMAC signature
	signature := r.Header.Get("X-Hub-Signature-256")
	if signature == "" {
		http.Error(w, "Missing HMAC signature", http.StatusUnauthorized)
		logError("Missing HMAC signature", nil)
		return
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Error reading request body", http.StatusInternalServerError)
		logError("Error reading request body", err)
		return
	}

	if !validateHMAC(body, signature, secretKey) {
		http.Error(w, "Invalid HMAC signature", http.StatusUnauthorized)
		logError("Invalid HMAC signature", nil)
		return
	}

	// Unmarshal the JSON to ensure it's valid and to convert it to the appropriate struct
	var m GitHubPayload
	if err := json.Unmarshal(body, &m); err != nil {
		http.Error(w, "Error decoding JSON", http.StatusBadRequest)
		logError("Error decoding JSON", err)
		return
	}

	// Ignore events that arent dependabot or code_scanning alerts
	//if m.Event != "dependabot_alert" || m.Action != "code_scanning_alert" {
	//	http.Error(w, "Invalid event or action", http.StatusBadRequest)
	//	return
	//}

	// Set the Event field from the X-GitHub-Event header
	m.Event = r.Header.Get("X-GitHub-Event")

	// Insert the data into BigQuery
	if err := inserter.Put(r.Context(), &m); err != nil {
		http.Error(w, "Error inserting data into BigQuery", http.StatusInternalServerError)
		logError("Error inserting data into BigQuery", err)
		return
	}

	fmt.Printf("Received and inserted message: %+v\n", m)
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Message received and inserted"))
}

func healthCheckHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}
