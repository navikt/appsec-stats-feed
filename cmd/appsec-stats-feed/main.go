package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"

	"cloud.google.com/go/bigquery"
	"google.golang.org/api/googleapi"
)

type GitHubPayload struct {
	Action     string `json:"action"`
	Alert      Alert  `json:"alert"`
	Repository Repo   `json:"repository"`
}

type Alert struct {
	State           string  `json:"state"`
	Severity        string  `json:"severity"`
	CreatedAt       string  `json:"created_at"`
	UpdatedAt       string  `json:"updated_at"`
	DismissedAt     *string `json:"dismissed_at"`
	FixedAt         *string `json:"fixed_at"`
	AutoDismissedAt *string `json:"auto_dismissed_at"`
}

type Repo struct {
	Name     string `json:"name"`
	Archived bool   `json:"archived"`
}

const (
	topicName = "appsec-stats-feed"
	tableName = "appsec_stats_feed"
	datasetID = "appsec"
)

var (
	projectID = os.Getenv("GCP_TEAM_PROJECT_ID")
	secretKey = os.Getenv("GITHUB_HMAC_SECRET_KEY")
	bqClient  *bigquery.Client
	inserter  *bigquery.Inserter
)

func main() {
	ctx := context.Background()

	var err error
	bqClient, err = bigquery.NewClient(ctx, projectID)
	if err != nil {
		panic(err)
	}
	defer bqClient.Close()

	table, err := createTableIfNotExists(ctx, bqClient)
	if err != nil {
		panic(err)
	}
	inserter = table.Inserter()

	http.HandleFunc("/isready", healthCheckHandler)
	http.HandleFunc("/isalive", healthCheckHandler)

	http.HandleFunc("/collect", postHandler)
	fmt.Println("Server is listening on port 8080...")
	if err := http.ListenAndServe(":8080", nil); err != nil {
		panic(err)
	}
}

func healthCheckHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}

func postHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	// Validate HMAC signature
	signature := r.Header.Get("X-Hub-Signature-256")
	if signature == "" {
		http.Error(w, "Missing HMAC signature", http.StatusUnauthorized)
		return
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Error reading request body", http.StatusInternalServerError)
		return
	}

	if !validateHMAC(body, signature, secretKey) {
		http.Error(w, "Invalid HMAC signature", http.StatusUnauthorized)
		return
	}

	var m GitHubPayload
	if err := json.Unmarshal(body, &m); err != nil {
		http.Error(w, "Error decoding JSON", http.StatusBadRequest)
		return
	}

	// Insert the data into BigQuery
	if err := inserter.Put(r.Context(), &m); err != nil {
		http.Error(w, "Error inserting data into BigQuery", http.StatusInternalServerError)
		return
	}

	fmt.Printf("Received and inserted message: %+v\n", m)
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Message received and inserted"))
}

func validateHMAC(body []byte, signature, secretKey string) bool {
	mac := hmac.New(sha256.New, []byte(secretKey))
	mac.Write(body)
	expectedMAC := mac.Sum(nil)
	expectedSignature := "sha256=" + hex.EncodeToString(expectedMAC)
	return hmac.Equal([]byte(expectedSignature), []byte(signature))
}

func createTableIfNotExists(ctx context.Context, bqClient *bigquery.Client) (*bigquery.Table, error) {
	schema := bigquery.Schema{
		{Name: "action", Type: bigquery.StringFieldType},
		{Name: "alert", Type: bigquery.RecordFieldType, Schema: bigquery.Schema{
			{Name: "state", Type: bigquery.StringFieldType},
			{Name: "severity", Type: bigquery.StringFieldType},
			{Name: "created_at", Type: bigquery.TimestampFieldType},
			{Name: "updated_at", Type: bigquery.TimestampFieldType},
			{Name: "dismissed_at", Type: bigquery.TimestampFieldType, Required: false},
			{Name: "fixed_at", Type: bigquery.TimestampFieldType, Required: false},
			{Name: "auto_dismissed_at", Type: bigquery.TimestampFieldType, Required: false},
		}},
		{Name: "repository", Type: bigquery.RecordFieldType, Schema: bigquery.Schema{
			{Name: "name", Type: bigquery.StringFieldType},
			{Name: "archived", Type: bigquery.BooleanFieldType},
		}},
	}

	metadata := &bigquery.TableMetadata{
		Schema: schema,
	}

	tableRef := bqClient.Dataset(datasetID).Table(tableName)
	if err := tableRef.Create(ctx, metadata); err != nil {
		if e, ok := err.(*googleapi.Error); ok {
			if e.Code == 409 {
				// already exists
				return tableRef, nil
			}
		}
		return nil, err
	}

	return tableRef, nil
}
