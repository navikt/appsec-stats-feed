package main

import (
	"context"
	"net/http"
	"os"

	"cloud.google.com/go/bigquery"
)

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
	if err := http.ListenAndServe(":8080", nil); err != nil {
		panic(err)
	}
}
