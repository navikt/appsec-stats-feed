package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"reflect"
	"testing"
	"time"

	"cloud.google.com/go/bigquery"
)

func TestPostHandler(t *testing.T) {

	// Open the test data file
	testDataFile, err := os.Open("testData.json")
	if err != nil {
		t.Fatalf("failed to open test data file: %v", err)
	}
	defer testDataFile.Close()

	// Read the test data file
	testData, err := io.ReadAll(testDataFile)
	if err != nil {
		t.Fatalf("failed to read test data file: %v", err)
	}

	// Unmarshal the test data into a Go data structure
	var testBody GitHubPayload
	if err := json.Unmarshal(testData, &testBody); err != nil {
		t.Fatalf("failed to unmarshal test data: %v", err)
	}

	// Print the unmarshaled test body
	fmt.Printf("Unmarshaled test body: %+v\n", testBody)

	// Marshal the Go data structure back to a JSON string
	//marshaledTestBody, err := json.Marshal(testBody)
	//if err != nil {
	//		t.Fatalf("failed to marshal test body: %v", err)
	//}

	// Define the expected struct instance
	expectedBody := GitHubPayload{
		Action: "reopen",
		Event:  "security_alert",
		Alert: Alert{
			State:    "open",
			Severity: "high",
			CreatedAt: bigquery.NullTimestamp{
				Timestamp: time.Date(2024, 10, 4, 6, 49, 15, 0, time.UTC),
				Valid:     true,
			},
		},
		Repository: Repo{
			Name: "kviss",
		},
		SecurityVulnerability: SecurityVulnerability{
			Severity: "high",
		},
	}

	// Compare the unmarshaled struct with the expected struct instance
	if !reflect.DeepEqual(testBody, expectedBody) {
		t.Fatalf("expected %+v, got %+v", expectedBody, testBody)
	}
}
