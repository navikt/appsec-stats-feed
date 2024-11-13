package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"cloud.google.com/go/bigquery"
	"google.golang.org/api/googleapi"
)

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
		{Name: "event", Type: bigquery.StringFieldType},
		{Name: "alert", Type: bigquery.RecordFieldType, Schema: bigquery.Schema{
			{Name: "state", Type: bigquery.StringFieldType},
			{Name: "severity", Type: bigquery.StringFieldType},
			{Name: "created_at", Type: bigquery.TimestampFieldType},
			{Name: "updated_at", Type: bigquery.TimestampFieldType, Required: false},
			{Name: "dismissed_at", Type: bigquery.TimestampFieldType, Required: false},
			{Name: "fixed_at", Type: bigquery.TimestampFieldType, Required: false},
			{Name: "auto_dismissed_at", Type: bigquery.TimestampFieldType, Required: false},
			{Name: "security_vulnerability", Type: bigquery.RecordFieldType, Schema: bigquery.Schema{
				{Name: "severity", Type: bigquery.StringFieldType},
			}},
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

func logError(message string, err error) {
	logEntry := map[string]interface{}{
		"time":    time.Now().Format(time.RFC3339),
		"level":   "error",
		"message": message,
		"error":   err.Error(),
	}
	logEntryJSON, _ := json.Marshal(logEntry)
	fmt.Println(string(logEntryJSON))
}
