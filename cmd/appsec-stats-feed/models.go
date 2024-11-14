package main

import (
	"encoding/json"
	"fmt"
	"time"

	"cloud.google.com/go/bigquery"
)

type GitHubPayload struct {
	Action     string `json:"action" bigquery:"action"`
	Event      string `json:"event" bigquery:"event"`
	Alert      Alert  `json:"alert" bigquery:"alert"`
	Repository Repo   `json:"repository" bigquery:"repository"`
}

type Alert struct {
	Number                string                 `json:"number" bigquery:"number"`
	State                 string                 `json:"state" bigquery:"state"`
	SecurityVulnerability SecurityVulnerability  `json:"security_vulnerability" bigquery:"security_vulnerability"`
	CreatedAt             bigquery.NullTimestamp `json:"created_at" bigquery:"created_at"`
	UpdatedAt             bigquery.NullTimestamp `json:"updated_at" bigquery:"updated_at"`
	DismissedAt           bigquery.NullTimestamp `json:"dismissed_at" bigquery:"dismissed_at"`
	DismissedReason       string                 `json:"dismissed_reason" bigquery:"dismissed_reason"`
	FixedAt               bigquery.NullTimestamp `json:"fixed_at" bigquery:"fixed_at"`
	AutoDismissedAt       bigquery.NullTimestamp `json:"auto_dismissed_at" bigquery:"auto_dismissed_at"`
}

type Repo struct {
	Name string `json:"name" bigquery:"name"`
}

type SecurityVulnerability struct {
	Severity string `json:"severity" bigquery:"severity"`
}

// Implement custom unmarshaling for Alert
func (a *Alert) UnmarshalJSON(data []byte) error {
	type Alias Alert
	aux := &struct {
		CreatedAt       string  `json:"created_at"`
		UpdatedAt       *string `json:"updated_at"`
		DismissedAt     *string `json:"dismissed_at"`
		FixedAt         *string `json:"fixed_at"`
		AutoDismissedAt *string `json:"auto_dismissed_at"`
		*Alias
	}{
		Alias: (*Alias)(a),
	}
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}

	var err error
	a.CreatedAt, err = parseNullTimestamp(aux.CreatedAt)
	if err != nil {
		return fmt.Errorf("error parsing created_at: %v", err)
	}
	a.UpdatedAt, err = parseNullableNullTimestamp(aux.UpdatedAt)
	if err != nil {
		return fmt.Errorf("error parsing updated_at: %v", err)
	}
	a.DismissedAt, err = parseNullableNullTimestamp(aux.DismissedAt)
	if err != nil {
		return fmt.Errorf("error parsing dismissed_at: %v", err)
	}
	a.FixedAt, err = parseNullableNullTimestamp(aux.FixedAt)
	if err != nil {
		return fmt.Errorf("error parsing fixed_at: %v", err)
	}
	a.AutoDismissedAt, err = parseNullableNullTimestamp(aux.AutoDismissedAt)
	if err != nil {
		return fmt.Errorf("error parsing auto_dismissed_at: %v", err)
	}

	return nil
}

func parseNullTimestamp(s string) (bigquery.NullTimestamp, error) {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return bigquery.NullTimestamp{}, err
	}
	return bigquery.NullTimestamp{Timestamp: t, Valid: true}, nil
}

func parseNullableNullTimestamp(s *string) (bigquery.NullTimestamp, error) {
	if s == nil || *s == "" {
		return bigquery.NullTimestamp{Valid: false}, nil
	}
	t, err := time.Parse(time.RFC3339, *s)
	if err != nil {
		return bigquery.NullTimestamp{}, err
	}
	return bigquery.NullTimestamp{Timestamp: t, Valid: true}, nil
}
