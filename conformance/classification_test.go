package conformance

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/michaelnwanna/network-anomaly-packet-inspection/internal/classify"
)

func TestClassificationContract(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "testdata", "conformance", "classification.json"))
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Rules json.RawMessage `json:"rules"`
		Cases []struct {
			Name     string   `json:"name"`
			Host     string   `json:"host"`
			Port     int      `json:"port"`
			Sent     int64    `json:"sent"`
			Received int64    `json:"received"`
			Flags    []string `json:"flags"`
		} `json:"classifications"`
		Scope   string `json:"inspection_scope"`
		Matches []struct {
			Host    string `json:"host"`
			Matches bool   `json:"matches"`
		} `json:"inspection_matches"`
		Invalid []string `json:"invalid_scopes"`
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	engine, err := classify.Load(bytes.NewReader(fixture.Rules))
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range fixture.Cases {
		t.Run(test.Name, func(t *testing.T) {
			if got := engine.Flags(test.Host, test.Port, test.Sent, test.Received); !reflect.DeepEqual(got, test.Flags) {
				t.Fatalf("flags=%v, want %v", got, test.Flags)
			}
		})
	}
	scope, err := classify.ParseScope(fixture.Scope)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range fixture.Matches {
		if got := scope.Matches(test.Host); got != test.Matches {
			t.Errorf("scope host=%q matches=%v, want %v", test.Host, got, test.Matches)
		}
	}
	for _, invalid := range fixture.Invalid {
		if _, err := classify.ParseScope(invalid); err == nil {
			t.Errorf("invalid inspection scope accepted: %q", invalid)
		}
	}
}
