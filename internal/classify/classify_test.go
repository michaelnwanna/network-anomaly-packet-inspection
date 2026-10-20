package classify

import (
	"reflect"
	"strings"
	"testing"
)

func TestRulesSizeLimit(t *testing.T) {
	valid := `{"allowed_ports":[443],"large_payload_bytes":1}`
	const limit = 1 << 20
	atLimit := valid + strings.Repeat(" ", limit-len(valid))
	if _, err := Load(strings.NewReader(atLimit)); err != nil {
		t.Fatalf("rules at size limit rejected: %v", err)
	}
	for _, suffix := range []string{" ", "{}"} {
		if _, err := Load(strings.NewReader(atLimit + suffix)); err == nil {
			t.Fatal("oversized rules were silently truncated and accepted")
		}
	}
}

func TestFlags(t *testing.T) {
	engine, err := Load(strings.NewReader(`{"tracking_domains":["tracker.test"],"allowed_ports":[80,443],"large_payload_bytes":100}`))
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		host           string
		port           int
		sent, received int64
		want           []string
	}{
		{"sub.TRACKER.test.", 8443, 60, 41, []string{"known-tracker", "large-payload", "unsanctioned-port"}},
		{"nottracker.test", 443, 60, 40, []string{}},
		{"tracker.test.evil", 80, 0, 0, []string{}},
		{"tracker.test", 443, 101, 0, []string{"known-tracker", "large-payload"}},
	} {
		if got := engine.Flags(tc.host, tc.port, tc.sent, tc.received); !reflect.DeepEqual(got, tc.want) {
			t.Errorf("%s: got %v want %v", tc.host, got, tc.want)
		}
	}
}

func TestInspectionScope(t *testing.T) {
	scope, err := ParseScope("example.com, *.tracker.test,127.0.0.1,::1")
	if err != nil {
		t.Fatal(err)
	}
	for host, want := range map[string]bool{
		"EXAMPLE.COM.": true, "sub.example.com": false, "a.tracker.test": true,
		"a.b.tracker.test": true, "tracker.test": false, "eviltracker.test": false,
		"127.0.0.1": true, "::1": true,
	} {
		if got := scope.Matches(host); got != want {
			t.Errorf("%s: got %v want %v", host, got, want)
		}
	}
	for _, input := range []string{"*", "https://example.com", "example.com:443", "a..b", "*.127.0.0.1", ",", "-bad.test"} {
		if _, err := ParseScope(input); err == nil {
			t.Errorf("accepted invalid scope %q", input)
		}
	}
}

func TestRulesValidation(t *testing.T) {
	for _, input := range []string{
		`{}`, `{"allowed_ports":[0],"large_payload_bytes":1}`,
		`{"allowed_ports":[443],"large_payload_bytes":0}`,
		`{"allowed_ports":[443],"large_payload_bytes":1,"unexpected":true}`,
		`{"allowed_ports":[443],"large_payload_bytes":1} {}`,
		`{"tracking_domains":["*.example.com"],"allowed_ports":[443],"large_payload_bytes":1}`,
	} {
		if _, err := Load(strings.NewReader(input)); err == nil {
			t.Errorf("accepted invalid rules %s", input)
		}

	}
	if _, err := Load(nil); err != nil {
		t.Fatal(err)
	}
}
