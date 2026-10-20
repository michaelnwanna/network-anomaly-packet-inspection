package classify

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
)

//go:embed defaults.json
var defaults []byte

type Rules struct {
	TrackingDomains   []string `json:"tracking_domains"`
	AllowedPorts      []int    `json:"allowed_ports"`
	LargePayloadBytes int64    `json:"large_payload_bytes"`
}

type Engine struct {
	rules Rules
}

func Load(r io.Reader) (*Engine, error) {
	if r == nil {
		r = strings.NewReader(string(defaults))
	}
	const maxRulesBytes = 1 << 20
	data, err := io.ReadAll(io.LimitReader(r, maxRulesBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read rules: %w", err)
	}
	if len(data) > maxRulesBytes {
		return nil, errors.New("rules exceed the 1 MiB size limit")
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var rules Rules
	if err := dec.Decode(&rules); err != nil {
		return nil, fmt.Errorf("decode rules: %w", err)
	}
	if err := dec.Decode(new(any)); err != io.EOF {
		return nil, errors.New("rules must contain exactly one JSON object")
	}
	if rules.LargePayloadBytes <= 0 || len(rules.AllowedPorts) == 0 {
		return nil, errors.New("rules require a positive payload threshold and allowed ports")
	}
	for _, p := range rules.AllowedPorts {
		if p < 1 || p > 65535 {
			return nil, fmt.Errorf("invalid allowed port %d", p)
		}
	}
	for i, d := range rules.TrackingDomains {
		d = NormalizeHost(d)
		if !ValidDomain(d) {
			return nil, fmt.Errorf("invalid tracking domain %q", d)
		}
		rules.TrackingDomains[i] = d
	}
	return &Engine{rules: rules}, nil
}

func NormalizeHost(host string) string {
	return strings.TrimSuffix(strings.ToLower(host), ".")
}

func ValidDomain(host string) bool {
	if len(host) == 0 || len(host) > 253 || net.ParseIP(host) != nil {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return true
}

func (e *Engine) Flags(host string, port int, sent, received int64) []string {
	flags := make([]string, 0, 3)
	host = NormalizeHost(host)
	for _, d := range e.rules.TrackingDomains {
		if host == d || strings.HasSuffix(host, "."+d) {
			flags = append(flags, "known-tracker")
			break
		}
	}
	if sent > e.rules.LargePayloadBytes || received > e.rules.LargePayloadBytes-sent {
		flags = append(flags, "large-payload")
	}
	allowed := false
	for _, p := range e.rules.AllowedPorts {
		if p == port {
			allowed = true
			break
		}
	}
	if !allowed {
		flags = append(flags, "unsanctioned-port")
	}
	return flags
}

type Scope []string

func ParseScope(value string) (Scope, error) {
	var scope Scope
	if value == "" {
		return scope, nil
	}
	for _, pattern := range strings.Split(value, ",") {
		pattern = NormalizeHost(strings.TrimSpace(pattern))
		base := strings.TrimPrefix(pattern, "*.")
		if !ValidDomain(base) && !(net.ParseIP(base) != nil && base == pattern) {
			return nil, fmt.Errorf("invalid inspection domain %q", pattern)
		}
		scope = append(scope, pattern)
	}
	return scope, nil
}

func (s Scope) Matches(host string) bool {
	host = NormalizeHost(host)
	for _, pattern := range s {
		if host == pattern || strings.HasPrefix(pattern, "*.") && strings.HasSuffix(host, pattern[1:]) {
			return true
		}
	}
	return false
}

func ParsePort(value string) (int, error) {
	p, err := strconv.Atoi(value)
	if err != nil || p < 1 || p > 65535 {
		return 0, errors.New("port must be between 1 and 65535")
	}
	return p, nil
}
