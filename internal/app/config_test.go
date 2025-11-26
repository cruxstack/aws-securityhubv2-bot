// Package app tests configuration parsing and auto-close rule loading.
//
// Tests cover:
// - JSON rule parsing (direct and JSON-encoded strings)
// - Empty and invalid rule arrays
// - Multiple rules with different filter combinations
// - Both single-encoded and double-encoded JSON (env var format)
package app

import (
	"encoding/json"
	"testing"

	"github.com/cruxstack/aws-securityhubv2-bot/internal/filters"
)

// TestConfig_ParseAutoCloseRules validates that a single auto-close rule
// can be parsed from JSON with all expected fields.
func TestConfig_ParseAutoCloseRules(t *testing.T) {
	rulesJSON := `[
		{
			"name": "test-rule",
			"enabled": true,
			"filters": {
				"finding_types": ["PrivilegeEscalation:Runtime/ContainerMountsHostDirectory"],
				"resource_tags": [
					{"name": "provider", "value": "runs-on.com"}
				]
			},
			"action": {
				"status_id": 5,
				"comment": "Test comment"
			},
			"skip_notification": true
		}
	]`

	var rules []filters.AutoCloseRule
	if err := json.Unmarshal([]byte(rulesJSON), &rules); err != nil {
		t.Fatalf("failed to parse rules: %v", err)
	}

	if len(rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(rules))
	}

	rule := rules[0]
	if rule.Name != "test-rule" {
		t.Errorf("expected name 'test-rule', got %s", rule.Name)
	}

	if !rule.Enabled {
		t.Error("expected rule to be enabled")
	}

	if len(rule.Filters.FindingTypes) != 1 {
		t.Errorf("expected 1 finding type, got %d", len(rule.Filters.FindingTypes))
	}

	if rule.Action.StatusID != 5 {
		t.Errorf("expected status_id 5, got %d", rule.Action.StatusID)
	}

	if !rule.SkipNotification {
		t.Error("expected skip_notification to be true")
	}
}

// TestConfig_EmptyRules verifies that an empty rule array is handled correctly.
func TestConfig_EmptyRules(t *testing.T) {
	var rules []filters.AutoCloseRule
	if err := json.Unmarshal([]byte("[]"), &rules); err != nil {
		t.Fatalf("failed to parse empty rules: %v", err)
	}

	if len(rules) != 0 {
		t.Errorf("expected 0 rules, got %d", len(rules))
	}
}

// TestConfig_InvalidJSON ensures that malformed JSON returns an error.
func TestConfig_InvalidJSON(t *testing.T) {
	var rules []filters.AutoCloseRule
	err := json.Unmarshal([]byte("not json"), &rules)
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

// TestParseAutoCloseRules_DirectJSON validates parsing of direct JSON array format.
func TestParseAutoCloseRules_DirectJSON(t *testing.T) {
	input := `[
		{
			"name": "test-rule",
			"enabled": true,
			"filters": {
				"finding_types": ["Execution:Runtime/NewBinaryExecuted"]
			},
			"action": {
				"status_id": 5,
				"comment": "Test"
			},
			"skip_notification": true
		}
	]`

	rules, err := parseAutoCloseRules(input)
	if err != nil {
		t.Fatalf("failed to parse direct JSON: %v", err)
	}

	if len(rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(rules))
	}

	if rules[0].Name != "test-rule" {
		t.Errorf("expected name 'test-rule', got %s", rules[0].Name)
	}
}

// TestParseAutoCloseRules_JSONEncodedString validates parsing of JSON-encoded strings.
// This format occurs when rules are passed as environment variables (double-encoded).
func TestParseAutoCloseRules_JSONEncodedString(t *testing.T) {
	input := `"[{\"name\":\"test-rule\",\"enabled\":true,\"filters\":{\"finding_types\":[\"Execution:Runtime/NewBinaryExecuted\"]},\"action\":{\"status_id\":5,\"comment\":\"Test\"},\"skip_notification\":true}]"`

	rules, err := parseAutoCloseRules(input)
	if err != nil {
		t.Fatalf("failed to parse JSON-encoded string: %v", err)
	}

	if len(rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(rules))
	}

	if rules[0].Name != "test-rule" {
		t.Errorf("expected name 'test-rule', got %s", rules[0].Name)
	}
}

// TestParseAutoCloseRules_EmptyArray validates handling of empty rule arrays
// in both direct and encoded formats.
func TestParseAutoCloseRules_EmptyArray(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{"direct empty array", "[]"},
		{"encoded empty array", `"[]"`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rules, err := parseAutoCloseRules(tt.input)
			if err != nil {
				t.Fatalf("failed to parse: %v", err)
			}

			if len(rules) != 0 {
				t.Errorf("expected 0 rules, got %d", len(rules))
			}
		})
	}
}

// TestParseAutoCloseRules_InvalidJSON validates that various invalid JSON formats
// return appropriate errors.
func TestParseAutoCloseRules_InvalidJSON(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{"completely invalid", "not json at all"},
		{"invalid array", "[{invalid}]"},
		{"encoded invalid", `"not an array"`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := parseAutoCloseRules(tt.input)
			if err == nil {
				t.Error("expected error for invalid JSON")
			}
		})
	}
}

// TestParseAutoCloseRules_MultipleRules validates parsing multiple rules
// with different enabled states and filter configurations.
func TestParseAutoCloseRules_MultipleRules(t *testing.T) {
	input := `[
		{
			"name": "rule-1",
			"enabled": true,
			"filters": {"severity": ["High"]},
			"action": {"status_id": 5, "comment": "Auto-close"},
			"skip_notification": true
		},
		{
			"name": "rule-2",
			"enabled": false,
			"filters": {"severity": ["Low"]},
			"action": {"status_id": 3, "comment": "Resolve"},
			"skip_notification": false
		}
	]`

	rules, err := parseAutoCloseRules(input)
	if err != nil {
		t.Fatalf("failed to parse: %v", err)
	}

	if len(rules) != 2 {
		t.Fatalf("expected 2 rules, got %d", len(rules))
	}

	if rules[0].Name != "rule-1" || rules[1].Name != "rule-2" {
		t.Errorf("unexpected rule names: %s, %s", rules[0].Name, rules[1].Name)
	}

	if !rules[0].Enabled {
		t.Error("expected rule-1 to be enabled")
	}

	if rules[1].Enabled {
		t.Error("expected rule-2 to be disabled")
	}
}
