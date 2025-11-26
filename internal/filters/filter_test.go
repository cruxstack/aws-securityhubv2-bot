// Package filters tests the auto-close rule matching engine.
//
// Tests cover:
// - Rule matching with various filter combinations
// - Disabled rule handling
// - First-match-wins rule precedence
// - Complex multi-filter rules
// - Uses fixtures/samples.json for realistic OCSF findings
package filters

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/cruxstack/aws-securityhubv2-bot/internal/events"
)

// TestFilterEngine_FindMatchingRule_RunsOnExample validates that a GuardDuty finding
// with "provider=runs-on.com" resource tag matches the auto-close rule.
// Uses fixtures/samples.json finding #3 (ContainerMountsHostDirectory).
func TestFilterEngine_FindMatchingRule_RunsOnExample(t *testing.T) {
	rules := []AutoCloseRule{
		{
			Name:    "auto-close-runs-on-container-mounts",
			Enabled: true,
			Filters: RuleFilters{
				FindingTypes: []string{"PrivilegeEscalation:Runtime/ContainerMountsHostDirectory"},
				ResourceTags: []ResourceTagFilter{
					{Name: "provider", Value: "runs-on.com"},
				},
			},
			Action: RuleAction{
				StatusID: 5,
				Comment:  "Auto-closed: Expected behavior for runs-on.com ephemeral runners",
			},
			SkipNotification: true,
		},
	}

	engine := NewFilterEngine(rules)

	path := filepath.Join("..", "..", "fixtures", "samples.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read samples: %v", err)
	}

	var findings []json.RawMessage
	if err := json.Unmarshal(raw, &findings); err != nil {
		t.Fatalf("failed to unmarshal samples: %v", err)
	}

	if len(findings) < 3 {
		t.Fatalf("expected at least 3 findings, got %d", len(findings))
	}

	runsOnFinding, err := events.NewSecurityHubFinding(findings[2])
	if err != nil {
		t.Fatalf("failed to parse runs-on finding: %v", err)
	}

	matchedRule, matched := engine.FindMatchingRule(runsOnFinding)
	if !matched {
		t.Error("runs-on.com finding should match the auto-close rule")
	}

	if matchedRule == nil {
		t.Fatal("matched rule should not be nil")
	}

	if matchedRule.Name != "auto-close-runs-on-container-mounts" {
		t.Errorf("expected rule name 'auto-close-runs-on-container-mounts', got %s", matchedRule.Name)
	}

	if matchedRule.Action.StatusID != 5 {
		t.Errorf("expected status ID 5, got %d", matchedRule.Action.StatusID)
	}

	if !matchedRule.SkipNotification {
		t.Error("expected skip_notification to be true")
	}
}

// TestFilterEngine_FindMatchingRule_NoMatch validates that a finding does not match
// when the filter criteria don't align.
func TestFilterEngine_FindMatchingRule_NoMatch(t *testing.T) {
	rules := []AutoCloseRule{
		{
			Name:    "test-rule",
			Enabled: true,
			Filters: RuleFilters{
				FindingTypes: []string{"NonExistentFindingType"},
			},
			Action: RuleAction{
				StatusID: 5,
				Comment:  "Test comment",
			},
			SkipNotification: true,
		},
	}

	engine := NewFilterEngine(rules)

	path := filepath.Join("..", "..", "fixtures", "samples.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read samples: %v", err)
	}

	var findings []json.RawMessage
	if err := json.Unmarshal(raw, &findings); err != nil {
		t.Fatalf("failed to unmarshal samples: %v", err)
	}

	finding, err := events.NewSecurityHubFinding(findings[0])
	if err != nil {
		t.Fatalf("failed to parse finding: %v", err)
	}

	_, matched := engine.FindMatchingRule(finding)
	if matched {
		t.Error("finding should not match the rule")
	}
}

// TestFilterEngine_DisabledRule ensures that disabled rules are skipped
// even when filters would match.
func TestFilterEngine_DisabledRule(t *testing.T) {
	rules := []AutoCloseRule{
		{
			Name:    "disabled-rule",
			Enabled: false,
			Filters: RuleFilters{
				Severity: []string{"Medium"},
			},
			Action: RuleAction{
				StatusID: 5,
				Comment:  "Test comment",
			},
			SkipNotification: true,
		},
	}

	engine := NewFilterEngine(rules)

	path := filepath.Join("..", "..", "fixtures", "samples.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read samples: %v", err)
	}

	var findings []json.RawMessage
	if err := json.Unmarshal(raw, &findings); err != nil {
		t.Fatalf("failed to unmarshal samples: %v", err)
	}

	finding, err := events.NewSecurityHubFinding(findings[0])
	if err != nil {
		t.Fatalf("failed to parse finding: %v", err)
	}

	_, matched := engine.FindMatchingRule(finding)
	if matched {
		t.Error("disabled rule should not match")
	}
}

// TestFilterEngine_MultipleFilters validates that all filter criteria must match
// (AND logic) for a rule to apply.
func TestFilterEngine_MultipleFilters(t *testing.T) {
	rules := []AutoCloseRule{
		{
			Name:    "complex-rule",
			Enabled: true,
			Filters: RuleFilters{
				FindingTypes: []string{"PrivilegeEscalation:Runtime/ContainerMountsHostDirectory"},
				Severity:     []string{"Medium"},
				ProductName:  []string{"GuardDuty"},
				Regions:      []string{"us-east-1"},
				ResourceTags: []ResourceTagFilter{
					{Name: "provider", Value: "runs-on.com"},
				},
			},
			Action: RuleAction{
				StatusID: 5,
				Comment:  "Multi-filter test",
			},
			SkipNotification: true,
		},
	}

	engine := NewFilterEngine(rules)

	path := filepath.Join("..", "..", "fixtures", "samples.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read samples: %v", err)
	}

	var findings []json.RawMessage
	if err := json.Unmarshal(raw, &findings); err != nil {
		t.Fatalf("failed to unmarshal samples: %v", err)
	}

	if len(findings) < 3 {
		t.Fatalf("expected at least 3 findings, got %d", len(findings))
	}

	runsOnFinding, err := events.NewSecurityHubFinding(findings[2])
	if err != nil {
		t.Fatalf("failed to parse runs-on finding: %v", err)
	}

	matchedRule, matched := engine.FindMatchingRule(runsOnFinding)
	if !matched {
		t.Error("finding should match all filter criteria")
	}

	if matchedRule == nil {
		t.Fatal("matched rule should not be nil")
	}

	if matchedRule.Name != "complex-rule" {
		t.Errorf("expected rule name 'complex-rule', got %s", matchedRule.Name)
	}
}
