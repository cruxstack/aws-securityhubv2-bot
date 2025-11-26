// Package filters tests S3-based auto-close rule loading.
//
// Tests cover:
// - Loading single rules from individual JSON files
// - Loading rule arrays from single files
// - Mixed single-rule and array files
// - Non-JSON file filtering
// - Empty and invalid JSON handling
// - Complex rule filter parsing
//
// Uses mock S3 client to avoid actual AWS calls.
package filters

import (
	"context"
	"io"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
)

type mockS3Client struct {
	objects map[string]string
	listErr error
	getErr  error
}

func (m *mockS3Client) ListObjectsV2(ctx context.Context, params *s3.ListObjectsV2Input, optFns ...func(*s3.Options)) (*s3.ListObjectsV2Output, error) {
	if m.listErr != nil {
		return nil, m.listErr
	}

	var contents []types.Object
	prefix := ""
	if params.Prefix != nil {
		prefix = *params.Prefix
	}

	for key := range m.objects {
		if strings.HasPrefix(key, prefix) {
			contents = append(contents, types.Object{
				Key: aws.String(key),
			})
		}
	}

	return &s3.ListObjectsV2Output{
		Contents: contents,
	}, nil
}

func (m *mockS3Client) GetObject(ctx context.Context, params *s3.GetObjectInput, optFns ...func(*s3.Options)) (*s3.GetObjectOutput, error) {
	if m.getErr != nil {
		return nil, m.getErr
	}

	content, ok := m.objects[*params.Key]
	if !ok {
		return nil, &types.NoSuchKey{}
	}

	return &s3.GetObjectOutput{
		Body: io.NopCloser(strings.NewReader(content)),
	}, nil
}

// TestS3RulesLoader_LoadRules_SingleRulePerFile validates loading multiple individual
// rule files from S3, where each file contains a single rule object.
func TestS3RulesLoader_LoadRules_SingleRulePerFile(t *testing.T) {
	client := &mockS3Client{
		objects: map[string]string{
			"rules/rule1.json": `{
				"name": "test-rule-1",
				"enabled": true,
				"filters": {
					"finding_types": ["Type1"]
				},
				"action": {
					"status_id": 5,
					"comment": "Test comment 1"
				}
			}`,
			"rules/rule2.json": `{
				"name": "test-rule-2",
				"enabled": false,
				"filters": {
					"severity": ["High"]
				},
				"action": {
					"status_id": 3,
					"comment": "Test comment 2"
				}
			}`,
		},
	}

	loader := NewS3RulesLoader(client)
	rules, err := loader.LoadRules(context.Background(), "test-bucket", "rules/")

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(rules) != 2 {
		t.Fatalf("expected 2 rules, got %d", len(rules))
	}

	// build map of rules by name (order is undefined from S3 listing)
	ruleMap := make(map[string]AutoCloseRule)
	for _, rule := range rules {
		ruleMap[rule.Name] = rule
	}

	rule1, ok1 := ruleMap["test-rule-1"]
	if !ok1 {
		t.Error("expected to find 'test-rule-1'")
	} else if !rule1.Enabled {
		t.Error("expected rule 1 to be enabled")
	}

	rule2, ok2 := ruleMap["test-rule-2"]
	if !ok2 {
		t.Error("expected to find 'test-rule-2'")
	} else if rule2.Enabled {
		t.Error("expected rule 2 to be disabled")
	}
}

// TestS3RulesLoader_LoadRules_ArrayInSingleFile validates loading a single file
// containing an array of multiple rules.
func TestS3RulesLoader_LoadRules_ArrayInSingleFile(t *testing.T) {
	client := &mockS3Client{
		objects: map[string]string{
			"rules/all-rules.json": `[
				{
					"name": "test-rule-1",
					"enabled": true,
					"filters": {
						"finding_types": ["Type1"]
					},
					"action": {
						"status_id": 5,
						"comment": "Test comment 1"
					}
				},
				{
					"name": "test-rule-2",
					"enabled": true,
					"filters": {
						"severity": ["High"]
					},
					"action": {
						"status_id": 3,
						"comment": "Test comment 2"
					}
				},
				{
					"name": "test-rule-3",
					"enabled": false,
					"filters": {
						"product_name": ["Inspector"]
					},
					"action": {
						"status_id": 5,
						"comment": "Test comment 3"
					}
				}
			]`,
		},
	}

	loader := NewS3RulesLoader(client)
	rules, err := loader.LoadRules(context.Background(), "test-bucket", "rules/")

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(rules) != 3 {
		t.Fatalf("expected 3 rules, got %d", len(rules))
	}

	if rules[0].Name != "test-rule-1" {
		t.Errorf("expected rule name 'test-rule-1', got '%s'", rules[0].Name)
	}

	if rules[1].Name != "test-rule-2" {
		t.Errorf("expected rule name 'test-rule-2', got '%s'", rules[1].Name)
	}

	if rules[2].Name != "test-rule-3" {
		t.Errorf("expected rule name 'test-rule-3', got '%s'", rules[2].Name)
	}
}

func TestS3RulesLoader_LoadRules_MixedArrayAndSingleFiles(t *testing.T) {
	client := &mockS3Client{
		objects: map[string]string{
			"rules/array-rules.json": `[
				{
					"name": "array-rule-1",
					"enabled": true,
					"filters": {
						"finding_types": ["Type1"]
					},
					"action": {
						"status_id": 5,
						"comment": "Array rule 1"
					}
				},
				{
					"name": "array-rule-2",
					"enabled": true,
					"filters": {
						"severity": ["High"]
					},
					"action": {
						"status_id": 3,
						"comment": "Array rule 2"
					}
				}
			]`,
			"rules/single-rule-1.json": `{
				"name": "single-rule-1",
				"enabled": true,
				"filters": {
					"product_name": ["GuardDuty"]
				},
				"action": {
					"status_id": 5,
					"comment": "Single rule 1"
				}
			}`,
			"rules/single-rule-2.json": `{
				"name": "single-rule-2",
				"enabled": false,
				"filters": {
					"accounts": ["123456789012"]
				},
				"action": {
					"status_id": 3,
					"comment": "Single rule 2"
				}
			}`,
		},
	}

	loader := NewS3RulesLoader(client)
	rules, err := loader.LoadRules(context.Background(), "test-bucket", "rules/")

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(rules) != 4 {
		t.Fatalf("expected 4 rules, got %d", len(rules))
	}

	ruleNames := make(map[string]bool)
	for _, rule := range rules {
		ruleNames[rule.Name] = true
	}

	expectedNames := []string{"array-rule-1", "array-rule-2", "single-rule-1", "single-rule-2"}
	for _, name := range expectedNames {
		if !ruleNames[name] {
			t.Errorf("expected to find rule '%s' in loaded rules", name)
		}
	}
}

func TestS3RulesLoader_LoadRules_IgnoreNonJSONFiles(t *testing.T) {
	client := &mockS3Client{
		objects: map[string]string{
			"rules/rule1.json": `{
				"name": "test-rule-1",
				"enabled": true,
				"filters": {},
				"action": {
					"status_id": 5,
					"comment": "Test"
				}
			}`,
			"rules/README.md":   "# Rules documentation",
			"rules/config.yaml": "key: value",
			"rules/.gitignore":  "*.log",
			"rules/script.sh":   "#!/bin/bash\necho test",
		},
	}

	loader := NewS3RulesLoader(client)
	rules, err := loader.LoadRules(context.Background(), "test-bucket", "rules/")

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(rules))
	}

	if rules[0].Name != "test-rule-1" {
		t.Errorf("expected rule name 'test-rule-1', got '%s'", rules[0].Name)
	}
}

func TestS3RulesLoader_LoadRules_EmptyPrefix(t *testing.T) {
	client := &mockS3Client{
		objects: map[string]string{
			"rule1.json": `{
				"name": "test-rule-1",
				"enabled": true,
				"filters": {},
				"action": {
					"status_id": 5,
					"comment": "Test"
				}
			}`,
		},
	}

	loader := NewS3RulesLoader(client)
	rules, err := loader.LoadRules(context.Background(), "test-bucket", "")

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(rules))
	}
}

func TestS3RulesLoader_LoadRules_NoJSONFiles(t *testing.T) {
	client := &mockS3Client{
		objects: map[string]string{
			"rules/README.md":   "# Documentation",
			"rules/config.yaml": "key: value",
		},
	}

	loader := NewS3RulesLoader(client)
	_, err := loader.LoadRules(context.Background(), "test-bucket", "rules/")

	if err == nil {
		t.Fatal("expected error when no JSON files found, got nil")
	}

	if !strings.Contains(err.Error(), "no rules loaded") {
		t.Errorf("expected 'no rules loaded' error, got: %v", err)
	}
}

func TestS3RulesLoader_LoadRules_EmptyJSONArray(t *testing.T) {
	client := &mockS3Client{
		objects: map[string]string{
			"rules/empty.json": `[]`,
		},
	}

	loader := NewS3RulesLoader(client)
	_, err := loader.LoadRules(context.Background(), "test-bucket", "rules/")

	if err == nil {
		t.Fatal("expected error when no rules found, got nil")
	}

	if !strings.Contains(err.Error(), "no rules loaded") {
		t.Errorf("expected 'no rules loaded' error, got: %v", err)
	}
}

func TestS3RulesLoader_LoadRules_InvalidJSON(t *testing.T) {
	client := &mockS3Client{
		objects: map[string]string{
			"rules/invalid.json": `{invalid json`,
		},
	}

	loader := NewS3RulesLoader(client)
	_, err := loader.LoadRules(context.Background(), "test-bucket", "rules/")

	if err == nil {
		t.Fatal("expected error for invalid JSON, got nil")
	}
}

func TestS3RulesLoader_LoadRules_WithComplexFilters(t *testing.T) {
	client := &mockS3Client{
		objects: map[string]string{
			"rules/complex.json": `{
				"name": "complex-rule",
				"enabled": true,
				"filters": {
					"finding_types": ["Type1", "Type2"],
					"severity": ["High", "Critical"],
					"product_name": ["GuardDuty", "Inspector"],
					"resource_types": ["AWS::EC2::Instance"],
					"resource_tags": [
						{
							"name": "Environment",
							"value": "production"
						},
						{
							"name": "Team",
							"value": "security"
						}
					],
					"accounts": ["111111111111", "222222222222"],
					"regions": ["us-east-1", "us-west-2"]
				},
				"action": {
					"status_id": 5,
					"comment": "Auto-closed by complex rule"
				},
				"skip_notification": true
			}`,
		},
	}

	loader := NewS3RulesLoader(client)
	rules, err := loader.LoadRules(context.Background(), "test-bucket", "rules/")

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(rules))
	}

	rule := rules[0]

	if rule.Name != "complex-rule" {
		t.Errorf("expected rule name 'complex-rule', got '%s'", rule.Name)
	}

	if len(rule.Filters.FindingTypes) != 2 {
		t.Errorf("expected 2 finding types, got %d", len(rule.Filters.FindingTypes))
	}

	if len(rule.Filters.Severity) != 2 {
		t.Errorf("expected 2 severities, got %d", len(rule.Filters.Severity))
	}

	if len(rule.Filters.ResourceTags) != 2 {
		t.Errorf("expected 2 resource tags, got %d", len(rule.Filters.ResourceTags))
	}

	if rule.SkipNotification != true {
		t.Errorf("expected skip_notification to be true")
	}
}

func TestParseRules_SingleRule(t *testing.T) {
	data := []byte(`{
		"name": "test-rule",
		"enabled": true,
		"filters": {},
		"action": {
			"status_id": 5,
			"comment": "Test"
		}
	}`)

	rules, err := parseRules(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(rules))
	}

	if rules[0].Name != "test-rule" {
		t.Errorf("expected rule name 'test-rule', got '%s'", rules[0].Name)
	}
}

func TestParseRules_Array(t *testing.T) {
	data := []byte(`[
		{
			"name": "test-rule-1",
			"enabled": true,
			"filters": {},
			"action": {
				"status_id": 5,
				"comment": "Test 1"
			}
		},
		{
			"name": "test-rule-2",
			"enabled": true,
			"filters": {},
			"action": {
				"status_id": 3,
				"comment": "Test 2"
			}
		}
	]`)

	rules, err := parseRules(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(rules) != 2 {
		t.Fatalf("expected 2 rules, got %d", len(rules))
	}

	if rules[0].Name != "test-rule-1" {
		t.Errorf("expected rule name 'test-rule-1', got '%s'", rules[0].Name)
	}

	if rules[1].Name != "test-rule-2" {
		t.Errorf("expected rule name 'test-rule-2', got '%s'", rules[1].Name)
	}
}

func TestParseRules_EmptyData(t *testing.T) {
	data := []byte("")

	rules, err := parseRules(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(rules) != 0 {
		t.Errorf("expected 0 rules for empty data, got %d", len(rules))
	}
}

func TestParseRules_WhitespaceOnly(t *testing.T) {
	data := []byte("   \n\t  ")

	rules, err := parseRules(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(rules) != 0 {
		t.Errorf("expected 0 rules for whitespace-only data, got %d", len(rules))
	}
}
