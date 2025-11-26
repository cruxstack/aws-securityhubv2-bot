// Package notifiers tests Slack notification functionality.
//
// Tests cover:
// - Slack notifier construction
// - Configuration handling
// - Custom API URL support for testing
//
// Note: Full integration testing with Slack SDK mocks is handled in cmd/verify.
// These unit tests focus on the construction and configuration logic.
package notifiers

import (
	"os"
	"testing"
)

// TestNewSlackNotifier validates that a SlackNotifier can be constructed
// with required configuration parameters.
func TestNewSlackNotifier(t *testing.T) {
	notifier := NewSlackNotifier(
		"xoxb-test-token",
		"C01234TEST",
		"https://console.aws.amazon.com",
		"https://portal.example.com",
		"SecurityAuditorRole",
		"us-east-1",
	)

	if notifier == nil {
		t.Fatal("expected non-nil SlackNotifier")
	}

	if notifier.channel != "C01234TEST" {
		t.Errorf("expected channel 'C01234TEST', got %s", notifier.channel)
	}

	if notifier.consoleURL != "https://console.aws.amazon.com" {
		t.Errorf("expected consoleURL 'https://console.aws.amazon.com', got %s", notifier.consoleURL)
	}

	if notifier.securityHubv2Region != "us-east-1" {
		t.Errorf("expected region 'us-east-1', got %s", notifier.securityHubv2Region)
	}
}

// TestNewSlackNotifier_CustomAPIURL validates that SLACK_API_URL environment
// variable is respected for testing purposes.
func TestNewSlackNotifier_CustomAPIURL(t *testing.T) {
	// set custom API URL
	originalURL := os.Getenv("SLACK_API_URL")
	os.Setenv("SLACK_API_URL", "https://mock-slack:9002/api")
	defer func() {
		if originalURL == "" {
			os.Unsetenv("SLACK_API_URL")
		} else {
			os.Setenv("SLACK_API_URL", originalURL)
		}
	}()

	notifier := NewSlackNotifier(
		"xoxb-test-token",
		"C01234TEST",
		"https://console.aws.amazon.com",
		"",
		"",
		"us-east-1",
	)

	if notifier == nil {
		t.Fatal("expected non-nil SlackNotifier")
	}

	if notifier.client == nil {
		t.Fatal("expected non-nil Slack client")
	}
}

// TestNewSlackNotifier_EmptyOptionalParams validates that optional parameters
// can be empty strings without causing issues.
func TestNewSlackNotifier_EmptyOptionalParams(t *testing.T) {
	notifier := NewSlackNotifier(
		"xoxb-test-token",
		"C01234TEST",
		"",
		"",
		"",
		"us-east-1",
	)

	if notifier == nil {
		t.Fatal("expected non-nil SlackNotifier")
	}

	if notifier.consoleURL != "" {
		t.Error("expected empty consoleURL")
	}

	if notifier.accessPortalURL != "" {
		t.Error("expected empty accessPortalURL")
	}

	if notifier.accessRoleName != "" {
		t.Error("expected empty accessRoleName")
	}
}
