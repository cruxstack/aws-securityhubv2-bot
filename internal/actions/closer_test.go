// Package actions tests finding update operations via Security Hub v2 API.
//
// Tests cover:
// - Finding closer construction
// - Input validation and preparation
//
// Note: Full integration testing with AWS SDK mocks is handled in cmd/verify.
// These unit tests focus on the logic within this package.
package actions

import (
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/securityhub"
)

// TestNewFindingCloser validates that a FindingCloser can be constructed
// with a Security Hub client.
func TestNewFindingCloser(t *testing.T) {
	client := &securityhub.Client{}
	closer := NewFindingCloser(client)

	if closer == nil {
		t.Fatal("expected non-nil FindingCloser")
	}

	if closer.client != client {
		t.Error("expected client to be set correctly")
	}
}

// TestNewFindingCloser_NilClient validates that a FindingCloser can be
// constructed even with a nil client (will fail at runtime, but constructor works).
func TestNewFindingCloser_NilClient(t *testing.T) {
	closer := NewFindingCloser(nil)

	if closer == nil {
		t.Fatal("expected non-nil FindingCloser even with nil client")
	}

	if closer.client != nil {
		t.Error("expected client to be nil")
	}
}
