package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"time"

	awsEvent "github.com/aws/aws-lambda-go/events"
	"github.com/cruxstack/aws-securityhubv2-bot/internal/app"
	"github.com/cruxstack/aws-securityhubv2-bot/internal/events"
)

// TestScenario defines a test case with input events and expected outcomes.
type TestScenario struct {
	Name            string            `json:"name"`
	Description     string            `json:"description,omitempty"`
	EventPayload    json.RawMessage   `json:"event_payload"`
	ConfigOverrides map[string]string `json:"config_overrides,omitempty"`
	ExpectedCalls   []ExpectedCall    `json:"expected_calls"`
	MockResponses   []MockResponse    `json:"mock_responses"`
	ExpectError     bool              `json:"expect_error,omitempty"`
}

// ExpectedCall defines an HTTP API call the test expects the application to
// make.
type ExpectedCall struct {
	Service string `json:"service"`
	Method  string `json:"method"`
	Path    string `json:"path"`
}

// runScenario executes a single test scenario with mock HTTP servers and
// validates that expected API calls were made.
func runScenario(ctx context.Context, scenario TestScenario, verbose bool, logger *slog.Logger) error {
	startTime := time.Now()

	fmt.Printf("\n▶ Running: %s\n", scenario.Name)
	if scenario.Description != "" {
		fmt.Printf("  %s\n", scenario.Description)
	}

	securityhubResponses := []MockResponse{}
	slackResponses := []MockResponse{}
	s3Responses := []MockResponse{}

	for _, resp := range scenario.MockResponses {
		switch resp.Service {
		case "securityhub":
			securityhubResponses = append(securityhubResponses, resp)
		case "slack":
			slackResponses = append(slackResponses, resp)
		case "s3":
			s3Responses = append(s3Responses, resp)
		}
	}

	securityhubMock := NewMockServer("SecurityHub", securityhubResponses, verbose)
	slackMock := NewMockServer("Slack", slackResponses, verbose)
	s3Mock := NewMockServer("S3", s3Responses, verbose)

	tlsCert, certPool, err := generateSelfSignedCert()
	if err != nil {
		return fmt.Errorf("generate cert: %w", err)
	}

	securityhubServer := &http.Server{
		Addr:    "localhost:9001",
		Handler: securityhubMock,
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{tlsCert},
		},
	}
	slackServer := &http.Server{
		Addr:    "localhost:9002",
		Handler: slackMock,
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{tlsCert},
		},
	}
	s3Server := &http.Server{
		Addr:    "localhost:9003",
		Handler: s3Mock,
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{tlsCert},
		},
	}

	securityhubReady := make(chan bool)
	slackReady := make(chan bool)
	s3Ready := make(chan bool)

	go func() {
		securityhubReady <- true
		if err := securityhubServer.ListenAndServeTLS("", ""); err != http.ErrServerClosed {
			logger.Error("securityhub mock server error", slog.String("error", err.Error()))
		}
	}()

	go func() {
		slackReady <- true
		if err := slackServer.ListenAndServeTLS("", ""); err != http.ErrServerClosed {
			logger.Error("slack mock server error", slog.String("error", err.Error()))
		}
	}()

	go func() {
		s3Ready <- true
		if err := s3Server.ListenAndServeTLS("", ""); err != http.ErrServerClosed {
			logger.Error("s3 mock server error", slog.String("error", err.Error()))
		}
	}()

	<-securityhubReady
	<-slackReady
	<-s3Ready
	time.Sleep(100 * time.Millisecond)

	defer func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		securityhubServer.Shutdown(shutdownCtx)
		slackServer.Shutdown(shutdownCtx)
		s3Server.Shutdown(shutdownCtx)
	}()

	// create HTTP client with custom TLS config
	httpClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs: certPool,
			},
		},
	}

	http.DefaultTransport = httpClient.Transport

	// pass HTTP client through context for AWS SDK
	ctx = context.WithValue(ctx, "aws_http_client", httpClient)

	// configure AWS SDK to use mock endpoints
	os.Setenv("AWS_ENDPOINT_URL", "https://localhost:9001")
	os.Setenv("AWS_ENDPOINT_URL_SECURITYHUB", "https://localhost:9001")
	os.Setenv("AWS_ENDPOINT_URL_S3", "https://localhost:9003")

	// configure Slack API URL for mock server
	os.Setenv("SLACK_API_URL", "https://localhost:9002/api")

	// enable debug mode for verbose scenarios
	if verbose {
		os.Setenv("APP_DEBUG_ENABLED", "true")
	}

	// apply config overrides
	for key, value := range scenario.ConfigOverrides {
		os.Setenv(key, value)
	}

	cfg, err := app.NewConfig()
	if err != nil {
		return fmt.Errorf("config creation failed: %w", err)
	}

	if verbose {
		fmt.Printf("  Auto-close rules configured: %d\n", len(cfg.AutoCloseRules))
	}

	appLogger := slog.New(&testHandler{prefix: "  ", verbose: verbose, w: os.Stdout})

	a, err := app.New(ctx, cfg, appLogger)
	if err != nil {
		return fmt.Errorf("app creation failed: %w", err)
	}

	if verbose {
		fmt.Printf("\n  Application Output:\n")
	}

	var evt awsEvent.CloudWatchEvent
	if err := json.Unmarshal(scenario.EventPayload, &evt); err != nil {
		return fmt.Errorf("unmarshal event payload failed: %w", err)
	}

	if verbose {
		fmt.Printf("  Processing event...\n")
	}

	// convert Lambda CloudWatch event to runtime-agnostic event input
	input := events.SecurityHubEventInput{
		EventID:    evt.ID,
		DetailType: evt.DetailType,
		Detail:     evt.Detail,
	}

	processErr := a.Process(ctx, input)

	if scenario.ExpectError {
		if processErr == nil {
			return fmt.Errorf("expected error but processing succeeded")
		}
		if verbose {
			fmt.Printf("  ✓ Expected error occurred: %v\n", processErr)
		}
	} else {
		if processErr != nil {
			return fmt.Errorf("process event failed: %w", processErr)
		}
		if verbose {
			fmt.Printf("  ✓ Event processed successfully\n")
		}
	}

	time.Sleep(500 * time.Millisecond)

	securityhubReqs := securityhubMock.GetRequests()
	slackReqs := slackMock.GetRequests()
	s3Reqs := s3Mock.GetRequests()

	allReqs := make(map[string][]RequestRecord)
	allReqs["securityhub"] = securityhubReqs
	allReqs["slack"] = slackReqs
	allReqs["s3"] = s3Reqs

	totalCalls := len(securityhubReqs) + len(slackReqs) + len(s3Reqs)

	if verbose {
		fmt.Printf("\n")
	}

	if err := validateExpectedCalls(scenario.ExpectedCalls, allReqs); err != nil {
		fmt.Printf("\n  Validation:\n")
		fmt.Printf("  ✗ FAILED: %v\n", err)
		fmt.Printf("\n  All captured requests:\n")
		if len(securityhubReqs) > 0 {
			fmt.Printf("    SecurityHub (%d):\n", len(securityhubReqs))
			for i, req := range securityhubReqs {
				fmt.Printf("      [%d] %s %s\n", i+1, req.Method, req.Path)
			}
		}
		if len(slackReqs) > 0 {
			fmt.Printf("    Slack (%d):\n", len(slackReqs))
			for i, req := range slackReqs {
				fmt.Printf("      [%d] %s %s\n", i+1, req.Method, req.Path)
			}
		}
		if len(s3Reqs) > 0 {
			fmt.Printf("    S3 (%d):\n", len(s3Reqs))
			for i, req := range s3Reqs {
				fmt.Printf("      [%d] %s %s\n", i+1, req.Method, req.Path)
			}
		}
		return err
	}

	duration := time.Since(startTime)

	if verbose {
		fmt.Printf("  Validation:\n")
		fmt.Printf("  ✓ All expected calls verified (%d total)\n", totalCalls)
		fmt.Printf("\n")
	}

	fmt.Printf("✓ PASSED (Duration: %.2fs)\n", duration.Seconds())
	return nil
}

// validateExpectedCalls verifies that all expected HTTP calls were captured
// by the mock servers.
func validateExpectedCalls(expected []ExpectedCall, allReqs map[string][]RequestRecord) error {
	for _, exp := range expected {
		reqs := allReqs[exp.Service]
		found := false
		for _, req := range reqs {
			if req.Method == exp.Method && matchPath(req.Path, exp.Path) {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("expected call not found: %s %s %s", exp.Service, exp.Method, exp.Path)
		}
	}
	return nil
}
