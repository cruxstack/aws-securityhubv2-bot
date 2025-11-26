# Integration Tests

Offline integration tests that validate bot behavior with Security Hub v2 events
and auto-close rules using local mock servers. Tests use real SDK clients
against production code paths, so no mocking of `internal/` packages.

## Quick Start

```bash
# run all tests
make test-verify

# debug with verbose output
make test-verify-verbose

# run specific scenario
go run ./cmd/verify -filter="auto_close_github_runner"
```

No setup required—uses `.env.test` automatically (dummy credentials, never sent to real APIs).

## How It Works

Tests run production code against local HTTPS mock servers (ports 9001-9003):

1. Mock servers start with self-signed TLS certificates
2. AWS/Slack SDKs are redirected to mocks via environment variables
3. Requests are captured and validated against expected API calls
4. Mock responses return predefined JSON from scenario definitions

## Scenarios

Current test suite in `fixtures/scenarios.json`:

- **auto_close_github_runner_new_binary** - Auto-close by resource tags
- **auto_close_inspector_low_severity_in_dev** - Close by product, severity, account with notification
- **no_match_sends_notification** - Unmatched findings trigger Slack
- **multiple_rules_first_match_wins** - Rule precedence validation
- **disabled_rule_not_applied** - Disabled rules are skipped
- **suppress_macie_findings_in_sandbox** - Multi-value filter matching

Each scenario defines:

- CloudWatch Event payload (OCSF finding)
- Config overrides (auto-close rules, Slack settings)
- Expected API calls (method, path patterns with wildcard support)
- Mock responses (status code, body)

See `fixtures/scenarios.json` for complete examples.

## Adding Tests

1. Add scenario to `fixtures/scenarios.json`
2. Define event payload and config overrides
3. Specify expected API calls and mock responses
4. Run `make test-verify`

## Debugging

Use `-verbose` flag for detailed output showing:
- Real-time HTTP request/response logging
- Application logs during execution
- All captured requests on test failure
- Missing or unexpected API calls

## Architecture

```
CloudWatch Event → App → AWS/Slack SDK → Mock HTTPS Server (localhost)
                                              ↓
                                         Capture & Validate
```

Mock servers:
- SecurityHub: `https://localhost:9001` (via `AWS_ENDPOINT_URL`)
- Slack: `https://localhost:9002/api` (via `APP_SLACK_API_URL`)
- S3: `https://localhost:9003` (if needed)

Implementation:
- `mock.go`: http server
- `tls.go`: certs
- `match.go`: path matching
- `scenario.go`: orchestration
- `logger.go`: log capture

## Limitations

- fixed ports prevent parallel execution
- tests run serially
- requires dummy aws credentials in environment
