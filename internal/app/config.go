package app

import (
	"encoding/json"
	"os"
	"strconv"

	"github.com/cockroachdb/errors"
	"github.com/cruxstack/aws-securityhubv2-bot/internal/filters"
)

type Config struct {
	DebugEnabled           bool
	AwsConsoleURL          string
	AwsAccessPortalURL     string
	AwsAccessRoleName      string
	AWSSecurityHubv2Region string
	AutoCloseRules         []filters.AutoCloseRule
	AutoCloseRulesS3Bucket string
	AutoCloseRulesS3Prefix string
	SlackEnabled           bool
	SlackToken             string
	SlackChannel           string
}

func NewConfig() (*Config, error) {
	debugEnabled, _ := strconv.ParseBool(os.Getenv("APP_DEBUG_ENABLED"))

	cfg := Config{
		DebugEnabled:           debugEnabled,
		AwsConsoleURL:          os.Getenv("APP_AWS_CONSOLE_URL"),
		AwsAccessPortalURL:     os.Getenv("APP_AWS_ACCESS_PORTAL_URL"),
		AwsAccessRoleName:      os.Getenv("APP_AWS_ACCESS_ROLE_NAME"),
		AWSSecurityHubv2Region: os.Getenv("APP_AWS_SECURITYHUBV2_REGION"),
		AutoCloseRulesS3Bucket: os.Getenv("APP_AUTO_CLOSE_RULES_S3_BUCKET"),
		AutoCloseRulesS3Prefix: os.Getenv("APP_AUTO_CLOSE_RULES_S3_PREFIX"),
		SlackToken:             os.Getenv("APP_SLACK_TOKEN"),
		SlackChannel:           os.Getenv("APP_SLACK_CHANNEL"),
	}

	if cfg.AwsConsoleURL == "" {
		cfg.AwsConsoleURL = "https://console.aws.amazon.com"
	}

	if cfg.AutoCloseRulesS3Prefix == "" {
		cfg.AutoCloseRulesS3Prefix = "rules/"
	}

	rulesJSON := os.Getenv("APP_AUTO_CLOSE_RULES")
	if rulesJSON != "" {
		rules, err := parseAutoCloseRules(rulesJSON)
		if err != nil {
			return nil, errors.Wrap(err, "failed to parse APP_AUTO_CLOSE_RULES")
		}
		cfg.AutoCloseRules = rules
	}

	if cfg.SlackToken != "" && cfg.SlackChannel == "" {
		return nil, errors.New("APP_SLACK_TOKEN requires APP_SLACK_CHANNEL")
	}
	if cfg.SlackToken == "" && cfg.SlackChannel != "" {
		return nil, errors.New("APP_SLACK_CHANNEL requires APP_SLACK_TOKEN")
	}

	cfg.SlackEnabled = cfg.SlackToken != "" && cfg.SlackChannel != ""

	return &cfg, nil
}

// parseAutoCloseRules parses auto-close rules from either JSON or JSON-encoded string format.
// supports both direct JSON arrays and JSON strings that need unescaping.
func parseAutoCloseRules(input string) ([]filters.AutoCloseRule, error) {
	var rules []filters.AutoCloseRule

	// try parsing as direct JSON first
	err := json.Unmarshal([]byte(input), &rules)
	if err == nil {
		return rules, nil
	}

	// if that fails, try parsing as JSON-encoded string (double-encoded)
	var unescaped string
	if err := json.Unmarshal([]byte(input), &unescaped); err != nil {
		// if both fail, return the original error
		return nil, errors.Wrap(err, "invalid JSON format - expected array or JSON-encoded string")
	}

	// parse the unescaped string
	if err := json.Unmarshal([]byte(unescaped), &rules); err != nil {
		return nil, errors.Wrap(err, "invalid JSON in encoded string")
	}

	return rules, nil
}
