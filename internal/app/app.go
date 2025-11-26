package app

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/securityhub"
	"github.com/cockroachdb/errors"
	"github.com/cruxstack/aws-securityhubv2-bot/internal/actions"
	"github.com/cruxstack/aws-securityhubv2-bot/internal/events"
	"github.com/cruxstack/aws-securityhubv2-bot/internal/filters"
	"github.com/cruxstack/aws-securityhubv2-bot/internal/notifiers"
)

type App struct {
	Config        *Config
	FilterEngine  *filters.FilterEngine
	FindingCloser *actions.FindingCloser
	Notifier      notifiers.Notifier
	Logger        *slog.Logger
}

func New(ctx context.Context, cfg *Config, logger *slog.Logger) (*App, error) {
	// allow custom HTTP client from context (for testing)
	configOpts := []func(*config.LoadOptions) error{}
	if httpClient, ok := ctx.Value("aws_http_client").(*http.Client); ok && httpClient != nil {
		configOpts = append(configOpts, config.WithHTTPClient(httpClient))
	}

	awsCfg, err := config.LoadDefaultConfig(ctx, configOpts...)
	if err != nil {
		return nil, errors.Wrap(err, "failed to load aws config - check credentials and region")
	}

	app := &App{
		Config:        cfg,
		FindingCloser: actions.NewFindingCloser(securityhub.NewFromConfig(awsCfg)),
		Logger:        logger,
	}

	rules := cfg.AutoCloseRules

	if cfg.AutoCloseRulesS3Bucket != "" {
		s3Client := s3.NewFromConfig(awsCfg)
		loader := filters.NewS3RulesLoader(s3Client)

		s3Rules, err := app.LoadRulesFromS3(ctx, loader, cfg.AutoCloseRulesS3Bucket, cfg.AutoCloseRulesS3Prefix)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to load rules from s3://%s/%s", cfg.AutoCloseRulesS3Bucket, cfg.AutoCloseRulesS3Prefix)
		}

		if len(cfg.AutoCloseRules) > 0 {
			app.Logger.Info("loaded rules from S3 and env", "s3_rules", len(s3Rules), "env_rules", len(cfg.AutoCloseRules))
			rules = append(cfg.AutoCloseRules, s3Rules...)
		} else {
			app.Logger.Info("loaded rules from S3", "count", len(s3Rules))
			rules = s3Rules
		}
	}

	app.FilterEngine = filters.NewFilterEngine(rules)

	if cfg.SlackEnabled {
		app.Notifier = notifiers.NewSlackNotifier(
			cfg.SlackToken,
			cfg.SlackChannel,
			cfg.AwsConsoleURL,
			cfg.AwsAccessPortalURL,
			cfg.AwsAccessRoleName,
			cfg.AWSSecurityHubv2Region,
		)
	}

	return app, nil
}

type EventDetail struct {
	Findings []json.RawMessage `json:"findings"`
}

func (a *App) ParseEvent(e events.SecurityHubEventInput) (*events.SecurityHubV2Finding, error) {
	if e.DetailType != "Findings Imported V2" {
		return nil, errors.Newf("unsupported event type: %s (expected 'Findings Imported V2')", e.DetailType)
	}

	var detail EventDetail
	if err := json.Unmarshal(e.Detail, &detail); err != nil {
		return nil, errors.Wrap(err, "failed to unmarshal event detail")
	}

	if len(detail.Findings) == 0 {
		return nil, errors.Newf("event contains no findings (event_id: %s)", e.EventID)
	}

	return events.NewSecurityHubFinding(detail.Findings[0])
}

func (a *App) LoadRulesFromS3(ctx context.Context, loader *filters.S3RulesLoader, bucket, prefix string) ([]filters.AutoCloseRule, error) {
	a.Logger.Debug("loading rules from S3", "bucket", bucket, "prefix", prefix)

	rules, err := loader.LoadRules(ctx, bucket, prefix)
	if err != nil {
		return nil, err
	}

	a.Logger.Debug("loaded rules from S3", "count", len(rules))
	return rules, nil
}

func (a *App) CloseFinding(ctx context.Context, finding *events.SecurityHubV2Finding, statusID int32, comment string) error {
	a.Logger.Debug("closing finding",
		"uid", finding.Metadata.UID,
		"status_id", statusID)

	err := a.FindingCloser.CloseFinding(ctx, finding, statusID, comment)
	if err != nil {
		return err
	}

	return nil
}

func (a *App) SendNotification(ctx context.Context, finding *events.SecurityHubV2Finding) error {
	a.Logger.Debug("sending notification",
		"uid", finding.Metadata.UID)

	err := a.Notifier.Notify(ctx, finding)
	if err != nil {
		a.Logger.Error("failed to send notification",
			"error", err,
			"uid", finding.Metadata.UID)
		return err
	}

	a.Logger.Info("sent notification",
		"uid", finding.Metadata.UID)

	return nil
}

func (a *App) Process(ctx context.Context, evt events.SecurityHubEventInput) error {
	finding, err := a.ParseEvent(evt)
	if err != nil {
		return err
	}

	if a.Config.DebugEnabled {
		a.Logger.Debug("processing finding",
			"uid", finding.Metadata.UID,
			"status", finding.Status,
			"severity", finding.Severity)
	}

	if matchedRule, matched := a.FilterEngine.FindMatchingRule(finding); matched {
		if a.Config.DebugEnabled {
			a.Logger.Debug("finding matched rule", "rule", matchedRule.Name)
		}

		err := a.CloseFinding(ctx, finding, matchedRule.Action.StatusID, matchedRule.Action.Comment)
		if err != nil {
			return errors.Wrap(err, "failed to auto-close finding")
		}

		a.Logger.Info("auto-closed finding",
			"uid", finding.Metadata.UID,
			"rule", matchedRule.Name,
			"status_id", matchedRule.Action.StatusID)

		if !matchedRule.SkipNotification && a.Notifier != nil {
			return a.SendNotification(ctx, finding)
		}

		return nil
	}

	if a.Notifier != nil && finding.IsAlertable() {
		return a.SendNotification(ctx, finding)
	}

	return nil
}
