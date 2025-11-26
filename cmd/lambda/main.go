package main

import (
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"sync"

	awsevents "github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/cruxstack/aws-securityhubv2-bot/internal/app"
	"github.com/cruxstack/aws-securityhubv2-bot/internal/events"
)

var (
	once    sync.Once
	a       *app.App
	logger  *slog.Logger
	initErr error
)

func LambdaHandler(ctx context.Context, evt awsevents.CloudWatchEvent) error {
	once.Do(func() {
		logger = slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
			Level: slog.LevelInfo,
		}))

		cfg, err := app.NewConfig()
		if err != nil {
			initErr = err
			return
		}

		if cfg.DebugEnabled {
			logger = slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
				Level: slog.LevelDebug,
			}))
		}

		a, initErr = app.New(ctx, cfg, logger)
	})

	if initErr != nil {
		return initErr
	}

	if a.Config.DebugEnabled {
		j, _ := json.Marshal(evt)
		logger.Debug("received event", "event_id", evt.ID, "detail_type", evt.DetailType, "event", string(j))
	}

	// convert Lambda CloudWatch event to runtime-agnostic event input
	input := events.SecurityHubEventInput{
		EventID:    evt.ID,
		DetailType: evt.DetailType,
		Detail:     evt.Detail,
	}

	return a.Process(ctx, input)
}

func main() {
	lambda.Start(LambdaHandler)
}
