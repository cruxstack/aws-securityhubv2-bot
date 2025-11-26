package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/joho/godotenv"

	"github.com/cruxstack/aws-securityhubv2-bot/internal/app"
	"github.com/cruxstack/aws-securityhubv2-bot/internal/events"
)

func main() {
	ctx := context.Background()

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	}))

	envpath := filepath.Join(".env")
	logger.Info("loading environment", "path", envpath)
	if _, err := os.Stat(envpath); err == nil {
		_ = godotenv.Load(envpath)
	}

	cfg, err := app.NewConfig()
	if err != nil {
		logger.Error("failed to load config", "error", err)
		os.Exit(1)
	}

	a, err := app.New(ctx, cfg, logger)
	if err != nil {
		logger.Error("failed to create app", "error", err)
		os.Exit(1)
	}

	path := filepath.Join("fixtures", "samples.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		logger.Error("failed to read fixtures", "error", err, "path", path)
		os.Exit(1)
	}

	var findings []json.RawMessage
	if err := json.Unmarshal(raw, &findings); err != nil {
		logger.Error("failed to unmarshal fixtures", "error", err)
		os.Exit(1)
	}

	logger.Info("processing samples", "count", len(findings))

	for i, finding := range findings {
		detail := map[string]any{
			"findings": []json.RawMessage{finding},
		}
		detailBytes, err := json.Marshal(detail)
		if err != nil {
			logger.Error("failed to marshal detail", "error", err, "sample", i)
			os.Exit(1)
		}

		evt := events.SecurityHubEventInput{
			EventID:    fmt.Sprintf("sample-%d", i),
			DetailType: "Findings Imported V2",
			Detail:     detailBytes,
		}

		if err := a.Process(ctx, evt); err != nil {
			logger.Error("failed to process sample", "error", err, "sample", i)
			os.Exit(1)
		}
		logger.Info("processed sample successfully", "sample", i)
	}
}
