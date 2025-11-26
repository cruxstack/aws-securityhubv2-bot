package notifiers

import (
	"context"

	"github.com/cruxstack/aws-securityhubv2-bot/internal/events"
)

type Notifier interface {
	Notify(ctx context.Context, finding *events.SecurityHubV2Finding) error
}
