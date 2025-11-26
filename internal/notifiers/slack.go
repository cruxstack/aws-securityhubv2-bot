package notifiers

import (
	"context"
	"os"

	"github.com/cruxstack/aws-securityhubv2-bot/internal/events"
	"github.com/slack-go/slack"
)

type SlackNotifier struct {
	client              *slack.Client
	channel             string
	consoleURL          string
	accessPortalURL     string
	accessRoleName      string
	securityHubv2Region string
}

func NewSlackNotifier(token, channel, consoleURL, accessPortalURL, accessRoleName, securityHubv2Region string) *SlackNotifier {
	// allow overriding slack api url for testing
	opts := []slack.Option{}
	if apiURL := os.Getenv("SLACK_API_URL"); apiURL != "" {
		opts = append(opts, slack.OptionAPIURL(apiURL+"/"))
	}

	return &SlackNotifier{
		client:              slack.New(token, opts...),
		channel:             channel,
		consoleURL:          consoleURL,
		accessPortalURL:     accessPortalURL,
		accessRoleName:      accessRoleName,
		securityHubv2Region: securityHubv2Region,
	}
}

func (s *SlackNotifier) Notify(ctx context.Context, finding *events.SecurityHubV2Finding) error {
	m0, m1 := finding.SlackMessage(
		s.consoleURL,
		s.accessPortalURL,
		s.accessRoleName,
		s.securityHubv2Region,
	)

	_, _, err := s.client.PostMessage(s.channel, m0, m1)
	return err
}
