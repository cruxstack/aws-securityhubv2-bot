package actions

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/securityhub"
	"github.com/cockroachdb/errors"
	"github.com/cruxstack/aws-securityhubv2-bot/internal/events"
)

type FindingCloser struct {
	client *securityhub.Client
}

func NewFindingCloser(client *securityhub.Client) *FindingCloser {
	return &FindingCloser{
		client: client,
	}
}

func (c *FindingCloser) CloseFinding(ctx context.Context, finding *events.SecurityHubV2Finding, statusID int32, comment string) error {
	input := &securityhub.BatchUpdateFindingsV2Input{
		MetadataUids: []string{finding.Metadata.UID},
		StatusId:     aws.Int32(statusID),
		Comment:      aws.String(comment),
	}

	output, err := c.client.BatchUpdateFindingsV2(ctx, input)
	if err != nil {
		return errors.Wrap(err, "failed to update finding")
	}

	if len(output.UnprocessedFindings) > 0 {
		unprocessed := output.UnprocessedFindings[0]
		return errors.Newf("failed to update finding %s: %s - %s",
			finding.Metadata.UID,
			string(unprocessed.ErrorCode),
			aws.ToString(unprocessed.ErrorMessage))
	}

	return nil
}
