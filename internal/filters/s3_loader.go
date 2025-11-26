package filters

import (
	"context"
	"encoding/json"
	"io"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/cockroachdb/errors"
)

type S3Client interface {
	ListObjectsV2(ctx context.Context, params *s3.ListObjectsV2Input, optFns ...func(*s3.Options)) (*s3.ListObjectsV2Output, error)
	GetObject(ctx context.Context, params *s3.GetObjectInput, optFns ...func(*s3.Options)) (*s3.GetObjectOutput, error)
}

type S3RulesLoader struct {
	client S3Client
}

func NewS3RulesLoader(client S3Client) *S3RulesLoader {
	return &S3RulesLoader{
		client: client,
	}
}

func (l *S3RulesLoader) LoadRules(ctx context.Context, bucket, prefix string) ([]AutoCloseRule, error) {
	keys, err := l.listObjects(ctx, bucket, prefix)
	if err != nil {
		return nil, errors.Wrap(err, "failed to list S3 objects")
	}

	if len(keys) == 0 {
		return nil, errors.Newf("no objects found in s3://%s/%s", bucket, prefix)
	}

	var allRules []AutoCloseRule
	for _, key := range keys {
		if !strings.HasSuffix(key, ".json") {
			continue
		}

		rules, err := l.loadRulesFromObject(ctx, bucket, key)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to load rules from s3://%s/%s", bucket, key)
		}

		allRules = append(allRules, rules...)
	}

	if len(allRules) == 0 {
		return nil, errors.Newf("no rules loaded from s3://%s/%s", bucket, prefix)
	}

	return allRules, nil
}

func (l *S3RulesLoader) listObjects(ctx context.Context, bucket, prefix string) ([]string, error) {
	var keys []string
	paginator := s3.NewListObjectsV2Paginator(l.client, &s3.ListObjectsV2Input{
		Bucket: aws.String(bucket),
		Prefix: aws.String(prefix),
	})

	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}

		for _, obj := range page.Contents {
			if obj.Key != nil {
				keys = append(keys, *obj.Key)
			}
		}
	}

	return keys, nil
}

func (l *S3RulesLoader) loadRulesFromObject(ctx context.Context, bucket, key string) ([]AutoCloseRule, error) {
	result, err := l.client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		return nil, err
	}
	defer result.Body.Close()

	data, err := io.ReadAll(result.Body)
	if err != nil {
		return nil, errors.Wrap(err, "failed to read object body")
	}

	return parseRules(data)
}

func parseRules(data []byte) ([]AutoCloseRule, error) {
	data = []byte(strings.TrimSpace(string(data)))
	if len(data) == 0 {
		return nil, nil
	}

	if data[0] == '[' {
		var rules []AutoCloseRule
		if err := json.Unmarshal(data, &rules); err != nil {
			return nil, errors.Wrap(err, "failed to parse rules array")
		}
		return rules, nil
	}

	var rule AutoCloseRule
	if err := json.Unmarshal(data, &rule); err != nil {
		return nil, errors.Wrap(err, "failed to parse single rule")
	}
	return []AutoCloseRule{rule}, nil
}
