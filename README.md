# aws-securityhubv2-bot

AWS Lambda bot that processes **AWS Security Hub v2** findings with configurable auto-close rules and optional Slack notifications.

> **Important:** Security Hub v2 only (OCSF format). Not directly compatible with original Security Hub CSPM (ASFF format).

## Features

* **auto-close rules** - suppress/resolve findings via JSON filters (type, severity, tags, accounts, regions)
* **optional slack** - rich notifications with context and remediation links
* **flexible config** - environment variables or S3 for rule storage
* **multi-service** - GuardDuty, Inspector, Macie, IAM Access Analyzer, Security Hub CSPM

---

## Quick Start

### Build

```bash
mkdir -p dist
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -C cmd/lambda -o ../../dist/bootstrap
cd dist && zip deployment.zip bootstrap && cd ..
```

### Deploy Lambda

1. **IAM role** with `AWSLambdaBasicExecutionRole` + `securityhub:BatchUpdateFindingsV2`
2. **Create function** using `deployment.zip` (runtime: `provided.al2023`, handler: `bootstrap`)
3. **EventBridge rule** targeting the Lambda:
   ```json
   {
     "source": ["aws.securityhub"],
     "detail-type": ["Findings Imported V2"]
   }
   ```
4. **Configure** using environment variables below

---

## Configuration

### Auto-Close Rules

| Name                               | Description                                        |
| ---------------------------------- | -------------------------------------------------- |
| `APP_AUTO_CLOSE_RULES`             | JSON array of auto-close rules (see examples)      |
| `APP_AUTO_CLOSE_RULES_S3_BUCKET`   | S3 bucket for rules (for large rule sets)          |
| `APP_AUTO_CLOSE_RULES_S3_PREFIX`   | S3 prefix for rules (default: `rules/`)            |

Use environment variables, S3, or both. Environment rules evaluated first.

### Slack (Optional)

| Name                 | Description                               |
| -------------------- | ----------------------------------------- |
| `APP_SLACK_TOKEN`    | Bot token with `chat:write` scope         |
| `APP_SLACK_CHANNEL`  | Channel ID (e.g., `C000XXXXXXX`)          |

### Additional

| Name                              | Description                              |
| --------------------------------- | ---------------------------------------- |
| `APP_DEBUG_ENABLED`               | Verbose logging (default: `false`)       |
| `APP_AWS_CONSOLE_URL`             | Base console URL                         |
| `APP_AWS_ACCESS_PORTAL_URL`       | Federated access portal URL              |
| `APP_AWS_ACCESS_ROLE_NAME`        | IAM role for portal                      |
| `APP_AWS_SECURITYHUBV2_REGION`    | Centralized SecurityHub region           |

---

## Examples

### Basic Rule: Suppress GitHub Runner Findings

```json
[
  {
    "name": "auto-close-github-runners",
    "enabled": true,
    "filters": {
      "finding_types": ["Execution:Runtime/NewBinaryExecuted"],
      "resource_tags": [{"name": "component-type", "value": "github-action-runners"}]
    },
    "action": {
      "status_id": 5,
      "comment": "Auto-archived: Expected CI/CD behavior"
    },
    "skip_notification": true
  }
]
```

See [examples/github-actions-runner-example.md](examples/github-actions-runner-example.md) for detailed walkthrough.

### Multiple Rules

```json
[
  {
    "name": "suppress-inspector-low-dev",
    "filters": {
      "product_name": ["Inspector"],
      "severity": ["Low"],
      "accounts": ["123456789012"]
    },
    "action": {"status_id": 3, "comment": "Auto-suppressed: Low severity in dev"},
    "skip_notification": false
  },
  {
    "name": "resolve-approved-scans",
    "filters": {
      "finding_types": ["Recon:EC2/PortProbeUnprotectedPort"],
      "resource_tags": [{"name": "ScannerApproved", "value": "true"}]
    },
    "action": {"status_id": 4, "comment": "Auto-resolved: Approved scanner"},
    "skip_notification": true
  }
]
```

### Filter Reference

All filters use AND logic. First matching rule wins.

| Field             | Type         | Example                                       |
| ----------------- | ------------ | --------------------------------------------- |
| `finding_types`   | `[]string`   | `["Execution:Runtime/NewBinaryExecuted"]`     |
| `severity`        | `[]string`   | `["Critical", "High"]`                        |
| `product_name`    | `[]string`   | `["GuardDuty", "Inspector"]`                  |
| `resource_types`  | `[]string`   | `["AWS::EC2::Instance"]`                      |
| `resource_tags`   | `[]object`   | `[{"name": "Environment", "value": "dev"}]`   |
| `accounts`        | `[]string`   | `["123456789012"]`                            |
| `regions`         | `[]string`   | `["us-east-1"]`                               |


### Status IDs

Based on [OCSF 1.6.0 specification](https://schema.ocsf.io/1.6.0/classes/detection_finding):

| ID  | Status        | Description                                                                      |
| --- | ------------- | -------------------------------------------------------------------------------- |
| 0   | Unknown       | The status is unknown                                                            |
| 1   | New           | The finding is new and yet to be reviewed                                        |
| 2   | In Progress   | The finding is under review                                                      |
| 3   | Suppressed    | The finding was reviewed, determined to be benign or false positive, suppressed  |
| 4   | Resolved      | The finding was reviewed, remediated and is now considered resolved              |
| 5   | Archived      | The finding was archived                                                         |
| 6   | Deleted       | The finding was deleted (e.g., created in error)                                 |
| 99  | Other         | The status is not mapped (see status attribute for source-specific value)        |

Common usage: `status_id: 5` (Archived) for accepted behavior, `status_id: 4` (Resolved) for remediated issues, `status_id: 3` (Suppressed) for false positives.

### S3 Rule Storage

For large rule sets (>4KB), store rules in S3. Supports single rule per file, arrays of rules, or mixed approach:

```
s3://my-rules-bucket/rules/
├── guardduty/
│   └── suppress-dev.json
├── inspector/
│   └── all-rules.json
└── auto-close-runners.json
```

Requirements: Lambda needs `s3:GetObject` and `s3:ListBucket` on the bucket. Only `.json` files processed.

---

## EventBridge Filters (Optional)

Filter by severity for high-volume environments:

```json
{
  "source": ["aws.securityhub"],
  "detail-type": ["Findings Imported V2"],
  "detail": {
    "findings": {
      "severity": ["Critical", "High"]
    }
  }
}
```

Or by source service:

```json
{
  "detail": {
    "findings": {
      "metadata": {
        "product": {
          "name": ["GuardDuty", "Inspector"]
        }
      }
    }
  }
}
```

---

## IAM Permissions

Lambda role needs `AWSLambdaBasicExecutionRole` plus:

```json
{
  "Effect": "Allow",
  "Action": ["securityhub:BatchUpdateFindingsV2"],
  "Resource": "*"
}
```

If using S3 rules, add:

```json
{
  "Effect": "Allow",
  "Action": ["s3:GetObject", "s3:ListBucket"],
  "Resource": [
    "arn:aws:s3:::my-rules-bucket",
    "arn:aws:s3:::my-rules-bucket/*"
  ]
}
```

---

## How It Works

1. EventBridge triggers Lambda on "Findings Imported V2"
2. Parse OCSF finding from event
3. Evaluate auto-close rules in order (first match wins)
4. If matched: call `BatchUpdateFindingsV2` with status + comment
5. Send Slack notification (unless `skip_notification: true`)
6. If no match: send to Slack if finding is alertable

---

## Local Development

```bash
cp .env.example .env  # edit values
go run -C cmd/sample .
```

Uses OCSF findings from `fixtures/samples.json`. Requires AWS credentials for auto-close testing.

---

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
