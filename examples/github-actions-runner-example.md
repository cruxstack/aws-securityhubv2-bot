# Example: Auto-Close GitHub Actions Runner Findings

This example demonstrates how to automatically close GuardDuty `Execution:Runtime/NewBinaryExecuted` findings for GitHub Actions runners. This is a common pattern for CI/CD environments where runners regularly execute newly created binaries as part of the build process.

## The Problem

When using GitHub Actions runners (self-hosted or ephemeral), GuardDuty Runtime Monitoring generates `NewBinaryExecuted` findings when containers or EC2 instances execute newly created binaries. This is expected behavior for CI/CD workflows but creates noise in Security Hub.

For example:
- Build tools creating and executing compiled binaries
- Package managers downloading and running install scripts
- Test runners executing newly built test binaries
- Deployment tools creating temporary executables

## The Solution

Use an auto-close rule that:
1. Matches the specific finding type (`Execution:Runtime/NewBinaryExecuted`)
2. Filters by resource tags (e.g., `component-type=github-action-runners`)
3. Automatically suppresses the finding
4. Skips Slack notifications (since it's not a security issue)

## Configuration

### Environment Variable

```bash
export APP_AUTO_CLOSE_RULES='[
  {
    "name": "auto-close-github-runner-new-binaries",
    "enabled": true,
    "filters": {
      "finding_types": [
        "Execution:Runtime/NewBinaryExecuted"
      ],
      "resource_tags": [
        {
          "name": "component-type",
          "value": "github-action-runners"
        }
      ]
    },
    "action": {
      "status_id": 5,
      "comment": "Auto-closed: Expected behavior for GitHub Actions CI/CD runners"
    },
    "skip_notification": true
  }
]'
```

### Lambda Environment Variables (AWS Console)

For better readability in the AWS Console, you can format it on a single line:

```
{"name":"auto-close-github-runner-new-binaries","enabled":true,"filters":{"finding_types":["Execution:Runtime/NewBinaryExecuted"],"resource_tags":[{"name":"component-type","value":"github-action-runners"}]},"action":{"status_id":5,"comment":"Auto-closed: Expected behavior for GitHub Actions CI/CD runners"},"skip_notification":true}
```

Then wrap it in an array:
```
[{...}]
```

## IAM Policy

Add this inline policy to your Lambda execution role:

```jsonc
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowAutoCloseFindings",
      "Effect": "Allow",
      "Action": [
        "securityhub:BatchUpdateFindingsV2"
      ],
      "Resource": "*"
    }
  ]
}
```

## How It Works

### 1. EventBridge Event Arrives

When GuardDuty Runtime Monitoring detects a newly created binary being executed, Security Hub receives the finding and EventBridge triggers your Lambda:

```jsonc
{
  "source": "aws.securityhub",
  "detail-type": "Findings Imported V2",
  "detail": {
    "findings": [{
      "finding_info": {
        "title": "A container has executed a newly created binary file.",
        "types": [
          "Threats",
          "Execution:Runtime/NewBinaryExecuted"
        ]
      },
      "resources": [{
        "tags": [
          {"name": "component-type", "value": "github-action-runners"},
          {"name": "ghr:Application", "value": "github-action-runner"},
          // ...
        ]
      }],
      "evidences": [{
        "actor": {
          "process": {
            "name": "kubectl",
            "path": "/opt/actions-runner/_work/_tool/kind/v0.22.0/amd64/kubectl/bin/kubectl"
          }
        }
      }]
    }]
  }
}
```

### 2. Lambda Evaluates Rules

The bot:
1. Parses the OCSF finding
2. Checks if finding type matches: `Execution:Runtime/NewBinaryExecuted` ✓
3. Searches resources for tag: `component-type=github-action-runners` ✓
4. Rule matches!

### 3. Auto-Close Action Executes

The bot calls BatchUpdateFindingsV2:

```go
input := &securityhub.BatchUpdateFindingsV2Input{
    MetadataUids: []string{"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"},
    StatusId:     aws.Int32(5),  // SUPPRESSED
    Comment:      aws.String("Auto-closed: Expected behavior for GitHub Actions CI/CD runners"),
}
```

### 4. Notification Skipped

Since `skip_notification: true`, no Slack message is sent.

### 5. Result

- Finding status: `New` → `Suppressed`
- Finding comment: "Auto-closed: Expected behavior for GitHub Actions CI/CD runners"
- Slack: No notification
- CloudWatch Logs: `auto-closed finding ... using rule 'auto-close-github-runner-new-binaries'`

## Sample Finding Data

See `fixtures/samples.json` (1st finding) for the exact OCSF structure that matches this rule. The finding includes:
- Process ancestry showing GitHub Actions runner chain
- File hash of executed binary (SHA-256)
- EC2 instance details with runner tags
- Network interface information

## Variations

### Also notify (audit trail)

Keep Slack notifications enabled for visibility:

```jsonc
{
  "name": "auto-close-github-runner-new-binaries",
  "enabled": true,
  "filters": {
    // ...
  },
  "action": {
    // ...
  },
  "skip_notification": false  // changed from true
}
```

### Match multiple environments or teams

Use broader tag patterns to match different runner deployments:

```jsonc
{
  "name": "auto-close-all-ci-runner-binaries",
  "enabled": true,
  "filters": {
    "finding_types": [
      "Execution:Runtime/NewBinaryExecuted"
    ],
    "resource_tags": [
      {
        "name": "environment",
        "value": "ci"
      }
    ]
  },
  "action": {
    "status_id": 5,
    "comment": "Auto-closed: Expected behavior for CI/CD environment"
  },
  "skip_notification": true
}
```

### Match by account instead of tags

Auto-close findings in dedicated CI/CD accounts:

```jsonc
{
  "name": "auto-close-ci-account-new-binaries",
  "enabled": true,
  "filters": {
    "finding_types": [
      "Execution:Runtime/NewBinaryExecuted"
    ],
    "accounts": [
      "123456789012"
    ]
  },
  "action": {
    "status_id": 5,
    "comment": "Auto-closed: Expected behavior in CI/CD account"
  },
  "skip_notification": true
}
```

### Resolve instead of suppress

```jsonc
{
  "action": {
    "status_id": 3,  // RESOLVED instead of SUPPRESSED
    "comment": "Auto-resolved: Known safe behavior for GitHub Actions runners"
  }
}
```

## Monitoring

### CloudWatch Logs

Look for these log messages:

**Rule matched:**
```
processing finding: eeeeeeee... (status: New, severity: Medium)
finding matched rule: auto-close-github-runner-new-binaries
auto-closed finding eeeeeeee... using rule 'auto-close-github-runner-new-binaries'
```

**Rule not matched:**
```
processing finding: abc123... (status: New, severity: High)
```
(No "matched rule" message - finding proceeds to normal notification)

### Security Hub Console

1. Navigate to Security Hub v2 → Threats
2. Search for finding type: `Execution:Runtime/NewBinaryExecuted`
3. Find the specific instance finding and check "Finding history" tab
4. Should see update with:
   - Status: New → Suppressed
   - Comment: "Auto-closed: Expected behavior for GitHub Actions CI/CD runners"
   - Updated by: aws-securityhubv2-bot

## Multiple Rules Example

Combine multiple CI/CD-related auto-close rules:

```jsonc
[
  {
    "name": "auto-close-github-runner-new-binaries",
    "enabled": true,
    "filters": {
      "finding_types": ["Execution:Runtime/NewBinaryExecuted"],
      "resource_tags": [{"name": "component-type", "value": "github-action-runners"}]
    },
    "action": {
      "status_id": 5,
      "comment": "Auto-closed: Expected behavior for GitHub Actions CI/CD runners"
    },
    "skip_notification": true
  },
  {
    "name": "auto-close-github-runner-docker-commands",
    "enabled": true,
    "filters": {
      "finding_types": ["Execution:Runtime/DockerCommandWithUnknownArgs"],
      "resource_tags": [{"name": "component-type", "value": "github-action-runners"}]
    },
    "action": {
      "status_id": 5,
      "comment": "Auto-closed: Expected Docker behavior in CI/CD runners"
    },
    "skip_notification": true
  },
  {
    "name": "auto-close-build-environment-network-activity",
    "enabled": true,
    "filters": {
      "finding_types": ["UnauthorizedAccess:EC2/MaliciousIPCaller"],
      "resource_tags": [{"name": "environment", "value": "ci"}]
    },
    "action": {
      "status_id": 5,
      "comment": "Auto-closed: Known build dependency sources in CI environment"
    },
    "skip_notification": false
  }
]
```

**Note:** Rules are evaluated in order. The first matching rule wins.
