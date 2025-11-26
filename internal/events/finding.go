package events

import (
	"encoding/json"
	"fmt"
	"net/url"
	"slices"
	"strings"

	"github.com/slack-go/slack"
)

type SecurityHubV2Finding struct {
	ActivityID   int             `json:"activity_id"`
	ActivityName string          `json:"activity_name"`
	CategoryName string          `json:"category_name"`
	CategoryUID  int             `json:"category_uid"`
	ClassName    string          `json:"class_name"`
	ClassUID     int             `json:"class_uid"`
	Cloud        Cloud           `json:"cloud"`
	Compliance   *OCSFCompliance `json:"compliance,omitempty"`
	FindingInfo  FindingInfo     `json:"finding_info"`
	Metadata     Metadata        `json:"metadata"`
	Remediation  *Remediation    `json:"remediation,omitempty"`
	Resources    []OCSFResource  `json:"resources"`
	Severity     string          `json:"severity"`
	SeverityID   int             `json:"severity_id"`
	Status       string          `json:"status"`
	StatusID     int             `json:"status_id"`
	Time         int64           `json:"time"`
	TimeDt       string          `json:"time_dt"`
	TypeName     string          `json:"type_name"`
	TypeUID      int             `json:"type_uid"`
}

type Cloud struct {
	Account struct {
		Type   string `json:"type,omitempty"`
		TypeID int    `json:"type_id,omitempty"`
		UID    string `json:"uid"`
	} `json:"account"`
	CloudPartition string `json:"cloud_partition,omitempty"`
	Provider       string `json:"provider"`
	Region         string `json:"region"`
}

type OCSFCompliance struct {
	Assessments []struct {
		Desc          string `json:"desc"`
		MeetsCriteria bool   `json:"meets_criteria"`
		Name          string `json:"name"`
	} `json:"assessments,omitempty"`
	Control           string   `json:"control,omitempty"`
	ControlParameters []any    `json:"control_parameters,omitempty"`
	Requirements      []string `json:"requirements,omitempty"`
	Standards         []string `json:"standards,omitempty"`
	Status            string   `json:"status,omitempty"`
	StatusID          int      `json:"status_id,omitempty"`
}

type FindingInfo struct {
	Analytic *struct {
		Type   string `json:"type"`
		TypeID int    `json:"type_id"`
		UID    string `json:"uid"`
	} `json:"analytic,omitempty"`
	CreatedTime     int64    `json:"created_time"`
	CreatedTimeDt   string   `json:"created_time_dt"`
	Desc            string   `json:"desc"`
	FirstSeenTime   int64    `json:"first_seen_time"`
	FirstSeenTimeDt string   `json:"first_seen_time_dt"`
	LastSeenTime    int64    `json:"last_seen_time"`
	LastSeenTimeDt  string   `json:"last_seen_time_dt"`
	ModifiedTime    int64    `json:"modified_time"`
	ModifiedTimeDt  string   `json:"modified_time_dt"`
	Product         *Product `json:"product,omitempty"`
	Title           string   `json:"title"`
	Types           []string `json:"types"`
	UID             string   `json:"uid"`
	UIDalt          string   `json:"uid_alt,omitempty"`
}

type Product struct {
	Feature *struct {
		Name string `json:"name"`
	} `json:"feature,omitempty"`
	Name       string `json:"name,omitempty"`
	UID        string `json:"uid,omitempty"`
	VendorName string `json:"vendor_name,omitempty"`
}

type Metadata struct {
	Product  MetadataProduct `json:"product"`
	Profiles []string        `json:"profiles"`
	UID      string          `json:"uid"`
	Version  string          `json:"version"`
}

type MetadataProduct struct {
	Feature *struct {
		Name string `json:"name"`
	} `json:"feature,omitempty"`
	Name       string `json:"name"`
	UID        string `json:"uid"`
	VendorName string `json:"vendor_name"`
}

type Remediation struct {
	Desc       string   `json:"desc,omitempty"`
	References []string `json:"references,omitempty"`
}

type OCSFResource struct {
	CloudPartition string         `json:"cloud_partition,omitempty"`
	Data           map[string]any `json:"data,omitempty"`
	Name           string         `json:"name,omitempty"`
	Owner          *ResourceOwner `json:"owner,omitempty"`
	Region         string         `json:"region"`
	Tags           []ResourceTag  `json:"tags,omitempty"`
	Type           string         `json:"type"`
	UID            string         `json:"uid"`
}

type ResourceOwner struct {
	Account struct {
		Type   string `json:"type,omitempty"`
		TypeID int    `json:"type_id,omitempty"`
		UID    string `json:"uid"`
	} `json:"account,omitempty"`
}

type ResourceTag struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

func (shf *SecurityHubV2Finding) SlackMessage(consoleURL, accessPortalURL, accessRoleName, shRegion string) (slack.MsgOption, slack.MsgOption) {
	var blocks []slack.Block

	severityEmoji := shf.GetSeverityEmoji()
	headerText := fmt.Sprintf("%s %s", severityEmoji, shf.FindingInfo.Title)
	header := slack.NewHeaderBlock(slack.NewTextBlockObject("plain_text", headerText, false, false))
	blocks = append(blocks, header)

	descriptionSection := slack.NewSectionBlock(
		slack.NewTextBlockObject("mrkdwn", shf.FindingInfo.Desc, false, false),
		nil, nil,
	)
	blocks = append(blocks, descriptionSection)

	var detailFields []*slack.TextBlockObject
	detailFields = append(detailFields, slack.NewTextBlockObject("mrkdwn", fmt.Sprintf("*Severity*\n%s", shf.Severity), false, false))
	detailFields = append(detailFields, slack.NewTextBlockObject("mrkdwn", fmt.Sprintf("*Source*\n%s", shf.Metadata.Product.Name), false, false))

	findingCategory := shf.GetFindingCategory()
	detailFields = append(detailFields, slack.NewTextBlockObject("mrkdwn", fmt.Sprintf("*Category*\n%s", findingCategory), false, false))

	detailFields = append(detailFields, slack.NewTextBlockObject("mrkdwn", fmt.Sprintf("*Account*\n%s", shf.Cloud.Account.UID), false, false))

	details := slack.NewSectionBlock(nil, detailFields, nil)
	blocks = append(blocks, details)

	findingIDSection := slack.NewSectionBlock(
		slack.NewTextBlockObject("mrkdwn", fmt.Sprintf("*Finding ID*\n`%s`", shf.Metadata.UID), false, false),
		nil, nil,
	)
	blocks = append(blocks, findingIDSection)

	if len(shf.Resources) > 0 {
		resource := shf.Resources[0]
		var resourceFields []*slack.TextBlockObject
		resourceFields = append(resourceFields, slack.NewTextBlockObject("mrkdwn", fmt.Sprintf("*Resource Type*\n`%s`", resource.Type), false, false))
		resourceFields = append(resourceFields, slack.NewTextBlockObject("mrkdwn", fmt.Sprintf("*Region*\n`%s`", resource.Region), false, false))

		resourceName := resource.UID
		if resource.Name != "" {
			resourceName = resource.Name
		}
		if len(resourceName) > 60 {
			parts := strings.Split(resourceName, "/")
			resourceName = parts[len(parts)-1]
		}
		resourceFields = append(resourceFields, slack.NewTextBlockObject("mrkdwn", fmt.Sprintf("*Resource ID*\n`%s`", resourceName), false, false))

		resourceSection := slack.NewSectionBlock(nil, resourceFields, nil)
		blocks = append(blocks, resourceSection)
	}

	if shf.Remediation != nil && len(shf.Remediation.References) > 0 {
		remediationText := fmt.Sprintf("*Remediation*\n%s\n<%s>",
			shf.Remediation.Desc,
			shf.Remediation.References[0])
		remediationSection := slack.NewSectionBlock(
			slack.NewTextBlockObject("mrkdwn", remediationText, false, false),
			nil, nil,
		)
		blocks = append(blocks, remediationSection)
	}

	consoleUrl := shf.BuildConsoleUrl(consoleURL, accessPortalURL, accessRoleName, shRegion)
	buttonSection := slack.NewActionBlock(
		"actions",
		slack.NewButtonBlockElement(
			"view_finding",
			"view",
			slack.NewTextBlockObject("plain_text", "View in Security Hub", false, false),
		).WithStyle(slack.StylePrimary).WithURL(consoleUrl),
	)
	blocks = append(blocks, buttonSection)

	return slack.MsgOptionText(shf.FindingInfo.Title, false), slack.MsgOptionBlocks(blocks...)
}

func (shf *SecurityHubV2Finding) IsAlertable() bool {
	if shf.Status != "New" {
		return false
	}

	if shf.Compliance != nil && shf.Compliance.Status == "Fail" {
		return true
	}

	alertSeverities := []string{"Critical", "High", "Medium"}
	return slices.Contains(alertSeverities, shf.Severity)
}

func NewSecurityHubFinding(raw json.RawMessage) (*SecurityHubV2Finding, error) {
	var shf SecurityHubV2Finding
	if err := json.Unmarshal(raw, &shf); err != nil {
		return &SecurityHubV2Finding{}, err
	}
	return &shf, nil
}

func (shf *SecurityHubV2Finding) GetFindingCategory() string {
	if len(shf.FindingInfo.Types) == 0 {
		return shf.CategoryName
	}

	for _, findingType := range shf.FindingInfo.Types {
		if strings.Contains(findingType, "Threats") {
			return "Threats"
		}
		if strings.Contains(findingType, "Posture Management") {
			return "Posture Management"
		}
		if strings.Contains(findingType, "Exposure") {
			return "Exposure"
		}
		if strings.Contains(findingType, "Vulnerabilities") {
			return "Vulnerabilities"
		}
		if strings.Contains(findingType, "Sensitive data") {
			return "Sensitive Data"
		}
	}

	return shf.CategoryName
}

func (shf *SecurityHubV2Finding) GetSeverityEmoji() string {
	switch shf.Severity {
	case "Critical":
		return "🔴"
	case "High":
		return "🟠"
	case "Medium":
		return "🟡"
	case "Low":
		return "🔵"
	case "Informational":
		return "⚪"
	default:
		return "⚫"
	}
}

func (shf *SecurityHubV2Finding) BuildConsoleUrl(consoleURL, accessPortalURL, accessRoleName, shRegion string) string {
	region := shRegion
	if region == "" {
		region = shf.Cloud.Region
	}

	var view string
	findingType := shf.GetFindingCategory()

	switch findingType {
	case "Exposure":
		view = "exposure"
	case "Posture Management":
		view = "postureManagement"
	case "Threats":
		view = "threats"
	case "Vulnerabilities":
		view = "vulnerabilities"
	}

	// example: https://console.aws.amazon.com/securityhub/v2/home?region=us-east-1#/postureManagement?findingDetailId=abc123...
	dst := fmt.Sprintf(
		"%s/securityhub/v2/home?region=%s#/%s?findingDetailId=%s",
		consoleURL, region, view, shf.Metadata.UID,
	)

	if accessPortalURL != "" && accessRoleName != "" {
		dstEncoded := url.QueryEscape(dst)
		return fmt.Sprintf(
			"%s/#/console?account_id=%s&role_name=%s&destination=%s",
			accessPortalURL, shf.Cloud.Account.UID, accessRoleName, dstEncoded,
		)
	}

	return dst
}
