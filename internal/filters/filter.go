package filters

import (
	"github.com/cruxstack/aws-securityhubv2-bot/internal/events"
)

type FilterEngine struct {
	Rules []AutoCloseRule
}

func NewFilterEngine(rules []AutoCloseRule) *FilterEngine {
	return &FilterEngine{Rules: rules}
}

func (e *FilterEngine) FindMatchingRule(finding *events.SecurityHubV2Finding) (*AutoCloseRule, bool) {
	for i := range e.Rules {
		rule := &e.Rules[i]
		if !rule.Enabled {
			continue
		}
		if e.matchesFilters(finding, rule.Filters) {
			return rule, true
		}
	}
	return nil, false
}

func (e *FilterEngine) matchesFilters(finding *events.SecurityHubV2Finding, filters RuleFilters) bool {
	if len(filters.FindingTypes) > 0 && !matchesFindingTypes(finding, filters.FindingTypes) {
		return false
	}

	if len(filters.Severity) > 0 && !contains(filters.Severity, finding.Severity) {
		return false
	}

	if len(filters.ProductName) > 0 && !contains(filters.ProductName, finding.Metadata.Product.Name) {
		return false
	}

	if len(filters.ResourceTypes) > 0 && !matchesResourceTypes(finding, filters.ResourceTypes) {
		return false
	}

	if len(filters.ResourceTags) > 0 && !matchesResourceTags(finding, filters.ResourceTags) {
		return false
	}

	if len(filters.Accounts) > 0 && !contains(filters.Accounts, finding.Cloud.Account.UID) {
		return false
	}

	if len(filters.Regions) > 0 && !contains(filters.Regions, finding.Cloud.Region) {
		return false
	}

	return true
}
