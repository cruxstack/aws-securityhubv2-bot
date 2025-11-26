package filters

import (
	"github.com/cruxstack/aws-securityhubv2-bot/internal/events"
)

func matchesFindingTypes(finding *events.SecurityHubV2Finding, types []string) bool {
	for _, filterType := range types {
		for _, findingType := range finding.FindingInfo.Types {
			if findingType == filterType {
				return true
			}
		}
	}
	return false
}

func matchesResourceTypes(finding *events.SecurityHubV2Finding, types []string) bool {
	for _, resource := range finding.Resources {
		for _, filterType := range types {
			if resource.Type == filterType {
				return true
			}
		}
	}
	return false
}

func matchesResourceTags(finding *events.SecurityHubV2Finding, tagFilters []ResourceTagFilter) bool {
	if len(finding.Resources) == 0 {
		return false
	}

	for _, resource := range finding.Resources {
		if resourceHasAllTags(resource.Tags, tagFilters) {
			return true
		}
	}
	return false
}

func resourceHasAllTags(resourceTags []events.ResourceTag, tagFilters []ResourceTagFilter) bool {
	for _, filterTag := range tagFilters {
		found := false
		for _, tag := range resourceTags {
			if tag.Name == filterTag.Name && tag.Value == filterTag.Value {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}
