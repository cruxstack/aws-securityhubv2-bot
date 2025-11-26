package filters

type AutoCloseRule struct {
	Name             string      `json:"name"`
	Enabled          bool        `json:"enabled"`
	Filters          RuleFilters `json:"filters"`
	Action           RuleAction  `json:"action"`
	SkipNotification bool        `json:"skip_notification"`
}

type RuleFilters struct {
	FindingTypes  []string            `json:"finding_types,omitempty"`
	Severity      []string            `json:"severity,omitempty"`
	ProductName   []string            `json:"product_name,omitempty"`
	ResourceTypes []string            `json:"resource_types,omitempty"`
	ResourceTags  []ResourceTagFilter `json:"resource_tags,omitempty"`
	Accounts      []string            `json:"accounts,omitempty"`
	Regions       []string            `json:"regions,omitempty"`
}

type ResourceTagFilter struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type RuleAction struct {
	StatusID int32  `json:"status_id"`
	Comment  string `json:"comment"`
}
