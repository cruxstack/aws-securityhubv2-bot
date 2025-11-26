package events

import "encoding/json"

// SecurityHubEventInput is a runtime-agnostic representation of a Security Hub event
type SecurityHubEventInput struct {
	EventID    string
	DetailType string
	Detail     json.RawMessage
}

type SecurityHubEvent interface {
	GetEventID() string
	GetDetailType() string
}
