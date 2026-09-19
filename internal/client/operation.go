package client

import "github.com/stackedapp/stacked/agent/internal/opschema"

// ValidatePayload decodes this operation's payload into a typed schema.
// The executor calls this before reporting running or performing side effects.
func (op Operation) ValidatePayload() (opschema.Payload, error) {
	return opschema.Decode(op.Type, op.Payload)
}
