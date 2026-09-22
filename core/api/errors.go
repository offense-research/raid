// API error model (spec 10.6): safe, structured errors. Raw CEL errors,
// Jev bodies, authorization headers, and policy internals are never
// returned to callers.
package api

import (
	"strings"

	"offense.dev/raid/core/canonical"
)

// Error codes exposed on the wire.
const (
	CodeInputInvalid         = "REQUEST_INVALID"
	CodePolicyEvaluation     = "POLICY_EVALUATION_FAILED"
	CodePolicyDenied         = "POLICY_DENIED"
	CodeApprovalRequired     = "APPROVAL_REQUIRED"
	CodeApprovalConflict     = "APPROVAL_CONFLICT"
	CodeApprovalExpired      = "APPROVAL_EXPIRED"
	CodeApprovalNotFound     = "APPROVAL_NOT_FOUND"
	CodeUnauthorized         = "UNAUTHORIZED"
	CodeUnavailable          = "UNAVAILABLE"
	CodeInternal             = "INTERNAL_ERROR"
)

// Error is the wire error body.
type Error struct {
	Code      string
	Message   string
	Retryable bool
	RequestID string
}

// writeJSON appends the error document.
func (e *Error) writeJSON(sb *strings.Builder) () {
	sb.WriteString(`{"error":{"code":`)
	canonical.WriteEscaped(sb, e.Code)
	sb.WriteString(`,"message":`)
	canonical.WriteEscaped(sb, e.Message)
	sb.WriteString(`,"retryable":`)
	if e.Retryable {
		sb.WriteString("true")
	} else {
		sb.WriteString("false")
	}
	sb.WriteString(`,"request_id":`)
	canonical.WriteEscaped(sb, e.RequestID)
	sb.WriteString(`}}`)
}

func errDoc(code, msg string, retryable bool, reqID string) string {
	e := &Error{Code: code, Message: msg, Retryable: retryable, RequestID: reqID}
	var sb strings.Builder
	e.writeJSON(&sb)
	return sb.String()
}