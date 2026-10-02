package core

import (
	"context"
	"errors"
	"fmt"
	"net/http"
)

// Code is a machine-readable error class (spec §26).
type Code string

const (
	CodeAuthenticationFailed Code = "AUTHENTICATION_FAILED"
	CodePermissionDenied     Code = "PERMISSION_DENIED"
	CodeApprovalRequired     Code = "APPROVAL_REQUIRED"
	CodeResourceNotFound     Code = "RESOURCE_NOT_FOUND"
	CodeProviderUnavailable  Code = "PROVIDER_UNAVAILABLE"
	CodeInvalidArgument      Code = "INVALID_ARGUMENT"
	CodeExecutionFailed      Code = "EXECUTION_FAILED"
	CodeTimeout              Code = "TIMEOUT"
	CodeConflict             Code = "CONFLICT"
	// CodeRateLimited means the agent exceeded a rate or pending-request
	// limit. Details may carry retry_after_seconds.
	CodeRateLimited Code = "RATE_LIMITED"
)

// HTTPStatus maps an error code to the HTTP status used by the API.
func (c Code) HTTPStatus() int {
	switch c {
	case CodeAuthenticationFailed:
		return http.StatusUnauthorized
	case CodePermissionDenied:
		return http.StatusForbidden
	case CodeApprovalRequired:
		return http.StatusAccepted
	case CodeResourceNotFound:
		return http.StatusNotFound
	case CodeProviderUnavailable:
		return http.StatusServiceUnavailable
	case CodeInvalidArgument:
		return http.StatusBadRequest
	case CodeTimeout:
		return http.StatusGatewayTimeout
	case CodeConflict:
		return http.StatusConflict
	case CodeRateLimited:
		return http.StatusTooManyRequests
	}
	return http.StatusInternalServerError
}

func (c Code) retryable() bool {
	return c == CodeProviderUnavailable || c == CodeTimeout || c == CodeRateLimited
}

// Error is the structured error returned to agents and API clients.
type Error struct {
	Code      Code           `json:"code"`
	Message   string         `json:"message"`
	Retryable bool           `json:"retryable"`
	Details   map[string]any `json:"details,omitempty"`
}

func (e *Error) Error() string { return string(e.Code) + ": " + e.Message }

// Errorf builds an Error with the default retryability for code.
func Errorf(code Code, format string, args ...any) *Error {
	return &Error{Code: code, Message: fmt.Sprintf(format, args...), Retryable: code.retryable()}
}

// WithDetail returns e with an additional detail entry.
func (e *Error) WithDetail(key string, value any) *Error {
	if e.Details == nil {
		e.Details = map[string]any{}
	}
	e.Details[key] = value
	return e
}

// AsError converts any error into a structured Error. Context deadlines become
// TIMEOUT; anything unrecognized becomes EXECUTION_FAILED.
func AsError(err error) *Error {
	if err == nil {
		return nil
	}
	var e *Error
	if errors.As(err, &e) {
		return e
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return Errorf(CodeTimeout, "operation timed out")
	}
	if errors.Is(err, context.Canceled) {
		return Errorf(CodeExecutionFailed, "operation was canceled")
	}
	return Errorf(CodeExecutionFailed, "%s", err.Error())
}
