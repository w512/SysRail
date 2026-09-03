package core

import "context"

// Caller identifies the authenticated agent behind a request.
type Caller struct {
	Agent   string
	Session string
}

type callerKey struct{}

// WithCaller attaches the caller identity to ctx.
func WithCaller(ctx context.Context, c Caller) context.Context {
	return context.WithValue(ctx, callerKey{}, c)
}

// CallerFrom returns the caller identity stored in ctx, if any.
func CallerFrom(ctx context.Context) (Caller, bool) {
	c, ok := ctx.Value(callerKey{}).(Caller)
	return c, ok
}
