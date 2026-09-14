package requestid

import "context"

type contextKey struct{}

func With(ctx context.Context, value string) context.Context {
	return context.WithValue(ctx, contextKey{}, value)
}

func FromContext(ctx context.Context) string {
	value, _ := ctx.Value(contextKey{}).(string)
	return value
}
