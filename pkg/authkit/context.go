package authkit

import "context"

type identityCtxKey struct{}

// WithIdentity returns a context carrying the identity; used by Middleware
// and grpcauth.UnaryInterceptor.
func WithIdentity(ctx context.Context, id *Identity) context.Context {
	return context.WithValue(ctx, identityCtxKey{}, id)
}

// IdentityFrom returns the authenticated identity, or nil when the request
// did not pass through authkit.
func IdentityFrom(ctx context.Context) *Identity {
	id, _ := ctx.Value(identityCtxKey{}).(*Identity)
	return id
}

// UserID returns the authenticated user's id (the JWT `sub`), or "" when
// unauthenticated.
func UserID(ctx context.Context) string {
	if id := IdentityFrom(ctx); id != nil {
		return id.UserID
	}
	return ""
}

// Email returns the authenticated user's email, or "" when unauthenticated.
func Email(ctx context.Context) string {
	if id := IdentityFrom(ctx); id != nil {
		return id.Email
	}
	return ""
}
