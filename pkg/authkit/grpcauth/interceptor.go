// Package grpcauth adapts authkit verification to gRPC. It lives in its own
// package so HTTP-only consumers never link the grpc dependency.
package grpcauth

import (
	"context"
	"strings"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/sriganeshlokesh/keysmith/pkg/authkit"
)

// UnaryInterceptor rejects calls without a valid keysmith access token in the
// `authorization` metadata ("Bearer <token>") and injects the caller identity
// into the handler context (authkit.UserID / authkit.Email).
func UnaryInterceptor(v *authkit.Verifier) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, _ *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		md, ok := metadata.FromIncomingContext(ctx)
		if !ok {
			return nil, status.Error(codes.Unauthenticated, "missing metadata")
		}
		values := md.Get("authorization")
		if len(values) == 0 {
			return nil, status.Error(codes.Unauthenticated, "missing authorization")
		}
		raw, ok := strings.CutPrefix(values[0], "Bearer ")
		if !ok || raw == "" {
			return nil, status.Error(codes.Unauthenticated, "malformed authorization")
		}
		id, err := v.Verify(ctx, raw)
		if err != nil {
			return nil, status.Error(codes.Unauthenticated, "invalid token")
		}
		return handler(authkit.WithIdentity(ctx, id), req)
	}
}
