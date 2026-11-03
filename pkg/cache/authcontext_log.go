package cache

import (
	"maps"
	"slices"
)

// Secret-bearing types implement logr.Marshaler, so every call site that
// logs them gets the redacted form: zapr calls MarshalLog before it
// reflects over a value.

// MarshalLog returns the non-secret fields of an AuthorizationContext for
// logging: session, status, scopes, client, expiry, whether each token and
// the code are set, and the names of the verified claims.
//
// A VALUE receiver, so the redaction applies to an AuthorizationContext
// logged either way round. A pointer receiver covers only the pointer:
// a call site logging *authCtx - a dereference is easy to write and
// impossible to spot in review - would then reflect over the struct and
// print every field. With a value receiver the pointer is covered too,
// because a pointer's method set contains its value methods.
//
// The cost is a nil *AuthorizationContext, whose MarshalLog dereferences
// nil. zapr recovers that and records the panic in place of the field, so
// the failure mode is a useless log entry rather than a leaked one - and
// a nil context has no secret to leak in the first place. That trade is
// the right way round: the dangerous case is the populated struct.
func (a AuthorizationContext) MarshalLog() any {
	return map[string]any{
		"session_id":          a.SessionID,
		"status":              a.Status,
		"scopes":              a.Scopes,
		"client_id":           a.ClientID,
		"expires_at":          a.ExpiresAt,
		"has_access_token":    a.AccessToken != "" || (a.Token != nil && a.Token.AccessToken != ""),
		"has_refresh_token":   a.RefreshToken != "",
		"has_id_token":        a.IDToken != "",
		"has_code":            a.Code != "",
		"has_tx_code":         a.TXCode != "",
		"has_vp_token":        a.VPToken != "",
		"verified_claim_keys": claimKeys(a.VerifiedClaims),
	}
}

// claimKeys returns the names of the verified claims, sorted.
//
// Sorted because map order is random per iteration, so the same context
// logged twice produced two different lines - which makes a diff between
// two log entries meaningless and hides a real change in the claim set
// among the churn.
func claimKeys(claims map[string]any) []string {
	if len(claims) == 0 {
		return nil
	}
	return slices.Sorted(maps.Keys(claims))
}
